//! Sans-I/O scheduler for pushing stamped chunks through several relay
//! lanes (`docs/pusher-design.md` §7).
//!
//! This module contains **no I/O, no clock and no environment reads**: the
//! driver supplies `now_ms`, performs the HTTP, and feeds results back. That
//! is what lets the native CLI (reqwest + tokio) and the browser dApp (wasm →
//! `fetch`) run the *same* scheduler instead of the two divergent ones they
//! had before — and what makes lane behaviour testable without a network
//! (see the simulation harness in `#[cfg(test)]` below).
//!
//! # Why the previous scheme had to go
//!
//! Stage C's first cut routed a chunk to `argmax po(chunk_addr, lane_overlay)`.
//! Measured against the four production relays that partitions the keyspace
//! ~49 / 50 / 0.8 / 0.2 %:
//!
//! - Proximity-argmax is not a load balancer. Its cells are Voronoi regions
//!   in Kademlia space, so their sizes depend entirely on how the overlays
//!   happen to cluster — and three of the four relays share a 6-bit prefix.
//! - Proximity ties (extremely common: two lanes agree at PO 1 half the time)
//!   were broken by `Iterator::max_by_key`, which returns the *last* maximum,
//!   so every tie went to the highest-numbered lane.
//!
//! Load only balanced because a separate work-stealing layer drained the
//! backed-up lanes — which discarded the routing decision anyway. So the
//! proximity machinery cost balance and bought nothing.
//!
//! # What replaces it
//!
//! **Weighted rendezvous hashing (HRW).** Score every eligible lane with
//! `w_l / -ln(u(addr, lane))` and take the max; `u` is a uniform derived from
//! a hash of `addr ‖ lane_id`. This gives, by construction:
//!
//! - load in exact proportion to `w_l`, because chunk addresses are uniform;
//! - stickiness per address, so a retry can't double-spend quota;
//! - minimal reshuffling when one lane's weight changes (only that lane's
//!   share moves, everyone else's assignment is untouched);
//! - a deterministic **rank #2** — the designated failover/hedge target.
//!
//! Weights come from observed throughput (EWMA), advertised egress budget and
//! pool occupancy — the things that actually differ between a dedicated-IP VPS
//! relay and a shared-IP free tier (≈0.42 vs ≈0.05 MiB/s measured).
//!
//! Proximity survives only as a *bounded multiplier* on the weight, disabled
//! by default ([`Config::proximity_alpha`] = 0). Turning it on is a decision
//! for the receipt data now carried in `/v1/push` acks (`po`), not for taste:
//! a relay pushes to the closest peer in its own 3.5k-entry peerstore, so its
//! own overlay is at best a weak proxy for how deep a chunk lands.

use std::collections::HashMap;

/// Maximum proximity order the weight bonus saturates at. Beyond ~8 bits of
/// shared prefix the difference stops meaning anything for lane choice.
const PROX_CAP: f64 = 8.0;

/// Consecutive fully-failed batches before a lane is put into backoff.
const FAIL_STREAK: u32 = 3;

/// Backoff schedule for an unhealthy lane: `base << exp`, capped.
const BACKOFF_BASE_MS: u64 = 2_000;
const BACKOFF_MAX_MS: u64 = 120_000;
/// Backoff doublings before a lane is considered gone for this run.
const MAX_BACKOFF_EXP: u32 = 5;

/// Floor for a lane weight, so an eligible-but-slow lane still attracts some
/// traffic instead of starving permanently (its EWMA could never recover if
/// it were never dispatched to again).
const MIN_WEIGHT: f64 = 0.02;

/// Minimum acked chunks for a batch to inform the throughput EWMA.
///
/// Rate is `acked / elapsed`, which is meaningless for a handful of chunks: a
/// 4-chunk batch answered in 10 ms reads as 400 chunks/s. Measured on a
/// two-lane VPS run, an under-fed lane reported 355–516/s against a real
/// sustained rate an order of magnitude lower, purely from small batches.
const RATE_MIN_SAMPLE: usize = 16;

/// Health of a single lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneHealth {
    /// No successful batch observed yet. Eligible, but dispatched a probe
    /// batch rather than a full one — free-tier relays cold-start (measured:
    /// 35 s to first byte on a sleeping instance), and a cold lane must not
    /// be able to swallow a full-size batch before proving it is awake.
    Warming,
    /// Over its credit line, or the client has no way to pay it. Ineligible
    /// but **not terminal** — unlike `Retired`, which is permanent for the
    /// run. Cleared by [`Scheduler::fund_lane`] once a cheque is accepted.
    Unfunded,
    /// Serving normally.
    Live,
    /// Failing; not eligible until `until_ms`.
    Backoff { until_ms: u64 },
    /// Repeatedly failed; excluded for the rest of the run.
    Retired,
}

/// A lane's self-advertisement, from `GET /v1/status`.
///
/// Every field is optional at the type level because a lane can be asleep
/// when we ask. A missing advertisement must never sink the whole run — the
/// previous implementation collected overlays all-or-nothing, so one cold
/// relay silently downgraded routing for *every* lane.
#[derive(Debug, Clone, Default)]
pub struct LaneInfo {
    /// Kademlia overlay, when advertised.
    pub overlay: Option<[u8; 32]>,
    /// Max frames the lane accepts per POST.
    pub batch_max: Option<usize>,
    /// Concurrent POSTs the lane suggests.
    pub inflight_max: Option<usize>,
    /// Remaining metered egress. `None` = unmetered, *not* "exhausted".
    pub budget_remaining_gb: Option<f64>,
    /// Live warm sessions; the strongest available prior on throughput.
    pub pool_live: Option<usize>,
    /// Price in PLUR per KiB of body, from a *verified* signed quote
    /// (`docs/pusher-incentives.md` §7.3). `None` on an `open` lane, and
    /// also `None` when the quote failed verification — an unverifiable
    /// quote is treated as "not metered" rather than "free", so the lane is
    /// simply not paid and not scheduled for payment.
    pub price_plur_per_kib: Option<u128>,
    /// True when the lane enforces 402 rather than metering softly.
    ///
    /// Deliberately *not* behind the `pusher` feature: a client that cannot
    /// pay still has to recognise a lane that will refuse it, and the
    /// browser build compiles without the payment stack entirely.
    pub hard_enforcement: bool,
    /// The whole verified quote, when this lane advertised one. Carried so
    /// the payment loop has the beneficiary and parameters without
    /// re-fetching and re-verifying `/v1/status`.
    #[cfg(not(target_arch = "wasm32"))]
    pub quote: Option<crate::payer::PaymentQuote>,
}

/// Tunables. Defaults are the shipping configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Frames per POST, further clamped by each lane's advertised `batch_max`.
    pub batch: usize,
    /// Frames in a `Warming` lane's probe batch.
    pub probe_batch: usize,
    /// Concurrent POSTs per lane when the lane doesn't advertise its own.
    pub inflight_per_lane: usize,
    /// Lane attempts per chunk before it is given up on.
    pub max_attempts: u16,
    /// Weight multiplier for proximity: `w *= 1 + alpha * min(po, 8)/8`.
    /// `0.0` disables proximity routing entirely (the default — see the
    /// module docs).
    pub proximity_alpha: f64,
    /// Fraction of chunks allowed to be hedged onto a second lane. Keeps
    /// cross-lane egress at ≈1.0–1.2× payload instead of the k× that blanket
    /// racing would cost.
    pub hedge_fraction: f64,
    /// Multiplier on a lane's observed batch latency before a chunk in
    /// flight on it is considered a straggler.
    pub hedge_latency_mult: f64,
    /// Hedges never fire before this, regardless of measured latency.
    pub hedge_min_ms: u64,
    /// ...nor after it.
    pub hedge_max_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            batch: 256,
            probe_batch: 16,
            inflight_per_lane: 4,
            max_attempts: 6,
            proximity_alpha: 0.0,
            hedge_fraction: 0.10,
            hedge_latency_mult: 1.5,
            hedge_min_ms: 3_000,
            hedge_max_ms: 60_000,
        }
    }
}

/// Terminal state of one chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkPhase {
    Pending,
    InFlight,
    Done,
    /// Attempts exhausted, or every lane died.
    Failed,
    /// Not needed any more: its group already reached the acks it required.
    /// Only reachable under [`CompletionPolicy::Group`].
    Skipped,
}

#[derive(Debug, Clone)]
struct ChunkState {
    addr: [u8; 32],
    size: u32,
    phase: ChunkPhase,
    attempts: u16,
    /// Lanes currently carrying this chunk (1 normally, 2 while hedged).
    on: Vec<usize>,
    /// Dispatch time of the first still-outstanding copy.
    since_ms: u64,
    hedged: bool,
    group: Option<u32>,
}

/// How a set of chunks is considered complete.
///
/// [`CompletionPolicy::Group`] is the seam for erasure-coded uploads: a
/// Reed–Solomon codeword of `shards + parities` chunks is retrievable once
/// any `shards` of them land, exactly as `erasure::joiner` stops fetching a
/// node's children at `present >= shard_cnt`. Under that policy the tail of
/// an upload stops being blocking — the stragglers are repaired by parity at
/// download time rather than scheduled around. The encoder that produces such
/// groups is a separate piece of work; the scheduler is ready for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompletionPolicy {
    /// Every chunk must be acked.
    #[default]
    AllAcked,
    /// Each group completes at its own `need` count.
    Group,
}

#[derive(Debug, Clone)]
struct GroupState {
    need: u16,
    acked: u16,
}

#[derive(Debug, Clone)]
struct Lane {
    id: usize,
    info: LaneInfo,
    health: LaneHealth,
    fail_streak: u32,
    backoff_exp: u32,
    /// POSTs currently outstanding.
    inflight: usize,
    /// EWMA of observed acked-chunks per second.
    rate: f64,
    /// EWMA of batch wall time, for the hedge deadline.
    batch_ms: f64,
    acked_total: u64,
    failed_total: u64,
    bytes_total: u64,
}

impl Lane {
    fn eligible(&self, now_ms: u64) -> bool {
        match self.health {
            LaneHealth::Live | LaneHealth::Warming => true,
            LaneHealth::Backoff { until_ms } => now_ms >= until_ms,
            // Ineligible until paid, but recoverable within this run.
            LaneHealth::Unfunded => false,
            LaneHealth::Retired => false,
        }
    }

    fn capacity(&self, cfg: &Config) -> usize {
        let want = self.info.inflight_max.unwrap_or(cfg.inflight_per_lane);
        // A lane that hasn't proved itself gets exactly one probe in flight.
        if matches!(self.health, LaneHealth::Warming) {
            1
        } else {
            want.max(1)
        }
    }

    fn batch_size(&self, cfg: &Config) -> usize {
        let lane_max = self.info.batch_max.unwrap_or(cfg.batch);
        if matches!(self.health, LaneHealth::Warming) {
            cfg.probe_batch.min(lane_max)
        } else {
            cfg.batch.min(lane_max)
        }
    }

    /// Scheduling weight. Never zero for an eligible lane: a lane that is
    /// never dispatched to can never revise its own EWMA upward.
    fn weight(&self, cfg: &Config) -> f64 {
        // Prior before any measurement: pool occupancy is the best signal we
        // have, and it is exactly what differs between a shared-IP free tier
        // (pool starves at ~10-35) and a dedicated IP (128+).
        let rate = if self.rate == 0.0 {
            (self.info.pool_live.unwrap_or(16) as f64 / 8.0).max(0.5)
        } else {
            self.rate
        };
        let budget = match self.info.budget_remaining_gb {
            // Shed load as a metered lane approaches its cap rather than
            // waiting for it to start returning errors.
            Some(gb) => (gb / 1.0).clamp(0.05, 1.0),
            None => 1.0,
        };
        // `rate` is per-batch capability; sustained throughput also scales
        // with how many batches the lane will run at once. Two lanes that
        // answer a batch equally fast are not equal if one accepts 8
        // concurrent POSTs and the other 1.
        let concurrency = self.capacity(cfg) as f64;
        (rate * budget * concurrency).max(MIN_WEIGHT)
    }

    /// How long a chunk may sit on this lane before it is hedged.
    fn hedge_deadline_ms(&self, cfg: &Config) -> u64 {
        let base = if self.batch_ms > 0.0 {
            self.batch_ms * cfg.hedge_latency_mult
        } else {
            cfg.hedge_min_ms as f64
        };
        (base as u64).clamp(cfg.hedge_min_ms, cfg.hedge_max_ms)
    }
}

/// One POST's worth of work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    /// Identifies this dispatch for [`Scheduler::on_batch_result`].
    pub batch: u64,
    pub lane: usize,
    /// Indices into the admitted chunk list, in the caller's own order.
    pub chunks: Vec<usize>,
    /// True when this is a duplicate of work already in flight elsewhere.
    pub hedge: bool,
}

/// Outcome of a POST at the HTTP level (independent of per-chunk acks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchOutcome {
    /// The lane answered and streamed acks (successful or not).
    Answered,
    /// Transport error, non-2xx, or an unparseable body.
    Failed(String),
    /// `402 Payment Required` — the account is over its credit line on this
    /// lane (`docs/pusher-incentives.md` §12).
    ///
    /// **Not a failure.** Mapping it to `Failed` would charge lane health
    /// for a *routine settlement*: five of them retire a perfectly healthy
    /// lane mid-upload, which is the opposite of what should happen when a
    /// relay says "pay me". The lane is paused until a cheque clears and its
    /// streak is left untouched.
    PaymentRequired,
}

/// Why a run couldn't finish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StallReason {
    /// Every lane is retired or backed off past its budget.
    AllLanesDown,
    /// Chunks exhausted their per-chunk attempt budget.
    ChunksExhausted,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct LaneStats {
    pub acked: u64,
    pub failed: u64,
    pub bytes: u64,
    pub rate: f64,
    pub health: Option<LaneHealthKind>,
}

/// [`LaneHealth`] without the payload, for reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneHealthKind {
    Warming,
    Live,
    Backoff,
    Unfunded,
    Retired,
}

/// The scheduler.
///
/// Lifecycle: [`admit`](Self::admit) chunks (repeatedly, for a streaming
/// upload), pump [`next`](Self::next) for work, feed
/// [`on_ack`](Self::on_ack) and [`on_batch_result`](Self::on_batch_result)
/// back, stop when [`done`](Self::done).
pub struct Scheduler {
    cfg: Config,
    policy: CompletionPolicy,
    lanes: Vec<Lane>,
    chunks: Vec<ChunkState>,
    groups: Vec<GroupState>,
    /// Chunks awaiting dispatch, in admission order.
    pending: Vec<usize>,
    /// Address → chunk index, so a lane's ack can be matched without the
    /// caller having to track which batch it came from.
    index: HashMap<[u8; 32], usize>,
    next_batch_id: u64,
    /// Outstanding dispatches: batch id → (lane, chunk indices).
    outstanding: HashMap<u64, (usize, Vec<usize>)>,
    hedges_used: usize,
    acked: usize,
    failed: usize,
    skipped: usize,
}

impl Scheduler {
    pub fn new(lanes: Vec<LaneInfo>, cfg: Config) -> Self {
        Self::with_policy(lanes, cfg, CompletionPolicy::AllAcked)
    }

    pub fn with_policy(lanes: Vec<LaneInfo>, cfg: Config, policy: CompletionPolicy) -> Self {
        let lanes = lanes
            .into_iter()
            .enumerate()
            .map(|(id, info)| Lane {
                id,
                info,
                health: LaneHealth::Warming,
                fail_streak: 0,
                backoff_exp: 0,
                inflight: 0,
                rate: 0.0,
                batch_ms: 0.0,
                acked_total: 0,
                failed_total: 0,
                bytes_total: 0,
            })
            .collect();
        Self {
            cfg,
            policy,
            lanes,
            chunks: Vec::new(),
            groups: Vec::new(),
            pending: Vec::new(),
            index: HashMap::new(),
            next_batch_id: 1,
            outstanding: HashMap::new(),
            hedges_used: 0,
            acked: 0,
            failed: 0,
            skipped: 0,
        }
    }

    pub fn lane_count(&self) -> usize {
        self.lanes.len()
    }

    /// Replace a lane's advertisement (e.g. after re-polling `/v1/status`).
    pub fn set_lane_info(&mut self, lane: usize, info: LaneInfo) {
        if let Some(l) = self.lanes.get_mut(lane) {
            l.info = info;
        }
    }

    /// Admit chunks for scheduling. Returns the index range assigned, which
    /// the caller uses to map indices back to its own frame payloads.
    ///
    /// Safe to call repeatedly while the run is in progress — that is how a
    /// windowed streaming upload feeds the scheduler without ever holding the
    /// whole file's frames in memory.
    pub fn admit<I: IntoIterator<Item = ([u8; 32], u32)>>(&mut self, chunks: I) -> (usize, usize) {
        let start = self.chunks.len();
        for (addr, size) in chunks {
            // A repeat address (manifest chunk shared between windows, or a
            // caller re-admitting) is not new work.
            if let Some(&existing) = self.index.get(&addr) {
                let _ = existing;
                continue;
            }
            let idx = self.chunks.len();
            self.chunks.push(ChunkState {
                addr,
                size,
                phase: ChunkPhase::Pending,
                attempts: 0,
                on: Vec::new(),
                since_ms: 0,
                hedged: false,
                group: None,
            });
            self.index.insert(addr, idx);
            self.pending.push(idx);
        }
        (start, self.chunks.len())
    }

    /// Admit a group of chunks that completes at `need` acks.
    ///
    /// Under [`CompletionPolicy::Group`] this is a Reed–Solomon codeword:
    /// `need` = data shards, the rest parity. Ignored (treated as
    /// [`Self::admit`]) under `AllAcked`.
    pub fn admit_group<I: IntoIterator<Item = ([u8; 32], u32)>>(
        &mut self,
        chunks: I,
        need: u16,
    ) -> (usize, usize) {
        let gid = self.groups.len() as u32;
        self.groups.push(GroupState { need, acked: 0 });
        let (start, end) = self.admit(chunks);
        for c in &mut self.chunks[start..end] {
            c.group = Some(gid);
        }
        (start, end)
    }

    pub fn chunk_addr(&self, idx: usize) -> [u8; 32] {
        self.chunks[idx].addr
    }

    /// Next POST to issue, or `None` when nothing can be dispatched right
    /// now (everything in flight, or every lane is backed off).
    pub fn next(&mut self, now_ms: u64) -> Option<Assignment> {
        self.expire_backoffs(now_ms);
        if let Some(a) = self.next_hedge(now_ms) {
            return Some(a);
        }
        if self.pending.is_empty() {
            return None;
        }

        // Lanes that could take work right now.
        let free: Vec<usize> = (0..self.lanes.len())
            .filter(|&l| {
                self.lanes[l].eligible(now_ms)
                    && self.lanes[l].inflight < self.lanes[l].capacity(&self.cfg)
            })
            .collect();
        if free.is_empty() {
            return None;
        }
        // Eligible lanes at all — the ranking universe. A chunk prefers its
        // top-ranked *eligible* lane; if that one is momentarily saturated
        // it waits rather than being handed to a lane that will just be slow.
        // But if none of the free lanes is anyone's first choice, we still
        // dispatch (work conservation beats purity when a lane is idle).
        let eligible: Vec<usize> = (0..self.lanes.len())
            .filter(|&l| self.lanes[l].eligible(now_ms))
            .collect();

        // Pick the free lane with the most first-choice work waiting; ties by
        // weight. Scanning per lane keeps assignment *lazy* — a chunk is only
        // bound to a lane at dispatch time, so a lane going bad mid-run
        // reroutes everything still pending, with no work-stealing layer.
        let mut best: Option<(usize, Vec<usize>)> = None;
        for &l in &free {
            let take = self.lanes[l].batch_size(&self.cfg);
            let mut picked = Vec::with_capacity(take);
            for &ci in &self.pending {
                if self.chunks[ci].phase != ChunkPhase::Pending {
                    continue;
                }
                if self.rank_lane(ci, &eligible) == Some(l) {
                    picked.push(ci);
                    if picked.len() == take {
                        break;
                    }
                }
            }
            if picked.is_empty() {
                continue;
            }
            let better = match &best {
                None => true,
                Some((bl, bp)) => {
                    (picked.len(), self.lanes[l].weight(&self.cfg))
                        > (bp.len(), self.lanes[*bl].weight(&self.cfg))
                }
            };
            if better {
                best = Some((l, picked));
            }
        }

        // Work conservation: an idle free lane and pending work that prefers
        // a busy lane. Give it the oldest pending chunks anyway.
        if best.is_none() {
            let l = *free
                .iter()
                .max_by(|&&a, &&b| {
                    self.lanes[a]
                        .weight(&self.cfg)
                        .partial_cmp(&self.lanes[b].weight(&self.cfg))
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .expect("free is non-empty");
            let take = self.lanes[l].batch_size(&self.cfg);
            let picked: Vec<usize> = self
                .pending
                .iter()
                .copied()
                .filter(|&ci| self.chunks[ci].phase == ChunkPhase::Pending)
                .take(take)
                .collect();
            if picked.is_empty() {
                return None;
            }
            best = Some((l, picked));
        }

        let (lane, picked) = best?;
        Some(self.dispatch(lane, picked, false, now_ms))
    }

    /// Re-dispatch a straggler to its rank-#2 lane.
    ///
    /// Mirrors `erasure::joiner::fetch_node_children`, which races every
    /// sibling and cancels the rest the moment enough have landed, instead of
    /// walking them one at a time and waiting out each timeout. Here the race
    /// is deliberately *late* and bounded — only chunks that have already blown
    /// their lane's own latency budget, and only up to `hedge_fraction` of the
    /// run — so aggregate egress stays near 1× payload.
    fn next_hedge(&mut self, now_ms: u64) -> Option<Assignment> {
        let budget = (self.chunks.len() as f64 * self.cfg.hedge_fraction).ceil() as usize;
        if self.hedges_used >= budget.max(8) {
            return None;
        }
        let eligible: Vec<usize> = (0..self.lanes.len())
            .filter(|&l| self.lanes[l].eligible(now_ms))
            .collect();
        if eligible.len() < 2 {
            return None;
        }

        let mut by_lane: HashMap<usize, Vec<usize>> = HashMap::new();
        for ci in 0..self.chunks.len() {
            let c = &self.chunks[ci];
            if c.phase != ChunkPhase::InFlight || c.hedged || c.on.is_empty() {
                continue;
            }
            let cur = c.on[0];
            if now_ms.saturating_sub(c.since_ms) < self.lanes[cur].hedge_deadline_ms(&self.cfg) {
                continue;
            }
            let Some(alt) = self.rank_nth(ci, &eligible, 1) else {
                continue;
            };
            if alt == cur || self.lanes[alt].inflight >= self.lanes[alt].capacity(&self.cfg) {
                continue;
            }
            by_lane.entry(alt).or_default().push(ci);
        }

        let (lane, mut picked) = by_lane.into_iter().max_by_key(|(_, v)| v.len())?;
        let cap = self.lanes[lane]
            .batch_size(&self.cfg)
            .min(budget.max(8).saturating_sub(self.hedges_used));
        picked.truncate(cap);
        if picked.is_empty() {
            return None;
        }
        self.hedges_used += picked.len();
        for &ci in &picked {
            self.chunks[ci].hedged = true;
        }
        Some(self.dispatch(lane, picked, true, now_ms))
    }

    fn dispatch(
        &mut self,
        lane: usize,
        picked: Vec<usize>,
        hedge: bool,
        now_ms: u64,
    ) -> Assignment {
        let batch = self.next_batch_id;
        self.next_batch_id += 1;
        for &ci in &picked {
            let c = &mut self.chunks[ci];
            if !hedge {
                c.phase = ChunkPhase::InFlight;
                c.since_ms = now_ms;
                c.attempts += 1;
            }
            c.on.push(lane);
        }
        if !hedge {
            // Phases were just flipped to InFlight, so a phase sweep is an
            // O(pending) prune instead of O(pending × batch) membership tests.
            let chunks = &self.chunks;
            self.pending
                .retain(|&ci| chunks[ci].phase == ChunkPhase::Pending);
        }
        self.lanes[lane].inflight += 1;
        self.outstanding.insert(batch, (lane, picked.clone()));
        Assignment {
            batch,
            lane,
            chunks: picked,
            hedge,
        }
    }

    /// Record one chunk-level ack from a lane.
    ///
    /// Idempotent by address: the losing copy of a hedged chunk arriving
    /// later is ignored, which is exactly what makes hedging safe.
    pub fn on_ack(&mut self, lane: usize, addr: &[u8; 32], ok: bool, now_ms: u64) {
        let Some(&ci) = self.index.get(addr) else {
            return;
        };
        let phase = self.chunks[ci].phase;
        if phase == ChunkPhase::Done || phase == ChunkPhase::Skipped {
            return;
        }
        if ok {
            self.chunks[ci].phase = ChunkPhase::Done;
            self.chunks[ci].on.clear();
            self.acked += 1;
            if let Some(l) = self.lanes.get_mut(lane) {
                l.acked_total += 1;
                l.bytes_total += u64::from(self.chunks[ci].size);
            }
            self.on_group_ack(ci);
        } else {
            if let Some(l) = self.lanes.get_mut(lane) {
                l.failed_total += 1;
            }
            // Requeue happens in on_batch_result, once we know the whole
            // batch's fate — a chunk can be `err` on one lane while its hedged
            // twin is still in flight on another.
            let c = &mut self.chunks[ci];
            c.on.retain(|&l| l != lane);
            if c.on.is_empty() {
                if c.attempts >= self.cfg.max_attempts {
                    c.phase = ChunkPhase::Failed;
                    self.failed += 1;
                } else {
                    c.phase = ChunkPhase::Pending;
                    c.hedged = false;
                    self.pending.push(ci);
                }
            }
        }
        let _ = now_ms;
    }

    /// A group reaching its threshold retires the rest of its members.
    ///
    /// This is the erasure seam: with `need = shard_cnt`, an RS codeword is
    /// complete as soon as enough of its shards land, and the stragglers stop
    /// being work. Under `AllAcked` no groups exist and this is a no-op.
    fn on_group_ack(&mut self, ci: usize) {
        if self.policy != CompletionPolicy::Group {
            return;
        }
        let Some(gid) = self.chunks[ci].group else {
            return;
        };
        let g = &mut self.groups[gid as usize];
        g.acked += 1;
        if g.acked < g.need {
            return;
        }
        for k in 0..self.chunks.len() {
            let c = &mut self.chunks[k];
            if c.group != Some(gid) {
                continue;
            }
            if matches!(c.phase, ChunkPhase::Pending) {
                c.phase = ChunkPhase::Skipped;
                self.skipped += 1;
            }
        }
        self.pending
            .retain(|&k| self.chunks[k].phase == ChunkPhase::Pending);
    }

    /// Bring a lane back after a cheque has been accepted.
    ///
    /// The counterpart to `PaymentRequired`: because that outcome left
    /// `fail_streak` and `backoff_exp` alone, settling restores the lane to
    /// exactly the health it had before it ran out of credit, rather than
    /// making it re-warm.
    pub fn fund_lane(&mut self, lane: usize) {
        if let Some(l) = self.lanes.get_mut(lane)
            && l.health == LaneHealth::Unfunded
        {
            l.health = if l.bytes_total > 0 {
                LaneHealth::Live
            } else {
                LaneHealth::Warming
            };
        }
    }

    /// Take a lane out of rotation permanently.
    ///
    /// For lanes that are unusable by configuration rather than by
    /// behaviour — a lane enforcing payment this client cannot make — where
    /// there is nothing to discover by trying and every attempt costs the
    /// chunks one of their retries.
    pub fn retire_lane(&mut self, lane: usize) {
        if let Some(l) = self.lanes.get_mut(lane) {
            l.health = LaneHealth::Retired;
        }
    }

    /// Re-clamp a lane's frames-per-POST between dispatches.
    ///
    /// A metered lane's affordable body shrinks as debt and in-flight bytes
    /// accumulate and grows back as cheques clear, so the ceiling set at
    /// startup goes stale immediately. Sizing the assignment here is what
    /// keeps the client from building a body the relay will refuse — §7.2
    /// wants the POST sized to fit rather than the ceiling discovered as a
    /// 402.
    pub fn set_lane_batch_max(&mut self, lane: usize, max: usize) {
        if let Some(l) = self.lanes.get_mut(lane) {
            l.info.batch_max = Some(max.max(1));
        }
    }

    /// Lanes currently paused for payment, so the driver knows which ones a
    /// cheque would unblock.
    pub fn unfunded_lanes(&self) -> Vec<usize> {
        self.lanes
            .iter()
            .enumerate()
            .filter(|(_, l)| l.health == LaneHealth::Unfunded)
            .map(|(i, _)| i)
            .collect()
    }

    /// Record the HTTP-level result of a dispatch. Must be called exactly
    /// once per [`Assignment`], after all of that batch's acks.
    pub fn on_batch_result(&mut self, batch: u64, outcome: BatchOutcome, now_ms: u64) {
        let Some((lane, chunks)) = self.outstanding.remove(&batch) else {
            return;
        };
        self.lanes[lane].inflight = self.lanes[lane].inflight.saturating_sub(1);

        let acked_here = chunks
            .iter()
            .filter(|&&ci| self.chunks[ci].phase == ChunkPhase::Done)
            .count();

        match outcome {
            BatchOutcome::Answered if acked_here > 0 => {
                let l = &mut self.lanes[lane];
                l.fail_streak = 0;
                l.backoff_exp = 0;
                l.health = LaneHealth::Live;
            }
            // A 402 says the relay is willing and the client is behind on
            // payment. Pause the lane without touching `fail_streak` or
            // `backoff_exp`, so settling restores it instantly and a long
            // upload is not punished for crossing a settlement window.
            // It also must not consume a retry attempt: a routine
            // settlement every ~32 MiB would otherwise fail a large upload
            // after a handful of windows. Undo the dispatch increment.
            BatchOutcome::PaymentRequired => {
                self.lanes[lane].health = LaneHealth::Unfunded;
                for &ci in &chunks {
                    let c = &mut self.chunks[ci];
                    if matches!(c.phase, ChunkPhase::Done | ChunkPhase::Skipped) {
                        continue;
                    }
                    c.attempts = c.attempts.saturating_sub(1);
                }
            }
            _ => {
                let l = &mut self.lanes[lane];
                l.fail_streak += 1;
                if l.fail_streak >= FAIL_STREAK {
                    l.backoff_exp += 1;
                    if l.backoff_exp > MAX_BACKOFF_EXP {
                        l.health = LaneHealth::Retired;
                    } else {
                        let wait = (BACKOFF_BASE_MS << (l.backoff_exp - 1)).min(BACKOFF_MAX_MS);
                        l.health = LaneHealth::Backoff {
                            until_ms: now_ms + wait,
                        };
                    }
                    l.fail_streak = 0;
                }
            }
        }

        // Anything in this batch still not resolved goes back to pending (or
        // dies), unless a hedged twin is still carrying it.
        for &ci in &chunks {
            let c = &mut self.chunks[ci];
            if matches!(c.phase, ChunkPhase::Done | ChunkPhase::Skipped) {
                continue;
            }
            c.on.retain(|&l| l != lane);
            if !c.on.is_empty() {
                continue;
            }
            if c.attempts >= self.cfg.max_attempts {
                if c.phase != ChunkPhase::Failed {
                    c.phase = ChunkPhase::Failed;
                    self.failed += 1;
                }
            } else if c.phase != ChunkPhase::Pending {
                c.phase = ChunkPhase::Pending;
                c.hedged = false;
                self.pending.push(ci);
            }
        }
    }

    /// Feed a lane's observed throughput for one batch.
    pub fn on_batch_timing(&mut self, lane: usize, acked: usize, elapsed_ms: u64) {
        let Some(l) = self.lanes.get_mut(lane) else {
            return;
        };
        let ms = elapsed_ms.max(1) as f64;
        l.batch_ms = if l.batch_ms == 0.0 {
            ms
        } else {
            0.7 * l.batch_ms + 0.3 * ms
        };
        if acked < RATE_MIN_SAMPLE {
            return;
        }
        let sample = acked as f64 * 1000.0 / ms;
        l.rate = if l.rate == 0.0 {
            sample
        } else {
            0.7 * l.rate + 0.3 * sample
        };
    }

    fn expire_backoffs(&mut self, now_ms: u64) {
        for l in &mut self.lanes {
            if let LaneHealth::Backoff { until_ms } = l.health
                && now_ms >= until_ms
            {
                // Half-open: one probe batch decides whether it is back.
                l.health = LaneHealth::Warming;
            }
        }
    }

    /// Weighted-rendezvous rank-`n` lane for a chunk (0 = best).
    fn rank_nth(&self, ci: usize, eligible: &[usize], n: usize) -> Option<usize> {
        let mut scored: Vec<(f64, usize)> =
            eligible.iter().map(|&l| (self.score(ci, l), l)).collect();
        // Descending by score; lane id breaks ties deterministically (and a
        // tie is astronomically unlikely with 64-bit hashes anyway — unlike
        // the proximity scheme this replaces, where ties were the norm).
        scored.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.1.cmp(&b.1))
        });
        scored.get(n).map(|&(_, l)| l)
    }

    fn rank_lane(&self, ci: usize, eligible: &[usize]) -> Option<usize> {
        self.rank_nth(ci, eligible, 0)
    }

    /// Weighted rendezvous score: `w / -ln(u)`, `u ∈ (0,1)` from
    /// `hash(addr ‖ lane)`. Max wins.
    fn score(&self, ci: usize, lane: usize) -> f64 {
        let l = &self.lanes[lane];
        let mut w = l.weight(&self.cfg);
        if self.cfg.proximity_alpha > 0.0
            && let Some(ov) = l.info.overlay
        {
            let po = proximity(&self.chunks[ci].addr, &ov) as f64;
            w *= 1.0 + self.cfg.proximity_alpha * (po.min(PROX_CAP) / PROX_CAP);
        }
        let h = hash64(&self.chunks[ci].addr, l.id as u64);
        // (h+1)/2^64 ∈ (0,1]; -ln of it is in [0,∞).
        let u = (h as f64 + 1.0) / (u64::MAX as f64 + 1.0);
        let denom = -u.ln();
        if denom <= f64::MIN_POSITIVE {
            f64::MAX
        } else {
            w / denom
        }
    }

    pub fn done(&self) -> bool {
        self.acked + self.failed + self.skipped >= self.chunks.len()
    }

    pub fn acked(&self) -> usize {
        self.acked
    }

    pub fn failed(&self) -> usize {
        self.failed
    }

    pub fn skipped(&self) -> usize {
        self.skipped
    }

    pub fn total(&self) -> usize {
        self.chunks.len()
    }

    pub fn hedges(&self) -> usize {
        self.hedges_used
    }

    /// Dispatches issued but not yet resolved by
    /// [`Self::on_batch_result`].
    pub fn in_flight(&self) -> usize {
        self.outstanding.len()
    }

    /// Addresses of chunks that were never acked. For error reporting.
    pub fn failed_addrs(&self) -> Vec<[u8; 32]> {
        self.chunks
            .iter()
            .filter(|c| c.phase == ChunkPhase::Failed)
            .map(|c| c.addr)
            .collect()
    }

    /// True when nothing is in flight and nothing can be dispatched, yet work
    /// remains — the caller should stop rather than spin.
    ///
    /// The counterpart of `joiner`'s `total - failed < shard_cnt` early bail:
    /// recognising a hopeless state immediately beats grinding through the
    /// full retry budget waiting out timeouts that cannot succeed.
    pub fn stalled(&self, now_ms: u64) -> Option<StallReason> {
        if self.done() || !self.outstanding.is_empty() {
            return None;
        }
        let any_eligible = self.lanes.iter().any(|l| l.eligible(now_ms));
        if !any_eligible {
            // Backed-off lanes will come back; only a fully retired set is
            // terminal. An all-`Unfunded` set with nothing in flight is the
            // same kind of terminal for a driver that cannot mint a cheque
            // (dust residual below the floor): report it rather than
            // waiting on a channel that never fires.
            let all_retired = self
                .lanes
                .iter()
                .all(|l| matches!(l.health, LaneHealth::Retired));
            if all_retired {
                return Some(StallReason::AllLanesDown);
            }
            let all_unfunded_or_retired = self
                .lanes
                .iter()
                .all(|l| matches!(l.health, LaneHealth::Retired | LaneHealth::Unfunded));
            if all_unfunded_or_retired {
                return Some(StallReason::AllLanesDown);
            }
            return None;
        }
        if self.pending.is_empty() {
            return Some(StallReason::ChunksExhausted);
        }
        None
    }

    /// When the caller should wake up if [`Self::next`] returned `None`:
    /// the earliest of any backoff expiry or hedge deadline.
    pub fn next_wake_ms(&self, now_ms: u64) -> Option<u64> {
        let mut wake: Option<u64> = None;
        let mut bump = |t: u64| {
            wake = Some(wake.map_or(t, |w: u64| w.min(t)));
        };
        for l in &self.lanes {
            if let LaneHealth::Backoff { until_ms } = l.health
                && until_ms > now_ms
            {
                bump(until_ms);
            }
        }
        for c in &self.chunks {
            if c.phase == ChunkPhase::InFlight && !c.hedged && !c.on.is_empty() {
                let d = self.lanes[c.on[0]].hedge_deadline_ms(&self.cfg);
                bump(c.since_ms + d);
            }
        }
        wake
    }

    pub fn lane_stats(&self) -> Vec<LaneStats> {
        self.lanes
            .iter()
            .map(|l| LaneStats {
                acked: l.acked_total,
                failed: l.failed_total,
                bytes: l.bytes_total,
                rate: l.rate,
                health: Some(match l.health {
                    LaneHealth::Warming => LaneHealthKind::Warming,
                    LaneHealth::Live => LaneHealthKind::Live,
                    LaneHealth::Backoff { .. } => LaneHealthKind::Backoff,
                    LaneHealth::Unfunded => LaneHealthKind::Unfunded,
                    LaneHealth::Retired => LaneHealthKind::Retired,
                }),
            })
            .collect()
    }
}

/// Kademlia proximity order: leading bits shared by two addresses.
pub fn proximity(a: &[u8; 32], b: &[u8; 32]) -> u8 {
    for i in 0..32 {
        let x = a[i] ^ b[i];
        if x != 0 {
            return (i as u8) * 8 + x.leading_zeros() as u8;
        }
    }
    255
}

/// splitmix64 over the address folded with the lane id.
///
/// Explicit rather than `DefaultHasher` so the mapping is stable across
/// toolchains and reproducible in tests — a rendezvous hash that changes
/// under you silently reshuffles every chunk's lane.
fn hash64(addr: &[u8; 32], lane: u64) -> u64 {
    let mut acc = lane.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    for c in addr.chunks_exact(8) {
        let v = u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
        acc ^= v;
        acc = acc.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        acc ^= acc >> 31;
    }
    let mut z = acc.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests;
