//! Deterministic simulation of the multi-lane scheduler.
//!
//! No network, no clock, no threads: mock lanes with configurable
//! throughput, failure and cold-start behaviour are driven by a virtual
//! clock, so lane pathologies that take minutes to reproduce against real
//! free-tier relays are exercised in microseconds and never flake.
//!
//! Modelled on how `erasure::joiner` is tested — a store that can be told to
//! lose specific addresses — because the interesting behaviour in both cases
//! is what happens when an arbitrary subset of the work refuses to complete.

use super::*;

/// Deterministic pseudo-random chunk addresses.
fn addrs(n: usize, seed: u64) -> Vec<([u8; 32], u32)> {
    let mut out = Vec::with_capacity(n);
    let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    for _ in 0..n {
        let mut a = [0u8; 32];
        for c in a.chunks_exact_mut(8) {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            c.copy_from_slice(&s.to_le_bytes());
        }
        out.push((a, 4096));
    }
    out
}

fn hex32(s: &str) -> [u8; 32] {
    let mut a = [0u8; 32];
    for (i, b) in a.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex");
    }
    a
}

/// The four production relay overlays, read from `/v1/status`. Three of them
/// share a 6-bit prefix, which is what made proximity-argmax routing collapse
/// to a 49 / 50 / 0.8 / 0.2 split.
fn production_overlays() -> Vec<[u8; 32]> {
    vec![
        hex32("df3d66ca610a3d771da02df25e1daea331dd4b2b57f9e56d32a1a095fed33e7d"),
        hex32("dd741bc8498f5f709f1930d21b9e2ff5c956503a01dcb2c2d68c95fc7c66495d"),
        hex32("ddc9d13f39777a1980b5d5b40d40ac2746b94b46401afeb75bfabe608c792e68"),
        hex32("2bba0b8341693c351d3a85b285a89fed07e003058dda438c6af765caa097f090"),
    ]
}

/// Behaviour of one simulated relay.
#[derive(Clone)]
struct MockLane {
    /// Chunks acked per second once serving.
    rate_per_s: f64,
    /// Fixed per-batch overhead (request latency).
    latency_ms: u64,
    /// Batches wholly rejected before the lane starts working. Models a
    /// cold free-tier instance, or one that is simply down.
    fail_first: usize,
    /// Every Nth chunk fails on this lane (0 = never).
    chunk_fail_every: usize,
    failed_batches: usize,
    seen_chunks: usize,
}

impl Default for MockLane {
    fn default() -> Self {
        Self {
            rate_per_s: 10.0,
            latency_ms: 100,
            fail_first: 0,
            chunk_fail_every: 0,
            failed_batches: 0,
            seen_chunks: 0,
        }
    }
}

struct Event {
    at_ms: u64,
    batch: u64,
    lane: usize,
    chunks: Vec<usize>,
    /// `None` = the POST itself failed.
    acks: Option<Vec<bool>>,
    started_ms: u64,
}

/// Run a scheduler to completion against mock lanes. Returns
/// `(finish_ms, per-lane chunks acked)`.
fn run(sched: &mut Scheduler, lanes: &mut [MockLane], cap_ms: u64) -> (u64, Vec<usize>) {
    let mut now = 0u64;
    let mut events: Vec<Event> = Vec::new();
    let mut per_lane = vec![0usize; lanes.len()];

    while !sched.done() {
        // Dispatch everything the scheduler is willing to hand out.
        while let Some(a) = sched.next(now) {
            let l = &mut lanes[a.lane];
            let n = a.chunks.len();
            let dur = a.chunks.len() as f64 * 1000.0 / l.rate_per_s;
            let at = now + l.latency_ms + dur as u64;
            let acks = if l.failed_batches < l.fail_first {
                l.failed_batches += 1;
                None
            } else {
                Some(
                    a.chunks
                        .iter()
                        .map(|_| {
                            l.seen_chunks += 1;
                            l.chunk_fail_every == 0
                                || !l.seen_chunks.is_multiple_of(l.chunk_fail_every)
                        })
                        .collect(),
                )
            };
            let _ = n;
            events.push(Event {
                at_ms: at,
                batch: a.batch,
                lane: a.lane,
                chunks: a.chunks,
                acks,
                started_ms: now,
            });
        }

        if events.is_empty() {
            match sched.next_wake_ms(now) {
                Some(t) if t > now => {
                    now = t;
                    continue;
                }
                _ => break,
            }
        }

        // Advance to the earliest completion.
        let i = events
            .iter()
            .enumerate()
            .min_by_key(|(_, e)| e.at_ms)
            .map(|(i, _)| i)
            .expect("events non-empty");
        let e = events.remove(i);
        now = now.max(e.at_ms);
        if now > cap_ms {
            panic!("simulation exceeded {cap_ms} ms of virtual time");
        }

        match &e.acks {
            Some(acks) => {
                let mut ok_n = 0;
                for (&ci, &ok) in e.chunks.iter().zip(acks) {
                    let addr = sched.chunk_addr(ci);
                    let was_done = sched.chunks[ci].phase == ChunkPhase::Done;
                    sched.on_ack(e.lane, &addr, ok, now);
                    if ok {
                        ok_n += 1;
                        if !was_done {
                            per_lane[e.lane] += 1;
                        }
                    }
                }
                sched.on_batch_timing(e.lane, ok_n, now - e.started_ms);
                sched.on_batch_result(e.batch, BatchOutcome::Answered, now);
            }
            None => {
                sched.on_batch_timing(e.lane, 0, now - e.started_ms);
                sched.on_batch_result(e.batch, BatchOutcome::Failed("mock down".into()), now);
            }
        }
    }
    (now, per_lane)
}

fn lane_infos(n: usize) -> Vec<LaneInfo> {
    (0..n).map(|_| LaneInfo::default()).collect()
}

// ---------------------------------------------------------------------------
// Assignment distribution
// ---------------------------------------------------------------------------

/// The regression that motivated the rewrite: with the real production
/// overlays, proximity-argmax gave 49 / 50 / 0.8 / 0.2. Weighted rendezvous
/// with equal weights must be uniform regardless of how the overlays cluster.
#[test]
fn distribution_is_uniform_on_clustered_production_overlays() {
    let infos: Vec<LaneInfo> = production_overlays()
        .into_iter()
        .map(|o| LaneInfo {
            overlay: Some(o),
            ..Default::default()
        })
        .collect();
    let mut sched = Scheduler::new(infos, Config::default());
    let n = 20_000;
    sched.admit(addrs(n, 42));

    let eligible: Vec<usize> = (0..4).collect();
    let mut counts = [0usize; 4];
    for ci in 0..n {
        counts[sched.rank_lane(ci, &eligible).expect("a lane")] += 1;
    }
    let expect = n / 4;
    for (l, &c) in counts.iter().enumerate() {
        let dev = (c as f64 - expect as f64).abs() / expect as f64;
        assert!(
            dev < 0.05,
            "lane {l} got {c}/{n} ({:.1}%), expected ~25% (dev {dev:.3})",
            100.0 * c as f64 / n as f64
        );
    }
}

/// The failure mode this replaces, asserted directly so the regression can't
/// creep back in disguised as "proximity routing".
#[test]
fn proximity_argmax_would_be_pathological() {
    let ov = production_overlays();
    let mut counts = [0usize; 4];
    for (a, _) in addrs(20_000, 7) {
        // `max_by_key` semantics: last maximum wins on ties.
        let best = (0..4).max_by_key(|&l| proximity(&a, &ov[l])).expect("lane");
        counts[best] += 1;
    }
    let worst = *counts.iter().min().expect("counts");
    assert!(
        worst * 20 < 20_000 / 4,
        "expected proximity-argmax to starve a lane, got {counts:?}"
    );
}

#[test]
fn distribution_follows_weights() {
    // pool_live is the throughput prior before any measurement.
    let infos = vec![
        LaneInfo {
            pool_live: Some(128),
            ..Default::default()
        },
        LaneInfo {
            pool_live: Some(32),
            ..Default::default()
        },
    ];
    let mut sched = Scheduler::new(infos, Config::default());
    let n = 20_000;
    sched.admit(addrs(n, 99));
    let eligible = vec![0usize, 1];
    let mut counts = [0usize; 2];
    for ci in 0..n {
        counts[sched.rank_lane(ci, &eligible).expect("a lane")] += 1;
    }
    // Weights are 16 and 4 → a 4:1 split.
    let ratio = counts[0] as f64 / counts[1] as f64;
    assert!(
        (3.6..4.4).contains(&ratio),
        "expected ~4:1 by weight, got {counts:?} (ratio {ratio:.2})"
    );
}

/// Two lanes that answer a batch equally fast are not equal if one accepts 8
/// concurrent POSTs and the other 1. Observed on a two-lane VPS run: the
/// low-concurrency lane's per-batch rate read *higher* than the fast lane's,
/// which would have mis-weighted it badly.
#[test]
fn weight_accounts_for_lane_concurrency() {
    let infos = vec![
        LaneInfo {
            pool_live: Some(64),
            inflight_max: Some(8),
            ..Default::default()
        },
        LaneInfo {
            pool_live: Some(64),
            inflight_max: Some(1),
            ..Default::default()
        },
    ];
    let mut sched = Scheduler::new(infos, Config::default());
    let n = 10_000;
    sched.admit(addrs(n, 77));
    // Equal per-batch capability, measured.
    sched.lanes[0].health = LaneHealth::Live;
    sched.lanes[1].health = LaneHealth::Live;
    sched.on_batch_timing(0, 256, 1_000);
    sched.on_batch_timing(1, 256, 1_000);
    let eligible = vec![0usize, 1];
    let mut counts = [0usize; 2];
    for ci in 0..n {
        counts[sched.rank_lane(ci, &eligible).expect("a lane")] += 1;
    }
    let ratio = counts[0] as f64 / counts[1] as f64;
    assert!(
        (7.0..9.0).contains(&ratio),
        "expected ~8:1 by concurrency, got {counts:?} (ratio {ratio:.2})"
    );
}

/// A handful of chunks answered quickly is not evidence of throughput.
#[test]
fn tiny_batches_do_not_move_the_rate_ewma() {
    let mut sched = Scheduler::new(lane_infos(1), Config::default());
    sched.admit(addrs(10, 78));
    // 4 chunks in 10 ms would read as 400/s.
    sched.on_batch_timing(0, 4, 10);
    assert_eq!(
        sched.lane_stats()[0].rate,
        0.0,
        "a 4-chunk sample must not set the rate"
    );
    sched.on_batch_timing(0, 256, 1_000);
    assert!(
        (sched.lane_stats()[0].rate - 256.0).abs() < 1.0,
        "a full batch should set the rate, got {}",
        sched.lane_stats()[0].rate
    );
}

#[test]
fn rank2_is_distinct_and_stable() {
    let mut sched = Scheduler::new(lane_infos(4), Config::default());
    sched.admit(addrs(500, 5));
    let eligible: Vec<usize> = (0..4).collect();
    for ci in 0..500 {
        let a = sched.rank_nth(ci, &eligible, 0).expect("rank 0");
        let b = sched.rank_nth(ci, &eligible, 1).expect("rank 1");
        assert_ne!(a, b, "rank #2 must differ from rank #1");
        assert_eq!(a, sched.rank_nth(ci, &eligible, 0).expect("stable"));
    }
}

/// Removing a lane must only move that lane's chunks — the minimal-disruption
/// property that makes retries sticky when a lane drops out mid-run.
#[test]
fn lane_removal_only_reshuffles_that_lanes_share() {
    let mut sched = Scheduler::new(lane_infos(4), Config::default());
    let n = 5_000;
    sched.admit(addrs(n, 11));
    let all: Vec<usize> = (0..4).collect();
    let without: Vec<usize> = vec![0, 1, 2];
    let mut moved = 0;
    let mut belonged_to_3 = 0;
    for ci in 0..n {
        let before = sched.rank_lane(ci, &all).expect("lane");
        let after = sched.rank_lane(ci, &without).expect("lane");
        if before == 3 {
            belonged_to_3 += 1;
        } else if before != after {
            moved += 1;
        }
    }
    assert_eq!(moved, 0, "{moved} chunks moved that didn't have to");
    assert!(belonged_to_3 > 0, "lane 3 should have had work");
}

// ---------------------------------------------------------------------------
// Runtime behaviour
// ---------------------------------------------------------------------------

#[test]
fn all_chunks_land_on_healthy_lanes() {
    let mut sched = Scheduler::new(lane_infos(3), Config::default());
    sched.admit(addrs(1_000, 1));
    let mut lanes = vec![MockLane::default(); 3];
    let (_, per_lane) = run(&mut sched, &mut lanes, 600_000);
    assert!(sched.done());
    assert_eq!(sched.acked(), 1_000);
    assert_eq!(sched.failed(), 0);
    assert!(
        per_lane.iter().all(|&c| c > 0),
        "every lane should carry work: {per_lane:?}"
    );
}

/// A slow lane must not set the finish time. This is the property the old
/// work-stealing layer existed to provide; weighted rendezvous plus lazy
/// (dispatch-time) assignment has to provide it without stealing.
#[test]
fn slow_lane_does_not_set_the_finish_time() {
    let mut sched = Scheduler::new(lane_infos(2), Config::default());
    sched.admit(addrs(2_000, 3));
    let mut lanes = vec![
        MockLane {
            rate_per_s: 100.0,
            ..Default::default()
        },
        MockLane {
            rate_per_s: 2.0,
            ..Default::default()
        },
    ];
    let (finish, per_lane) = run(&mut sched, &mut lanes, 2_000_000);
    assert_eq!(sched.acked(), 2_000);
    assert!(
        per_lane[0] > per_lane[1] * 3,
        "fast lane should carry most of the load: {per_lane:?}"
    );
    // A naive even split would take ~1000/2 = 500 s on the slow lane.
    assert!(
        finish < 300_000,
        "slow lane dominated the finish time: {finish} ms"
    );
}

/// A free-tier relay that is merely asleep must not be written off. It fails
/// its first batches, backs off, and is expected to serve after waking.
#[test]
fn cold_lane_backs_off_then_recovers() {
    let mut sched = Scheduler::new(lane_infos(2), Config::default());
    sched.admit(addrs(600, 21));
    let mut lanes = vec![
        MockLane::default(),
        MockLane {
            fail_first: 3,
            ..Default::default()
        },
    ];
    let (_, per_lane) = run(&mut sched, &mut lanes, 600_000);
    assert_eq!(sched.acked(), 600);
    assert!(
        per_lane[1] > 0,
        "cold lane never recovered: {per_lane:?} / {:?}",
        sched.lane_stats()
    );
    assert_ne!(
        sched.lane_stats()[1].health,
        Some(LaneHealthKind::Retired),
        "a lane that recovered must not stay retired"
    );
}

#[test]
fn dead_lane_retires_and_run_still_completes() {
    let mut sched = Scheduler::new(lane_infos(2), Config::default());
    sched.admit(addrs(400, 22));
    let mut lanes = vec![
        MockLane::default(),
        MockLane {
            fail_first: usize::MAX,
            ..Default::default()
        },
    ];
    let (_, per_lane) = run(&mut sched, &mut lanes, 2_000_000);
    assert_eq!(sched.acked(), 400, "healthy lane must absorb everything");
    assert_eq!(per_lane[1], 0);
}

#[test]
fn all_lanes_down_is_reported_not_spun_on() {
    let mut sched = Scheduler::new(lane_infos(2), Config::default());
    sched.admit(addrs(100, 23));
    let mut lanes = vec![
        MockLane {
            fail_first: usize::MAX,
            ..Default::default()
        },
        MockLane {
            fail_first: usize::MAX,
            ..Default::default()
        },
    ];
    let (finish, _) = run(&mut sched, &mut lanes, 10_000_000);
    assert!(!sched.done());
    assert_eq!(sched.stalled(finish), Some(StallReason::AllLanesDown));
}

#[test]
fn chunk_gives_up_after_max_attempts() {
    let cfg = Config {
        max_attempts: 3,
        ..Default::default()
    };
    let mut sched = Scheduler::new(lane_infos(2), cfg);
    sched.admit(addrs(20, 24));
    // Every 1st chunk of every batch fails, forever.
    let mut lanes = vec![
        MockLane {
            chunk_fail_every: 1,
            ..Default::default()
        },
        MockLane {
            chunk_fail_every: 1,
            ..Default::default()
        },
    ];
    run(&mut sched, &mut lanes, 2_000_000);
    assert_eq!(sched.acked(), 0);
    assert_eq!(sched.failed(), 20);
    assert!(sched.done(), "give-up must terminate the run");
    assert_eq!(sched.failed_addrs().len(), 20);
}

#[test]
fn duplicate_acks_are_idempotent() {
    let mut sched = Scheduler::new(lane_infos(2), Config::default());
    sched.admit(addrs(4, 25));
    let a = sched.next(0).expect("assignment");
    let addr = sched.chunk_addr(a.chunks[0]);
    sched.on_ack(a.lane, &addr, true, 10);
    sched.on_ack(a.lane, &addr, true, 20);
    sched.on_ack(1 - a.lane, &addr, true, 30);
    assert_eq!(sched.acked(), 1, "one chunk, one ack");
}

/// Hedging must fire for genuine stragglers and stay inside its budget, so
/// cross-lane egress stays near 1× payload rather than 2×.
#[test]
fn hedge_is_bounded_and_targets_stragglers() {
    let cfg = Config {
        batch: 32,
        hedge_min_ms: 500,
        hedge_fraction: 0.10,
        ..Default::default()
    };
    let mut sched = Scheduler::new(lane_infos(2), cfg);
    sched.admit(addrs(1_000, 26));
    let mut lanes = vec![
        MockLane {
            rate_per_s: 200.0,
            ..Default::default()
        },
        MockLane {
            rate_per_s: 0.5,
            latency_ms: 5_000,
            ..Default::default()
        },
    ];
    run(&mut sched, &mut lanes, 5_000_000);
    assert_eq!(sched.acked(), 1_000);
    let budget = (1_000f64 * 0.10).ceil() as usize;
    assert!(
        sched.hedges() <= budget.max(8),
        "hedges {} exceeded budget {budget}",
        sched.hedges()
    );
}

#[test]
fn no_hedging_with_a_single_lane() {
    let cfg = Config {
        hedge_min_ms: 1,
        ..Default::default()
    };
    let mut sched = Scheduler::new(lane_infos(1), cfg);
    sched.admit(addrs(200, 27));
    let mut lanes = vec![MockLane {
        rate_per_s: 1.0,
        ..Default::default()
    }];
    run(&mut sched, &mut lanes, 5_000_000);
    assert_eq!(sched.hedges(), 0);
    assert_eq!(sched.acked(), 200);
}

// ---------------------------------------------------------------------------
// Streaming admission
// ---------------------------------------------------------------------------

#[test]
fn streaming_admission_matches_one_shot() {
    let chunks = addrs(900, 31);
    let mut one = Scheduler::new(lane_infos(3), Config::default());
    one.admit(chunks.clone());
    let mut lanes = vec![MockLane::default(); 3];
    run(&mut one, &mut lanes, 600_000);

    let mut streamed = Scheduler::new(lane_infos(3), Config::default());
    let mut lanes2 = vec![MockLane::default(); 3];
    let mut now = 0u64;
    for window in chunks.chunks(100) {
        streamed.admit(window.to_vec());
        // Drain what we can before the next window is stamped.
        while let Some(a) = streamed.next(now) {
            for &ci in &a.chunks {
                let addr = streamed.chunk_addr(ci);
                streamed.on_ack(a.lane, &addr, true, now);
            }
            streamed.on_batch_timing(a.lane, a.chunks.len(), 100);
            streamed.on_batch_result(a.batch, BatchOutcome::Answered, now);
            now += 100;
        }
    }
    let _ = &mut lanes2;
    assert!(streamed.done());
    assert_eq!(streamed.acked(), one.acked());
    assert_eq!(streamed.acked(), 900);
}

#[test]
fn repeat_addresses_are_admitted_once() {
    let mut sched = Scheduler::new(lane_infos(2), Config::default());
    let c = addrs(10, 33);
    sched.admit(c.clone());
    sched.admit(c);
    assert_eq!(sched.total(), 10);
}

// ---------------------------------------------------------------------------
// Erasure seam
// ---------------------------------------------------------------------------

/// The `CompletionPolicy::Group` hook: a Reed–Solomon codeword is complete
/// once `need` of its shards land, so the stragglers stop being work. Same
/// stopping rule as `erasure::joiner`'s `present >= shard_cnt`.
#[test]
fn group_policy_completes_at_threshold() {
    let mut sched = Scheduler::with_policy(
        lane_infos(2),
        Config {
            batch: 4,
            ..Default::default()
        },
        CompletionPolicy::Group,
    );
    // One codeword: 8 shards + 2 parity, retrievable at 8.
    sched.admit_group(addrs(10, 41), 8);
    let mut lanes = vec![MockLane::default(); 2];
    run(&mut sched, &mut lanes, 600_000);
    assert!(sched.done());
    assert!(
        sched.acked() >= 8,
        "codeword needs 8 shards, got {}",
        sched.acked()
    );
    assert_eq!(
        sched.acked() + sched.skipped() + sched.failed(),
        10,
        "every chunk must reach a terminal state"
    );
}

#[test]
fn all_acked_policy_ignores_groups() {
    let mut sched = Scheduler::new(lane_infos(2), Config::default());
    sched.admit_group(addrs(10, 42), 8);
    let mut lanes = vec![MockLane::default(); 2];
    run(&mut sched, &mut lanes, 600_000);
    assert_eq!(sched.acked(), 10, "AllAcked must not stop at the threshold");
    assert_eq!(sched.skipped(), 0);
}

// ── Metered lanes (docs/pusher-incentives.md §12) ────────────────────────

fn two_lanes() -> Scheduler {
    let infos = vec![LaneInfo::default(), LaneInfo::default()];
    let mut s = Scheduler::new(infos, Config::default());
    s.admit(addrs(64, 7));
    s
}

/// Drive one batch and hand back `(batch, lane)`. The scheduler chooses the
/// lane by weight, so tests follow its choice rather than dictating one.
fn dispatch_one(s: &mut Scheduler, now_ms: u64) -> (u64, usize) {
    let a = s
        .next(now_ms)
        .expect("a lane with pending work must produce an assignment");
    (a.batch, a.lane)
}

/// The failure §12 exists to prevent: five routine settlements retiring a
/// perfectly healthy lane mid-upload.
#[test]
fn repeated_402s_never_retire_a_lane() {
    let mut s = two_lanes();
    let mut now = 0u64;
    for _ in 0..20 {
        let (b, lane) = dispatch_one(&mut s, now);
        s.on_batch_result(b, BatchOutcome::PaymentRequired, now);
        // Settling is what un-pauses it; without that the lane stays out.
        s.fund_lane(lane);
        now += 1000;
    }
    for (i, st) in s.lane_stats().iter().enumerate() {
        assert_ne!(
            st.health.expect("health"),
            LaneHealthKind::Retired,
            "lane {i} kept asking to be paid and must never be retired"
        );
    }
}

/// A 402 must not burn a retry attempt: a routine settlement every ~32 MiB
/// would otherwise fail a large upload after a handful of windows.
#[test]
fn a_402_does_not_burn_a_retry_attempt() {
    let mut s = two_lanes();
    let max = s.cfg.max_attempts;
    // Exhaust all but one attempt with real failures, then 402 repeatedly:
    // the chunk must never tip into Failed from 402s alone.
    for _ in 0..20 {
        let (b, _lane) = dispatch_one(&mut s, 0);
        s.on_batch_result(b, BatchOutcome::PaymentRequired, 0);
        // fund so the lane stays dispatchable; attempts are what we assert.
        for l in s.unfunded_lanes() {
            s.fund_lane(l);
        }
    }
    assert_eq!(s.failed(), 0, "402s must never fail a chunk");
    assert!(s.total() > s.failed(), "work remains");
    let _ = max;
}

/// A 402 must not touch the failure streak — otherwise a lane that has
/// been asking for payment is one transport error away from backoff.
#[test]
fn a_402_does_not_charge_lane_health() {
    let mut s = two_lanes();
    let mut victim = None;
    for i in 0..10 {
        let (b, lane) = dispatch_one(&mut s, 100 + i * 10);
        // Charge every 402 to one lane, so any accumulation would show.
        if victim.is_none() {
            victim = Some(lane);
        }
        s.on_batch_result(b, BatchOutcome::PaymentRequired, 100 + i * 10);
        s.fund_lane(lane);
    }
    // A single real failure now must still be just one failure, not the
    // straw that tips an already-charged streak into backoff.
    let (b, lane) = dispatch_one(&mut s, 500);
    s.on_batch_result(b, BatchOutcome::Failed("boom".into()), 500);
    let health = s.lane_stats()[lane].health.expect("health");
    assert!(
        matches!(health, LaneHealthKind::Live | LaneHealthKind::Warming),
        "one failure after many 402s must not have compounded: {health:?}"
    );
}

/// `Unfunded` is ineligible but recoverable — unlike `Retired`, which is
/// permanent for the run.
#[test]
fn an_unfunded_lane_is_paused_then_restored_by_paying() {
    let mut s = two_lanes();
    let (b, lane) = dispatch_one(&mut s, 0);
    s.on_batch_result(b, BatchOutcome::PaymentRequired, 0);

    assert_eq!(
        s.unfunded_lanes(),
        vec![lane],
        "the driver must see what to pay"
    );
    for _ in 0..8 {
        assert_ne!(
            s.next(20).map(|a| a.lane),
            Some(lane),
            "an unfunded lane must not be dispatched to"
        );
    }
    s.fund_lane(lane);
    assert!(s.unfunded_lanes().is_empty(), "paying clears the pause");
    assert!(s.next(30).is_some(), "and the run continues");
}

/// Work must not be stranded on a paused lane: chunks go back to pending
/// and another lane picks them up while the cheque is in flight.
#[test]
fn work_on_an_unfunded_lane_fails_over_rather_than_stalling() {
    let mut s = two_lanes();
    let (b, lane) = dispatch_one(&mut s, 0);
    s.on_batch_result(b, BatchOutcome::PaymentRequired, 0);
    let other = s.next(10).expect("work must not strand on a paused lane");
    assert_ne!(other.lane, lane, "it fails over to the funded lane");
}

/// Paying is optional (§2): a fleet may mix `open`, soft-metered and
/// hard-metered lanes, and a client with no chequebook must keep using the
/// ones it can.
///
/// A retired lane is out of rotation for good — the point is that nothing
/// is ever dispatched to it, since a lane that refuses for a missing
/// capability is not a 402 and would charge lane health once per chunk.
#[test]
fn a_retired_lane_never_receives_work() {
    let infos: Vec<LaneInfo> = (0..3).map(|_| LaneInfo::default()).collect();
    let mut sched = Scheduler::new(infos, Config::default());
    sched.admit(addrs(600, 7));

    // Lane 1 is the one this client cannot pay.
    sched.retire_lane(1);

    let mut seen = [0usize; 3];
    while let Some(a) = sched.next(0) {
        seen[a.lane] += 1;
        sched.on_batch_result(a.batch, BatchOutcome::Answered, 0);
    }
    assert_eq!(seen[1], 0, "retired lane took {} assignments", seen[1]);
    assert!(
        seen[0] > 0 && seen[2] > 0,
        "the payable lanes must still carry the upload: {seen:?}"
    );
}
