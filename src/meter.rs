//! Stage 0 shadow metering — `docs/pusher-incentives.md` §14.
//!
//! Measures what a *metered* relay would have billed, while changing
//! nothing on the wire. No new client-visible behaviour, no refusals, no
//! payment: the relay simply counts, and an operator reads the counts off
//! `/v1/meter`.
//!
//! It answers the two questions Stage 1 is gated on:
//!
//! 1. **Is anyone consuming enough to justify metering?** Per-account bytes
//!    admitted, what they would owe at §9.2's candidate price, and how many
//!    accounts would ever cross the cashout threshold — not a profitability
//!    line (§9.3's gas is negligible), but the volume at which cashing out
//!    is worth an operator's round trip at all.
//! 2. **Is `credit_ratio = 1000` right?** For every batch actually seen, the
//!    credit line §10.3 would have granted it, against the size of a full
//!    POST. A batch whose line is under one POST has to split its uploads,
//!    which is fine; a population where most batches are in that state means
//!    the ratio is wrong.
//!
//! It also reports §9.1's egress multiplier, which the doc *estimates* at
//! ×3 racing × 1.15 shallow ≈ 3.45 attempts per chunk — the number that
//! sets the whole cost basis. **The reported figure is not yet a valid
//! measurement of it.** It divides completed push outcomes by frames
//! admitted, and the racing dispatcher cancels losing racers before they
//! complete, so their egress is spent but uncounted (see `stream_attempts`
//! in `src/pusher.rs`). Treat it as a floor, not an observation.
//!
//! **Hot path cost is one lock per POST.** A request accumulates into a
//! [`PostTally`] on its own stack and merges once at completion, so N
//! concurrent POSTs contend N times rather than N × `PUSH_BATCH_MAX`.
//!
//! **Known limitation:** state is in-memory, so a restart resets it. That
//! biases "do accounts return?" downward on hosts that sleep, which is
//! exactly the free tier §5 says must not run metered anyway. Read the
//! window length (`window_secs`) before drawing conclusions from repeat
//! rates.

use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

// ── Candidate parameters (docs/pusher-incentives.md §9.2, §10.1) ─────────
//
// Constants rather than flags on purpose: Stage 0 exists to decide whether
// these numbers are right, and every figure in the report is derived from
// the same raw observations, so changing one re-derives the report without
// re-collecting anything.

/// $0.02/GiB at $0.40/BZZ → 5e14 PLUR/GiB ÷ 1 048 576 KiB.
pub const PRICE_PLUR_PER_KIB: u128 = 480_000_000;
/// ~32 MiB — one settlement window.
pub const SETTLE_EVERY_PLUR: u128 = 15_600_000_000_000;
/// ~127 MiB — the global ceiling on a credit line.
pub const MAX_OUTSTANDING_PLUR: u128 = 62_200_000_000_000;
/// 0.25 BZZ ≈ 5 GiB. Not a break-even: §9.3's measured cashout gas is ~1e-10
/// xDAI, so any non-zero cheque repays it. This is a batching convenience —
/// how much value to let accumulate before spending an RPC round trip and a
/// pending transaction on it — and should be derived from `eth_gasPrice`
/// rather than pinned, since Gnosis gas will not stay this cheap.
pub const CASHOUT_THRESHOLD_PLUR: u128 = 2_500_000_000_000_000;
/// Credit line = batch remaining value ÷ this (§10.3).
pub const CREDIT_RATIO: u128 = 1_000;

const PLUR_PER_BZZ: f64 = 1e16;
const USD_PER_BZZ: f64 = 0.40;

/// Distinct `(owner, batch)` pairs held before FIFO eviction. Bounded for
/// the same reason the owner cache is (§16.2): the key is attacker-chosen,
/// so an unbounded map is a memory DoS. Evicted rows keep contributing to
/// the totals, only their per-row detail is lost.
const METER_ROW_CAP: usize = 4096;

/// A shadow account is the batch-owner EOA (§6), and credit is keyed one
/// level finer, on the batch — so the ledger is keyed on both.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct AccountBatch {
    pub owner: [u8; 20],
    pub batch: [u8; 32],
}

#[derive(Clone)]
struct Row {
    /// Body bytes attributable to admitted frames, in KiB (§8).
    kib_admitted: u64,
    /// Of which served from the recent-ack cache, and so billed at zero
    /// (§8.2).
    kib_dedup: u64,
    frames: u64,
    dedup_frames: u64,
    /// `remainingBalance × 2^depth` observed at resolution (§6). Zero when
    /// the batch was never resolved with a value, which cannot currently
    /// happen but is not worth panicking over.
    remaining_value_plur: u128,
    first_seen: Instant,
    last_seen: Instant,
}

impl Row {
    fn billable_kib(&self) -> u64 {
        self.kib_admitted.saturating_sub(self.kib_dedup)
    }

    /// What §10.3 would have granted this batch.
    fn credit_plur(&self) -> u128 {
        (self.remaining_value_plur / CREDIT_RATIO).min(MAX_OUTSTANDING_PLUR)
    }

    fn credit_kib(&self) -> u64 {
        (self.credit_plur() / PRICE_PLUR_PER_KIB).min(u64::MAX as u128) as u64
    }
}

/// One owner's rollup across every batch it pushed under. The account is
/// what settlement and cashout are keyed on (§6, §9.3), while credit is
/// keyed per batch — so the report needs both views of the same rows.
#[derive(Default, Clone, Copy)]
struct OwnerTotals {
    kib: u64,
    kib_dedup: u64,
    frames: u64,
    batches: u64,
}

impl OwnerTotals {
    fn owed_plur(&self) -> u128 {
        self.kib.saturating_sub(self.kib_dedup) as u128 * PRICE_PLUR_PER_KIB
    }
}

/// Per-request staging buffer. A POST touches at most
/// `PUSH_MAX_BATCH_LOOKUPS` distinct batches, so a linear scan beats a
/// `HashMap` and allocates nothing in the common single-batch case.
#[derive(Default)]
pub struct PostTally {
    rows: Vec<TallyRow>,
}

struct TallyRow {
    key: AccountBatch,
    remaining_value_plur: u128,
    bytes_admitted: u64,
    bytes_dedup: u64,
    frames: u64,
    dedup_frames: u64,
}

impl PostTally {
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    fn slot(&mut self, key: AccountBatch, remaining_value_plur: u128) -> &mut TallyRow {
        if let Some(i) = self.rows.iter().position(|r| r.key == key) {
            // A later frame may carry a value the first one lacked; never
            // let a zero overwrite a real reading.
            if self.rows[i].remaining_value_plur == 0 {
                self.rows[i].remaining_value_plur = remaining_value_plur;
            }
            return &mut self.rows[i];
        }
        self.rows.push(TallyRow {
            key,
            remaining_value_plur,
            bytes_admitted: 0,
            bytes_dedup: 0,
            frames: 0,
            dedup_frames: 0,
        });
        self.rows.last_mut().expect("just pushed")
    }

    /// A frame that passed stamp validation and owner resolution. `bytes` is
    /// the body it occupied — header plus wire — which is what §8 bills.
    pub fn admit(&mut self, key: AccountBatch, remaining_value_plur: u128, bytes: u64) {
        let row = self.slot(key, remaining_value_plur);
        row.bytes_admitted += bytes;
        row.frames += 1;
    }

    /// An admitted frame that the recent-ack cache answered. Counted in
    /// `admit` as well — this records the portion billed at zero (§8.2).
    pub fn dedup(&mut self, key: AccountBatch, remaining_value_plur: u128, bytes: u64) {
        let row = self.slot(key, remaining_value_plur);
        row.bytes_dedup += bytes;
        row.dedup_frames += 1;
    }
}

/// Bounded shadow ledger over `(owner, batch)`.
pub struct Meter {
    rows: HashMap<AccountBatch, Row>,
    order: VecDeque<AccountBatch>,
    cap: usize,
    started: Instant,
    /// Totals that survive eviction, so the headline figures stay honest
    /// even once detail rows are dropped.
    evicted_rows: u64,
    evicted_kib: u64,
    evicted_kib_dedup: u64,
    evicted_frames: u64,
}

impl Default for Meter {
    fn default() -> Self {
        Self::new(METER_ROW_CAP)
    }
}

impl Meter {
    pub fn new(cap: usize) -> Self {
        Self {
            rows: HashMap::new(),
            order: VecDeque::new(),
            cap: cap.max(1),
            started: Instant::now(),
            evicted_rows: 0,
            evicted_kib: 0,
            evicted_kib_dedup: 0,
            evicted_frames: 0,
        }
    }

    /// Fold one request's tally in. Bytes become KiB here, once per
    /// `(POST, batch)` — which is how a metered relay would round, since it
    /// bills a whole body against one `Content-Length` (§8).
    pub fn merge(&mut self, tally: PostTally) {
        let now = Instant::now();
        for t in tally.rows {
            let kib = t.bytes_admitted.div_ceil(1024);
            let kib_dedup = t.bytes_dedup.div_ceil(1024).min(kib);
            match self.rows.get_mut(&t.key) {
                Some(row) => {
                    row.kib_admitted += kib;
                    row.kib_dedup += kib_dedup;
                    row.frames += t.frames;
                    row.dedup_frames += t.dedup_frames;
                    if t.remaining_value_plur > 0 {
                        // Latest reading wins: the line decays as the batch
                        // is spent down, and the decay is the point (§10.3).
                        row.remaining_value_plur = t.remaining_value_plur;
                    }
                    row.last_seen = now;
                }
                None => {
                    self.rows.insert(
                        t.key,
                        Row {
                            kib_admitted: kib,
                            kib_dedup,
                            frames: t.frames,
                            dedup_frames: t.dedup_frames,
                            remaining_value_plur: t.remaining_value_plur,
                            first_seen: now,
                            last_seen: now,
                        },
                    );
                    self.order.push_back(t.key);
                }
            }
        }
        while self.order.len() > self.cap {
            let Some(old) = self.order.pop_front() else {
                break;
            };
            if let Some(row) = self.rows.remove(&old) {
                self.evicted_rows += 1;
                self.evicted_kib += row.kib_admitted;
                self.evicted_kib_dedup += row.kib_dedup;
                self.evicted_frames += row.frames;
            }
        }
    }

    fn window_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    fn by_owner(&self) -> HashMap<[u8; 20], OwnerTotals> {
        let mut out: HashMap<[u8; 20], OwnerTotals> = HashMap::new();
        for (k, r) in &self.rows {
            let e = out.entry(k.owner).or_default();
            e.kib += r.kib_admitted;
            e.kib_dedup += r.kib_dedup;
            e.frames += r.frames;
            e.batches += 1;
        }
        out
    }

    /// Headline figures. Names no account, so it is safe on the public
    /// `/v1/status` — total volume is already published there as
    /// `bytes_pushed`.
    ///
    /// `full_post_kib` is the body of a maximal POST, and `attempts` the sum
    /// of the per-stream push outcome counters (§9.1).
    pub fn summary(&self, full_post_kib: u64, attempts: u64) -> serde_json::Value {
        let live_kib: u64 = self.rows.values().map(|r| r.kib_admitted).sum();
        let live_dedup: u64 = self.rows.values().map(|r| r.kib_dedup).sum();
        let live_frames: u64 = self.rows.values().map(|r| r.frames).sum();
        let kib = live_kib + self.evicted_kib;
        let dedup = live_kib.min(live_dedup) + self.evicted_kib_dedup;
        let frames = live_frames + self.evicted_frames;
        let billable = kib.saturating_sub(dedup);
        let owed = billable as u128 * PRICE_PLUR_PER_KIB;

        let owners = self.by_owner();
        let would_settle = owners
            .values()
            .filter(|t| t.owed_plur() >= SETTLE_EVERY_PLUR)
            .count();
        let would_cash = owners
            .values()
            .filter(|t| t.owed_plur() >= CASHOUT_THRESHOLD_PLUR)
            .count();

        json!({
            "window_secs": self.window_secs(),
            "price_plur_per_kib": PRICE_PLUR_PER_KIB.to_string(),
            "accounts": owners.len(),
            "batches": self.rows.len(),
            "evicted_batches": self.evicted_rows,
            "kib_admitted": kib,
            "kib_dedup": dedup,
            "frames_admitted": frames,
            "owed_plur": owed.to_string(),
            "owed_usd": plur_to_usd(owed),
            // The two questions §9.3 turns on: how many accounts reach one
            // settlement at all, and how many ever repay their cashout gas.
            "accounts_reaching_settlement": would_settle,
            "accounts_reaching_cashout": would_cash,
            "egress": egress(frames, billable, attempts),
            "credit": self.credit_summary(full_post_kib),
        })
    }

    /// §10.3's calibration: what credit line every observed batch would get.
    fn credit_summary(&self, full_post_kib: u64) -> serde_json::Value {
        let mut lines: Vec<u64> = self
            .rows
            .values()
            .filter(|r| r.remaining_value_plur > 0)
            .map(Row::credit_kib)
            .collect();
        if lines.is_empty() {
            return json!({"batches_priced": 0});
        }
        lines.sort_unstable();
        let below_post = lines.iter().filter(|&&c| c < full_post_kib).count();
        let capped = self
            .rows
            .values()
            .filter(|r| r.remaining_value_plur > 0)
            .filter(|r| r.remaining_value_plur / CREDIT_RATIO < MAX_OUTSTANDING_PLUR)
            .count();
        json!({
            "batches_priced": lines.len(),
            "credit_ratio": CREDIT_RATIO,
            "full_post_kib": full_post_kib,
            // A batch here must split its uploads across smaller POSTs
            // (§7.2). Fine individually; a high fraction means the ratio is
            // mis-set.
            "batches_below_one_full_post": below_post,
            // Below the global ceiling, i.e. the per-batch line binds.
            "batches_capped_below_ceiling": capped,
            "credit_kib_p10": pct(&lines, 10),
            "credit_kib_p50": pct(&lines, 50),
            "credit_kib_p90": pct(&lines, 90),
        })
    }

    /// Per-account and per-batch detail. **Operator-only** — this is a
    /// volume oracle over on-chain-enumerable batch owners, which is exactly
    /// why §7 authenticates `/v1/account`.
    pub fn detail(&self, full_post_kib: u64, attempts: u64, top: usize) -> serde_json::Value {
        let mut owners: Vec<([u8; 20], OwnerTotals)> = self.by_owner().into_iter().collect();
        owners.sort_by(|a, b| b.1.kib.cmp(&a.1.kib).then(a.0.cmp(&b.0)));
        let accounts: Vec<serde_json::Value> = owners
            .iter()
            .take(top)
            .map(|(owner, t)| {
                let owed = t.owed_plur();
                json!({
                    "account": format!("0x{}", hex::encode(owner)),
                    "batches": t.batches,
                    "kib_admitted": t.kib,
                    "kib_dedup": t.kib_dedup,
                    "frames": t.frames,
                    "owed_plur": owed.to_string(),
                    "owed_usd": plur_to_usd(owed),
                    "settlements": (owed / SETTLE_EVERY_PLUR) as u64,
                    "reaches_cashout": owed >= CASHOUT_THRESHOLD_PLUR,
                })
            })
            .collect();

        let mut rows: Vec<(&AccountBatch, &Row)> = self.rows.iter().collect();
        rows.sort_by(|a, b| b.1.kib_admitted.cmp(&a.1.kib_admitted).then(a.0.cmp(b.0)));
        let batches: Vec<serde_json::Value> = rows
            .iter()
            .take(top)
            .map(|(k, r)| {
                let credit_kib = r.credit_kib();
                json!({
                    "account": format!("0x{}", hex::encode(k.owner)),
                    "batch": format!("0x{}", hex::encode(k.batch)),
                    "kib_admitted": r.kib_admitted,
                    "kib_dedup": r.kib_dedup,
                    "frames": r.frames,
                    "dedup_frames": r.dedup_frames,
                    "remaining_value_plur": r.remaining_value_plur.to_string(),
                    "credit_plur": r.credit_plur().to_string(),
                    "credit_kib": credit_kib,
                    "fits_full_post": credit_kib >= full_post_kib,
                    "billable_kib": r.billable_kib(),
                    "age_secs": r.first_seen.elapsed().as_secs(),
                    "idle_secs": r.last_seen.elapsed().as_secs(),
                })
            })
            .collect();

        json!({
            "summary": self.summary(full_post_kib, attempts),
            "accounts": accounts,
            "batches": batches,
            "truncated_to": top,
        })
    }
}

/// §9.1's cost basis. The doc's model is ×3 peer race × 1.15 shallow
/// retries ≈ 3.45 stream attempts per chunk.
///
/// `attempts` counts *completed* outcomes, so this is a lower bound rather
/// than the observation §9.2 needs — cancelled racers are missing. Do not
/// reprice on it until the counter moves to dispatch.
fn egress(frames: u64, billable_kib: u64, attempts: u64) -> serde_json::Value {
    if frames == 0 {
        return json!({"frames": 0, "stream_attempts": attempts});
    }
    let per = attempts as f64 / frames as f64;
    let mut out = json!({
        "frames": frames,
        "stream_attempts": attempts,
        // The measured number. Everything below is derived from it.
        "attempts_per_frame": round3(per),
        "modelled_attempts_per_frame": 3.45,
    });
    if billable_kib > 0 {
        // Each Delivery is ~4.4 KiB on the wire for a 4 KiB chunk (§9.1:
        // addr + stamp + span/data, plus ~5 % protobuf/yamux/noise/TCP).
        // Denominated in *billable* payload, since a dedup hit generates no
        // attempts and would otherwise dilute the ratio. The doc models 3.7.
        let ratio = attempts as f64 * 4.4 / billable_kib as f64;
        out["egress_ratio_estimate"] = json!(round3(ratio));
        out["modelled_egress_ratio"] = json!(3.7);
    }
    out
}

fn pct(sorted: &[u64], p: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let i = (sorted.len() * p / 100).min(sorted.len() - 1);
    sorted[i]
}

fn plur_to_usd(plur: u128) -> f64 {
    round6(plur as f64 / PLUR_PER_BZZ * USD_PER_BZZ)
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

fn round6(v: f64) -> f64 {
    (v * 1e6).round() / 1e6
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(owner: u8, batch: u8) -> AccountBatch {
        AccountBatch {
            owner: [owner; 20],
            batch: [batch; 32],
        }
    }

    /// One full frame: 147 B header + 4104 B wire (`src/pushframe.rs`).
    const FRAME: u64 = 4251;

    #[test]
    fn bytes_round_to_kib_once_per_post_not_once_per_frame() {
        // Per-frame rounding would charge 5 KiB for a 4.15 KiB frame — a
        // 20 % over-count that would have made every figure in the report
        // wrong in the relay's favour.
        let mut m = Meter::default();
        let mut t = PostTally::default();
        for _ in 0..100 {
            t.admit(key(1, 1), 0, FRAME);
        }
        m.merge(t);
        let want = (FRAME * 100).div_ceil(1024);
        assert_eq!(want, 416, "100 frames is 415.14 KiB, ceil 416");
        let s = m.summary(2126, 0);
        assert_eq!(s["kib_admitted"], want);
    }

    #[test]
    fn dedup_is_recorded_but_not_double_counted_as_volume() {
        let mut m = Meter::default();
        let mut t = PostTally::default();
        // Ten frames admitted, three of them cache hits: dedup is a subset
        // of admitted, never an addition to it (§8.2).
        for _ in 0..10 {
            t.admit(key(1, 1), 0, FRAME);
        }
        for _ in 0..3 {
            t.dedup(key(1, 1), 0, FRAME);
        }
        m.merge(t);
        let s = m.summary(2126, 0);
        assert_eq!(s["kib_admitted"], (FRAME * 10).div_ceil(1024));
        assert_eq!(s["kib_dedup"], (FRAME * 3).div_ceil(1024));
        let billable =
            s["kib_admitted"].as_u64().expect("u64") - s["kib_dedup"].as_u64().expect("u64");
        assert_eq!(
            s["owed_plur"].as_str().expect("string"),
            (billable as u128 * PRICE_PLUR_PER_KIB).to_string()
        );
    }

    #[test]
    fn credit_line_follows_batch_value_and_caps_at_the_ceiling() {
        let mut m = Meter::default();
        let mut t = PostTally::default();
        // 0.01 BZZ = 1e14 PLUR → 1e11 credit → ~208 KiB (§10.3's worked
        // example). Must not saturate the global ceiling.
        t.admit(key(1, 1), 100_000_000_000_000, FRAME);
        // 100 BZZ is far past the ceiling, so the line clamps.
        t.admit(key(2, 2), 1_000_000_000_000_000_000, FRAME);
        m.merge(t);
        let d = m.detail(2126, 0, 10);
        let by_batch: HashMap<String, serde_json::Value> = d["batches"]
            .as_array()
            .expect("array")
            .iter()
            .map(|b| (b["account"].as_str().expect("acct").to_string(), b.clone()))
            .collect();
        let dust = &by_batch[&format!("0x{}", hex::encode([1u8; 20]))];
        assert_eq!(dust["credit_kib"], 208, "0.01 BZZ batch earns ~208 KiB");
        assert_eq!(dust["fits_full_post"], false, "dust must split its POSTs");
        let rich = &by_batch[&format!("0x{}", hex::encode([2u8; 20]))];
        assert_eq!(
            rich["credit_plur"].as_str().expect("string"),
            MAX_OUTSTANDING_PLUR.to_string(),
            "a rich batch clamps to the global ceiling"
        );
        assert_eq!(rich["fits_full_post"], true);
    }

    #[test]
    fn eviction_is_bounded_and_totals_survive_it() {
        let mut m = Meter::new(4);
        for i in 0..64u8 {
            let mut t = PostTally::default();
            t.admit(key(i, i), 0, 1024);
            m.merge(t);
        }
        assert_eq!(m.rows.len(), 4, "rows stay at cap");
        assert_eq!(m.order.len(), 4, "order stays at cap");
        // The whole point of carrying evicted totals: the headline volume
        // must not silently shrink as detail rows are dropped.
        let s = m.summary(2126, 0);
        assert_eq!(s["kib_admitted"], 64, "all 64 KiB still counted");
        assert_eq!(s["evicted_batches"], 60);
    }

    #[test]
    fn a_later_reading_updates_the_batch_value_but_zero_never_clobbers_it() {
        let mut m = Meter::default();
        let mut t = PostTally::default();
        t.admit(key(1, 1), 0, FRAME); // resolved without a value
        t.admit(key(1, 1), 100_000_000_000_000, FRAME); // then with one
        m.merge(t);
        let mut t2 = PostTally::default();
        t2.admit(key(1, 1), 0, FRAME); // a valueless frame must not erase it
        m.merge(t2);
        let d = m.detail(2126, 0, 10);
        assert_eq!(
            d["batches"][0]["remaining_value_plur"]
                .as_str()
                .expect("string"),
            "100000000000000"
        );
    }

    #[test]
    fn egress_multiplier_is_attempts_over_frames() {
        let mut m = Meter::default();
        let mut t = PostTally::default();
        for _ in 0..100 {
            t.admit(key(1, 1), 0, FRAME);
        }
        m.merge(t);
        // 345 stream attempts for 100 chunks is the doc's modelled 3.45.
        let s = m.summary(2126, 345);
        assert_eq!(s["egress"]["attempts_per_frame"], 3.45);
        // …which lands within a whisker of §9.1's modelled 3.7 GiB of real
        // egress per GiB of payload. If a live relay reports something far
        // from this, §9.2's price is wrong.
        let ratio = s["egress"]["egress_ratio_estimate"].as_f64().expect("f64");
        assert!(
            (3.6..3.8).contains(&ratio),
            "modelled attempts should reproduce the modelled ratio, got {ratio}"
        );
    }

    #[test]
    fn cashout_and_settlement_thresholds_classify_accounts() {
        let mut m = Meter::default();
        // 5 GiB is the cashout threshold (§9.3); 32 MiB is one settlement.
        let five_gib_kib = 5 * 1024 * 1024;
        let mut t = PostTally::default();
        t.admit(key(9, 9), 0, five_gib_kib * 1024);
        t.admit(key(3, 3), 0, 40 * 1024 * 1024); // ~40 MiB, one settlement
        t.admit(key(4, 4), 0, 1024 * 1024); // 1 MiB, neither
        m.merge(t);
        let s = m.summary(2126, 0);
        assert_eq!(s["accounts_reaching_cashout"], 1);
        assert_eq!(s["accounts_reaching_settlement"], 2);
    }
}

/// ~8 MiB — the dust floor. Exists only to bound RPC cost per unit of
/// value (§11.6 lists up to 4 `eth_call`s per cheque), *not* to cover
/// cashout gas, which cumulative cheques amortize separately (§8.3).
pub const MIN_CHEQUE_PLUR: u128 = 3_900_000_000_000;

/// Metered-mode parameters, quoted in `/v1/status` and enforced at
/// admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    pub price_plur_per_kib: u128,
    pub min_cheque_plur: u128,
    pub settle_every_plur: u128,
    pub max_outstanding_plur: u128,
    pub credit_ratio: u128,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            price_plur_per_kib: PRICE_PLUR_PER_KIB,
            min_cheque_plur: MIN_CHEQUE_PLUR,
            settle_every_plur: SETTLE_EVERY_PLUR,
            max_outstanding_plur: MAX_OUTSTANDING_PLUR,
            credit_ratio: CREDIT_RATIO,
        }
    }
}

impl Params {
    /// §10.1's invariant, checked at startup so a misconfigured relay
    /// refuses to boot rather than bricking every account it serves.
    ///
    /// Violating it is not a tuning mistake, it is a deadlock: an account
    /// accrues, crosses `settle_every`, signs a cheque, has it **rejected as
    /// dust**, keeps accruing, hits its cap, and the only cheque that would
    /// clear the 402 is larger than what it owes — which the no-prepayment
    /// rule forbids. There is no exit.
    pub fn validate(&self) -> Result<(), String> {
        if self.price_plur_per_kib == 0 {
            return Err("price_plur_per_kib must be non-zero".into());
        }
        if self.credit_ratio == 0 {
            return Err("credit_ratio must be non-zero".into());
        }
        if self.min_cheque_plur > self.settle_every_plur {
            return Err(format!(
                "min_cheque_plur ({}) exceeds settle_every_plur ({}): every account \
                 would accrue past settlement and have its cheque refused as dust, \
                 with no cheque able to clear the resulting 402 (§10.1)",
                self.min_cheque_plur, self.settle_every_plur
            ));
        }
        if self.settle_every_plur >= self.max_outstanding_plur {
            return Err(format!(
                "settle_every_plur ({}) must be below max_outstanding_plur ({}): \
                 otherwise an account hits its cap before it is ever asked to pay (§10.1)",
                self.settle_every_plur, self.max_outstanding_plur
            ));
        }
        Ok(())
    }

    /// §10.3: scale the credit line to the batch's on-chain value rather
    /// than asserting a constant, so the Sybil margin is `credit_ratio` by
    /// construction and independent of batch size.
    pub fn credit_line(&self, remaining_value_plur: u128) -> u128 {
        (remaining_value_plur / self.credit_ratio).min(self.max_outstanding_plur)
    }

    /// What a body of `bytes` costs. Rounds up to KiB **once**, per §8 —
    /// rounding per frame would over-count a 4 251-byte frame by 20 %.
    pub fn price_bytes(&self, bytes: u64) -> u128 {
        u128::from(bytes.div_ceil(1024)) * self.price_plur_per_kib
    }

    /// The settlement thresholds that actually apply to an account whose
    /// credit line is `cap`.
    ///
    /// `validate` checks §10.1's invariant against `max_outstanding_plur`,
    /// but that is only the *ceiling* on a credit line — the line that
    /// binds is per batch, `min(remaining_value / credit_ratio, ceiling)`
    /// (§10.3). For any batch smaller than
    /// `min_cheque_plur * credit_ratio` the configured floor sits *above*
    /// everything that account can ever owe, and the invariant quietly
    /// stops holding: it accrues to its cap, is refused, and cannot write
    /// a cheque large enough to be accepted. Service stops permanently,
    /// for a batch that is paid up and behaving.
    ///
    /// Observed live with the shipped defaults: a credit line of
    /// 679,783,122,862 against a 3,900,000,000,000 floor — 5.7× short —
    /// which is §10.3's small batch, the case the scaled line exists to
    /// keep serving.
    ///
    /// Both sides derive this from `(params, cap)` and `cap` is already in
    /// the challenge, so the two agree without exchanging anything new.
    /// Settling at half the line leaves the other half as the working
    /// headroom a POST is dispatched into.
    pub fn effective(&self, cap: u128) -> EffectiveParams {
        // Floor at 1: for a degenerate line (cap < 2) `cap / 2` is 0, which
        // would make every cheque acceptable including 0-value ones — dust
        // protection off exactly when the batch is most worthless. The
        // account can still exit (settle_every=1 is immediately crossed).
        let settle_every = self.settle_every_plur.min(cap / 2).max(1);
        EffectiveParams {
            // Preserves `min_cheque <= settle_every` — the half of §10.1
            // that makes a 402 clearable — at any credit line.
            min_cheque_plur: self.min_cheque_plur.min(settle_every).max(1),
            settle_every_plur: settle_every,
        }
    }
}

/// §10.1's thresholds resolved against a particular credit line. See
/// [`Params::effective`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveParams {
    pub min_cheque_plur: u128,
    pub settle_every_plur: u128,
}

#[cfg(test)]
mod param_tests {
    use super::*;

    /// §10.1's invariant is checked against `max_outstanding_plur`, but the
    /// line that binds is per batch. A small batch gets a line far under
    /// the configured floor, and then no cheque it can write is acceptable
    /// — it accrues to its cap and is refused for good. Seen live at a
    /// 679,783,122,862 line against a 3,900,000,000,000 floor.
    #[test]
    fn a_credit_line_below_the_dust_floor_can_still_settle() {
        let p = Params::default();
        let line = 679_783_122_862u128;
        assert!(
            line < p.min_cheque_plur,
            "this is the case: the whole line is under the configured floor"
        );

        let e = p.effective(line);
        assert!(
            e.min_cheque_plur <= e.settle_every_plur,
            "a 402 must be clearable by the cheque the client is told to write"
        );
        assert!(
            e.settle_every_plur < line,
            "and settlement must trigger before the line is full, or the \
             account is refused before it is ever asked to pay"
        );
        assert!(e.min_cheque_plur > 0, "some cheque must be acceptable");
    }

    /// A line with room to spare must keep the configured thresholds —
    /// scaling down is for the batches that need it, not a general discount.
    #[test]
    fn a_generous_credit_line_keeps_the_configured_thresholds() {
        let p = Params::default();
        let e = p.effective(p.max_outstanding_plur);
        assert_eq!(e.min_cheque_plur, p.min_cheque_plur);
        assert_eq!(e.settle_every_plur, p.settle_every_plur);
    }

    #[test]
    fn the_shipped_defaults_satisfy_the_invariant() {
        Params::default()
            .validate()
            .expect("defaults must be valid");
    }

    /// The exact misconfiguration an early draft published: a dust floor 87×
    /// larger than the settlement window.
    #[test]
    fn a_dust_floor_above_the_settlement_window_is_refused_at_startup() {
        let p = Params {
            min_cheque_plur: SETTLE_EVERY_PLUR * 87,
            ..Params::default()
        };
        let e = p.validate().expect_err("must refuse to boot");
        assert!(e.contains("no exit") || e.contains("dust"), "got: {e}");
    }

    #[test]
    fn a_cap_at_or_below_the_settlement_window_is_refused() {
        let p = Params {
            max_outstanding_plur: SETTLE_EVERY_PLUR,
            ..Params::default()
        };
        p.validate()
            .expect_err("cap must exceed the settlement window");
    }

    #[test]
    fn zero_price_or_ratio_is_refused() {
        Params {
            price_plur_per_kib: 0,
            ..Params::default()
        }
        .validate()
        .expect_err("zero price");
        Params {
            credit_ratio: 0,
            ..Params::default()
        }
        .validate()
        .expect_err("zero ratio would divide by zero");
    }

    /// §10.3's worked example, and the §7.2 consequence: a dust batch gets a
    /// usable line that is nonetheless too small for one full POST.
    #[test]
    fn a_dust_batch_gets_a_small_but_usable_line() {
        let p = Params::default();
        let line = p.credit_line(100_000_000_000_000); // 0.01 BZZ
        assert_eq!(line / p.price_plur_per_kib, 208, "~208 KiB of credit");
        assert!(line < p.max_outstanding_plur, "must not reach the ceiling");
    }

    #[test]
    fn a_rich_batch_clamps_to_the_global_ceiling() {
        let p = Params::default();
        assert_eq!(
            p.credit_line(u128::MAX / 2),
            p.max_outstanding_plur,
            "the ceiling binds however rich the batch"
        );
    }

    #[test]
    fn a_body_is_priced_by_rounding_up_once() {
        let p = Params::default();
        assert_eq!(
            p.price_bytes(1),
            p.price_plur_per_kib,
            "a partial KiB is a KiB"
        );
        assert_eq!(p.price_bytes(1024), p.price_plur_per_kib);
        assert_eq!(p.price_bytes(1025), 2 * p.price_plur_per_kib);
        // One full frame, priced once rather than per-frame.
        assert_eq!(p.price_bytes(4251), 5 * p.price_plur_per_kib);
    }
}
