//! Inbound per-key rate limiting — `docs/pusher-incentives.md` §11.6.
//!
//! **`src/ratelimit.rs` cannot be reused for this.** That one is a per-peer
//! *outbound libp2p dial* GCRA pacer that **parks** the caller until its
//! slot comes up; it has no inbound, per-account or HTTP concept. Parking
//! is exactly wrong here — an attacker that can make the relay hold a task
//! per request has turned a rate limiter into a memory amplifier. This one
//! refuses immediately.
//!
//! Used on `/v1/challenge` (per IP — no account exists yet), `/v1/pay` (per
//! account) and `/v1/push` (per account).
//!
//! ## Eviction is fail-closed, and that is the whole design
//!
//! The bucket map is keyed by something the caller influences, so it has to
//! be bounded. But naive eviction *is* the bypass: if an attacker can push
//! its own throttled bucket out of the map, the next request re-creates it
//! with a full budget and the limit never binds.
//!
//! So only buckets that have nothing to lose are evictable — ones refilled
//! to full, which is indistinguishable from never having existed. When the
//! map is at capacity and every bucket is *still throttled*, new keys are
//! **refused** rather than admitted. Under attack the relay gets stricter,
//! not more permissive.

use std::collections::HashMap;
use std::time::Instant;

pub struct InboundLimiter {
    buckets: HashMap<Vec<u8>, Bucket>,
    cap: usize,
    /// Sustained requests per second.
    rate: f64,
    /// Maximum burst, in requests.
    burst: f64,
}

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn refill(&mut self, now: Instant, rate: f64, burst: f64) {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + dt * rate).min(burst);
        self.last = now;
    }

    /// Nothing to lose by dropping it: a fresh bucket is identical.
    fn is_full(&self, burst: f64) -> bool {
        self.tokens >= burst
    }
}

impl InboundLimiter {
    pub fn new(rate_per_sec: f64, burst: f64, cap: usize) -> Self {
        Self {
            buckets: HashMap::new(),
            cap: cap.max(1),
            rate: rate_per_sec.max(f64::MIN_POSITIVE),
            burst: burst.max(1.0),
        }
    }

    pub fn allow(&mut self, key: &[u8]) -> bool {
        self.allow_at(key, Instant::now())
    }

    pub fn allow_at(&mut self, key: &[u8], now: Instant) -> bool {
        let (rate, burst) = (self.rate, self.burst);
        if let Some(b) = self.buckets.get_mut(key) {
            b.refill(now, rate, burst);
            if b.tokens < 1.0 {
                return false;
            }
            b.tokens -= 1.0;
            return true;
        }
        if self.buckets.len() >= self.cap {
            self.sweep(now);
            if self.buckets.len() >= self.cap {
                // Every bucket is still throttled and we are full. Admitting
                // this one would mean an attacker with enough distinct keys
                // can mint budget on demand; refusing costs a stranger one
                // request during an active flood.
                return false;
            }
        }
        self.buckets.insert(
            key.to_vec(),
            Bucket {
                tokens: burst - 1.0,
                last: now,
            },
        );
        true
    }

    /// Drop only buckets that have refilled to full.
    fn sweep(&mut self, now: Instant) {
        let (rate, burst) = (self.rate, self.burst);
        self.buckets.retain(|_, b| {
            b.refill(now, rate, burst);
            !b.is_full(burst)
        });
    }

    pub fn tracked(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_burst_is_allowed_then_the_rate_binds() {
        let mut l = InboundLimiter::new(1.0, 5.0, 128);
        let t0 = Instant::now();
        for i in 0..5 {
            assert!(l.allow_at(b"a", t0), "burst request {i} must pass");
        }
        assert!(
            !l.allow_at(b"a", t0),
            "the 6th in the same instant must not"
        );
    }

    #[test]
    fn tokens_refill_over_time() {
        let mut l = InboundLimiter::new(2.0, 2.0, 128);
        let t0 = Instant::now();
        assert!(l.allow_at(b"a", t0));
        assert!(l.allow_at(b"a", t0));
        assert!(!l.allow_at(b"a", t0));
        assert!(
            l.allow_at(b"a", t0 + Duration::from_millis(500)),
            "half a second at 2/s is one token"
        );
    }

    #[test]
    fn keys_are_independent() {
        let mut l = InboundLimiter::new(1.0, 1.0, 128);
        let t0 = Instant::now();
        assert!(l.allow_at(b"a", t0));
        assert!(!l.allow_at(b"a", t0));
        assert!(
            l.allow_at(b"b", t0),
            "one key's flood must not throttle another"
        );
    }

    /// The bypass this design exists to close: an attacker cycling keys must
    /// not be able to evict its own throttled bucket and come back fresh.
    #[test]
    fn a_throttled_bucket_cannot_be_evicted_by_flooding_new_keys() {
        let mut l = InboundLimiter::new(0.001, 1.0, 4);
        let t0 = Instant::now();
        assert!(l.allow_at(b"victim", t0));
        assert!(!l.allow_at(b"victim", t0), "victim is now throttled");
        // Flood distinct keys to try to push `victim` out.
        for i in 0..200u32 {
            l.allow_at(format!("k{i}").as_bytes(), t0);
        }
        assert!(
            !l.allow_at(b"victim", t0),
            "the throttled bucket must have survived the flood"
        );
        assert!(l.tracked() <= 4, "map stays bounded, got {}", l.tracked());
    }

    /// Fail-closed: when the map is full of throttled buckets, a new key is
    /// refused rather than admitted.
    #[test]
    fn a_full_map_of_throttled_buckets_refuses_new_keys() {
        let mut l = InboundLimiter::new(0.001, 1.0, 2);
        let t0 = Instant::now();
        assert!(l.allow_at(b"a", t0));
        assert!(l.allow_at(b"b", t0));
        assert!(
            !l.allow_at(b"c", t0),
            "must refuse rather than evict a live limit"
        );
    }

    /// …but a bucket that has refilled to full is free to drop, so the map
    /// recovers once the flood stops.
    #[test]
    fn full_buckets_are_reclaimed_so_the_map_recovers() {
        let mut l = InboundLimiter::new(10.0, 1.0, 2);
        let t0 = Instant::now();
        assert!(l.allow_at(b"a", t0));
        assert!(l.allow_at(b"b", t0));
        let later = t0 + Duration::from_secs(60);
        assert!(
            l.allow_at(b"c", later),
            "once a and b are refilled they carry no state worth keeping"
        );
    }
}
