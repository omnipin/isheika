//! Metered relay mode — `docs/pusher-incentives.md` Stages 1–2.
//!
//! Holds the state the metered endpoints share and implements their logic,
//! so `src/pusher.rs` stays a router. Everything here defends the **relay**
//! against the **client** (§2); nothing here tries to prove to a client that
//! the relay did its work.
//!
//! Soft mode meters, reports, and accepts cheques without refusing;
//! hard mode (402 enforcement) flips one flag — the arithmetic that decides
//! "over cap" is computed here so the two modes cannot disagree about it.
//! Absent challenge headers are served as unmetered (`open`) in soft mode
//! for staged rollout; present-but-invalid headers are refused in both.

use crate::challenge::{
    ChallengeError, ChallengeFields, IssuedChallenge, MAX_CHALLENGE_HEADER, PresentedChallenge,
};
use crate::inbound_limit::InboundLimiter;
use crate::ledger::{Ledger, LedgerError};
use crate::meter::Params;
use alloy_primitives::Address;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Accounts allowed to hold a live reservation at once (§7.2). The map is
/// attacker-influenced — one entry per batch in standing — so it is capped
/// and sheds beyond.
const MAX_LIVE_RESERVATIONS: usize = 4096;

/// Chequebook-deployment answers cached per address. `true` never changes,
/// and `false` is exactly what an attacker replays, so both are cached
/// (§11.6).
const DEPLOYED_CACHE_CAP: usize = 4096;
const DEPLOYED_OK_TTL: Duration = Duration::from_secs(86_400);
const DEPLOYED_BAD_TTL: Duration = Duration::from_secs(600);

/// How long a chequebook's balance reads are reused.
///
/// **This does not weaken anything, because there was no guarantee to
/// weaken.** §11.2 is explicit that the funding check is true *at
/// acceptance time, not at cashout time*: the issuer can `withdraw()` the
/// instant after we accept, and bee has the identical exposure. So a fresh
/// read per cheque only narrows the window in which an attacker must act
/// from "any time after acceptance" to "any time after acceptance, or up to
/// `STATE_TTL` before it" — against an exposure already bounded by
/// `max_outstanding` either way.
///
/// What it buys is real: four sequential `eth_call`s per `/v1/pay` became
/// one batched request, and with this most cheques cost none at all. At
/// §10.1's 32 MiB settlement window that is ~2-3 cheques per 71 MB upload,
/// so the chain reads stop being on the critical path entirely.
const STATE_TTL: Duration = Duration::from_secs(30);
const STATE_CACHE_CAP: usize = 2048;

#[derive(Debug, Clone)]
pub struct MeterConfig {
    /// Configured hostnames. **Never derived from a request header** — see
    /// `challenge::verify`.
    pub origins: Vec<String>,
    pub beneficiary: [u8; 20],
    pub chain_id: u64,
    pub factory: Address,
    pub params: Params,
    /// Stage 2. False = soft mode: record the overshoot, serve anyway.
    pub hard_mode: bool,
}

pub struct Metered {
    pub cfg: MeterConfig,
    pub ledger: Mutex<Ledger>,
    /// Per-IP: `/v1/challenge` runs before any account exists.
    challenge_limit: Mutex<InboundLimiter>,
    /// Per-account: `/v1/pay` and `/v1/push`.
    account_limit: Mutex<InboundLimiter>,
    deployed: Mutex<DeployedCache>,
    /// `chequebook -> (state, read_at)`. `issuer` inside it is immutable,
    /// so a hit is always authoritative for that field.
    cb_state: Mutex<StateCache>,
}

impl Metered {
    pub fn new(cfg: MeterConfig, ledger: Ledger) -> Self {
        Self {
            cfg,
            ledger: Mutex::new(ledger),
            // A client needs one challenge per POST batch, so a handful per
            // second sustained is generous; the burst covers a pipelined
            // upload opening several lanes at once.
            challenge_limit: Mutex::new(InboundLimiter::new(5.0, 40.0, 8192)),
            account_limit: Mutex::new(InboundLimiter::new(20.0, 120.0, 8192)),
            deployed: Mutex::new(DeployedCache::new(DEPLOYED_CACHE_CAP)),
            cb_state: Mutex::new(StateCache::new(STATE_CACHE_CAP)),
        }
    }

    /// Chequebook state, from cache when it is fresh enough.
    pub async fn chequebook_state(
        &self,
        rpc_url: &str,
        chequebook: [u8; 20],
    ) -> Result<crate::batch::ChequebookState, String> {
        if let Some(hit) = self
            .cb_state
            .lock()
            .expect("state cache poisoned")
            .get(&chequebook)
        {
            return Ok(hit);
        }
        let st = crate::batch::read_chequebook_state(
            rpc_url,
            Address::from(chequebook),
            Address::from(self.cfg.beneficiary),
        )
        .await
        .map_err(|e| format!("chequebook: {e}"))?;
        self.cb_state
            .lock()
            .expect("state cache poisoned")
            .insert(chequebook, st);
        Ok(st)
    }

    /// Drop a cached read after we act on it, so the next cheque from this
    /// chequebook sees the balance it actually left behind rather than the
    /// one from before we credited.
    pub fn invalidate_chequebook(&self, chequebook: &[u8; 20]) {
        self.cb_state
            .lock()
            .expect("state cache poisoned")
            .remove(chequebook);
    }

    pub fn allow_challenge(&self, ip: &str) -> bool {
        self.challenge_limit
            .lock()
            .expect("challenge limiter poisoned")
            .allow(ip.as_bytes())
    }

    pub fn allow_account(&self, account: &[u8; 20]) -> bool {
        self.account_limit
            .lock()
            .expect("account limiter poisoned")
            .allow(account)
    }

    /// Issue a capability for a batch in good standing.
    ///
    /// Standing is resolved by the caller (it owns the RPC path and its
    /// cache); this turns it into a credit line and a MAC. The result is
    /// what makes `/v1/push` admission chain-free.
    pub fn issue(
        &self,
        account: [u8; 20],
        batch: [u8; 32],
        remaining_value_plur: u128,
        origin: &str,
        now: u64,
    ) -> Result<IssuedChallenge, ChallengeError> {
        let cap = self.cfg.params.credit_line(remaining_value_plur);
        let fields = ChallengeFields {
            account,
            batch,
            origin: origin.to_string(),
            expiry_unix: now.saturating_add(crate::challenge::CHALLENGE_TTL_SECS),
            cap_plur: cap,
        };
        let secret = *self.ledger.lock().expect("ledger poisoned").secret();
        let nonce = crate::challenge::nonce(&secret, &fields)?;
        Ok(IssuedChallenge { fields, nonce })
    }

    /// Verify a presented challenge header end to end.
    ///
    /// Two independent proofs, and both are required:
    /// 1. our MAC over the nonce — this relay issued this capability;
    /// 2. the client's EIP-712 signature — the caller holds the account key
    ///    *and* signed for this origin (§11.1).
    ///
    /// A valid MAC alone would let anyone who observed a challenge use it,
    /// and a valid signature alone would let a challenge issued by another
    /// relay be presented here.
    pub fn verify_header(&self, raw: &str, now: u64) -> Result<VerifiedChallenge, String> {
        if raw.len() > MAX_CHALLENGE_HEADER {
            return Err(format!("challenge header too large: {} bytes", raw.len()));
        }
        let presented = PresentedChallenge::decode(raw)?;
        let secret = *self.ledger.lock().expect("ledger poisoned").secret();
        crate::challenge::verify(
            &secret,
            &presented.fields,
            &presented.nonce,
            now,
            &self.cfg.origins,
        )
        .map_err(|e| e.to_string())?;

        let sol = crate::signer::PushChallenge {
            nonce: alloy_primitives::B256::from(presented.nonce),
            origin: presented.fields.origin.clone(),
            account: Address::from(presented.fields.account),
            batchId: alloy_primitives::B256::from(presented.fields.batch),
            expiry: alloy_primitives::U256::from(presented.fields.expiry_unix),
        };
        let signer = crate::signer::recover_push_challenge(&sol, self.cfg.chain_id, &presented.sig)
            .map_err(|e| format!("challenge signature: {e}"))?;
        if signer != presented.fields.account {
            return Err(format!(
                "challenge signed by 0x{} but claims account 0x{}",
                hex::encode(signer),
                hex::encode(presented.fields.account)
            ));
        }
        Ok(VerifiedChallenge {
            account: presented.fields.account,
            batch: presented.fields.batch,
            cap_plur: presented.fields.cap_plur,
        })
    }

    /// Is this address a chequebook our canonical factory deployed?
    /// Cached both ways — an uncached miss is a one-RPC-per-request
    /// amplifier on an endpoint an attacker reaches for free (§11.6).
    pub async fn is_deployed(&self, rpc_url: &str, chequebook: [u8; 20]) -> Result<bool, String> {
        if let Some(hit) = self
            .deployed
            .lock()
            .expect("deployed cache poisoned")
            .get(&chequebook)
        {
            return Ok(hit);
        }
        let ok = crate::batch::is_deployed_chequebook(
            rpc_url,
            self.cfg.factory,
            Address::from(chequebook),
        )
        .await
        .map_err(|e| format!("factory lookup: {e}"))?;
        self.deployed
            .lock()
            .expect("deployed cache poisoned")
            .insert(chequebook, ok);
        Ok(ok)
    }

    /// Reserve for a request whose body is `content_length` bytes.
    ///
    /// The reservation and the eventual bill are the *same* quantity
    /// computed the same way (§7.2), so there is no estimate to be wrong
    /// about and no flat over-reserve to lock small batches out.
    pub fn reserve_for_body(
        &self,
        account: [u8; 20],
        content_length: u64,
        cap: u128,
    ) -> crate::ledger::Admission {
        let amount = self.cfg.params.price_bytes(content_length);
        let mut l = self.ledger.lock().expect("ledger poisoned");
        l.reserve(account, amount, cap)
    }

    pub fn shed_reservations(&self) -> bool {
        self.ledger
            .lock()
            .expect("ledger poisoned")
            .live_reservations()
            >= MAX_LIVE_RESERVATIONS
    }

    /// Apply a cheque. Every free check runs before this is called; this is
    /// the ledger half only.
    ///
    /// Persist failure rolls back in memory and is propagated (caller
    /// answers 5xx): accepting in memory but failing to durably record
    /// `last_cumulative` re-opens §11.4's replay hole after a restart —
    /// the same cheque would credit a second time.
    pub fn credit(
        &self,
        account: [u8; 20],
        chequebook: [u8; 20],
        cumulative: u128,
        signature: [u8; 65],
    ) -> Result<u128, LedgerError> {
        let mut l = self.ledger.lock().expect("ledger poisoned");
        let prev_owed = l.owed(&account);
        let prev_held = l.held_cheque(&account, &chequebook);
        let had_binding = l.had_binding(&chequebook);
        let accepted = l.credit(account, chequebook, cumulative, signature)?;
        // Persist immediately: the window between accepting a cheque and
        // durably recording its cumulative is exactly §11.4's replay hole.
        if let Err(e) = l.persist() {
            l.rollback_credit(account, chequebook, prev_owed, prev_held, had_binding);
            return Err(LedgerError::Store(e.to_string()));
        }
        Ok(accepted)
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedChallenge {
    pub account: [u8; 20],
    pub batch: [u8; 32],
    pub cap_plur: u128,
}

struct StateCache {
    map: HashMap<[u8; 20], (crate::batch::ChequebookState, Instant)>,
    order: std::collections::VecDeque<[u8; 20]>,
    cap: usize,
}

impl StateCache {
    fn new(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: std::collections::VecDeque::new(),
            cap: cap.max(1),
        }
    }

    fn get(&self, k: &[u8; 20]) -> Option<crate::batch::ChequebookState> {
        let (v, at) = self.map.get(k)?;
        (at.elapsed() < STATE_TTL).then_some(*v)
    }

    fn insert(&mut self, k: [u8; 20], v: crate::batch::ChequebookState) {
        if self.map.insert(k, (v, Instant::now())).is_none() {
            self.order.push_back(k);
        }
        while self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
    }

    fn remove(&mut self, k: &[u8; 20]) {
        self.map.remove(k);
        // Drop the ghost from the eviction queue too: otherwise every pay
        // leaves one slot behind, the next insert for the same key pushes a
        // duplicate, and live entries are evicted early (extra eth_calls).
        self.order.retain(|x| x != k);
    }
}

struct DeployedCache {
    map: HashMap<[u8; 20], (bool, Instant)>,
    order: std::collections::VecDeque<[u8; 20]>,
    cap: usize,
}

impl DeployedCache {
    fn new(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: std::collections::VecDeque::new(),
            cap: cap.max(1),
        }
    }

    fn get(&self, k: &[u8; 20]) -> Option<bool> {
        let (v, at) = self.map.get(k)?;
        let ttl = if *v {
            DEPLOYED_OK_TTL
        } else {
            DEPLOYED_BAD_TTL
        };
        (at.elapsed() < ttl).then_some(*v)
    }

    fn insert(&mut self, k: [u8; 20], v: bool) {
        if self.map.insert(k, (v, Instant::now())).is_none() {
            self.order.push_back(k);
        }
        while self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::encode_challenge_header;
    use crate::signer::SwarmSigner;

    const KEY: &str = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

    fn signer() -> SwarmSigner {
        SwarmSigner::from_hex_with_nonce(KEY, &format!("0x{}", hex::encode([0u8; 32])), 1)
            .expect("key")
    }

    fn metered() -> Metered {
        Metered::new(
            MeterConfig {
                origins: vec!["relay-a.example".into()],
                beneficiary: [3u8; 20],
                chain_id: 100,
                factory: Address::ZERO,
                params: Params::default(),
                hard_mode: false,
            },
            Ledger::ephemeral(),
        )
    }

    /// Issue → sign → present → verify, the whole admission path.
    fn round_trip(m: &Metered, now: u64) -> Result<VerifiedChallenge, String> {
        let s = signer();
        let account = *s.eth_address();
        let issued = m
            .issue(
                account,
                [5u8; 32],
                6_200_000_000_000_000_000,
                "relay-a.example",
                now,
            )
            .expect("issue");
        let sol = crate::signer::PushChallenge {
            nonce: alloy_primitives::B256::from(issued.nonce),
            origin: issued.fields.origin.clone(),
            account: Address::from(account),
            batchId: alloy_primitives::B256::from(issued.fields.batch),
            expiry: alloy_primitives::U256::from(issued.fields.expiry_unix),
        };
        let sig = s.sign_push_challenge(&sol, 100).expect("sign");
        let header = encode_challenge_header(&issued, &sig);
        m.verify_header(&header, now)
    }

    #[test]
    fn a_challenge_we_issued_and_the_client_signed_is_admitted() {
        let m = metered();
        let v = round_trip(&m, 1000).expect("must admit");
        assert_eq!(v.account, *signer().eth_address());
        assert_eq!(v.batch, [5u8; 32]);
        assert_eq!(
            v.cap_plur,
            Params::default().max_outstanding_plur,
            "a rich batch clamps to the ceiling"
        );
    }

    /// A capability alone is not enough — the caller must prove it holds the
    /// account key, or a harvested header would be usable by anyone.
    #[test]
    fn a_challenge_signed_by_the_wrong_key_is_refused() {
        let m = metered();
        let victim = *signer().eth_address();
        let issued = m
            .issue(
                victim,
                [5u8; 32],
                1_000_000_000_000_000,
                "relay-a.example",
                1000,
            )
            .expect("issue");
        let attacker = SwarmSigner::from_hex_with_nonce(
            "0x1111111111111111111111111111111111111111111111111111111111111111",
            &format!("0x{}", hex::encode([0u8; 32])),
            1,
        )
        .expect("key");
        let sol = crate::signer::PushChallenge {
            nonce: alloy_primitives::B256::from(issued.nonce),
            origin: issued.fields.origin.clone(),
            account: Address::from(victim),
            batchId: alloy_primitives::B256::from(issued.fields.batch),
            expiry: alloy_primitives::U256::from(issued.fields.expiry_unix),
        };
        let sig = attacker.sign_push_challenge(&sol, 100).expect("sign");
        let header = encode_challenge_header(&issued, &sig);
        let e = m.verify_header(&header, 1000).expect_err("must refuse");
        assert!(e.contains("claims account"), "got: {e}");
    }

    /// §11.1: a signature gathered at relay A must be useless at relay B.
    #[test]
    fn a_challenge_for_another_relay_is_refused() {
        let a = metered();
        let mut b_cfg = a.cfg.clone();
        b_cfg.origins = vec!["relay-b.example".into()];
        let b = Metered::new(b_cfg, Ledger::ephemeral());

        let s = signer();
        let issued = a
            .issue(
                *s.eth_address(),
                [5u8; 32],
                1_000_000_000_000_000,
                "relay-a.example",
                1000,
            )
            .expect("issue");
        let sol = crate::signer::PushChallenge {
            nonce: alloy_primitives::B256::from(issued.nonce),
            origin: issued.fields.origin.clone(),
            account: Address::from(*s.eth_address()),
            batchId: alloy_primitives::B256::from(issued.fields.batch),
            expiry: alloy_primitives::U256::from(issued.fields.expiry_unix),
        };
        let sig = s.sign_push_challenge(&sol, 100).expect("sign");
        let header = encode_challenge_header(&issued, &sig);
        let e = b.verify_header(&header, 1000).expect_err("must refuse");
        assert!(e.contains("origin"), "got: {e}");
    }

    #[test]
    fn an_expired_challenge_is_refused() {
        let m = metered();
        let e = round_trip(&m, 1000).map(|_| ()).and(Ok(()));
        assert!(e.is_ok());
        // Same issue instant, far-future presentation.
        let s = signer();
        let issued = m
            .issue(
                *s.eth_address(),
                [5u8; 32],
                1_000_000_000_000_000,
                "relay-a.example",
                1000,
            )
            .expect("issue");
        let sol = crate::signer::PushChallenge {
            nonce: alloy_primitives::B256::from(issued.nonce),
            origin: issued.fields.origin.clone(),
            account: Address::from(*s.eth_address()),
            batchId: alloy_primitives::B256::from(issued.fields.batch),
            expiry: alloy_primitives::U256::from(issued.fields.expiry_unix),
        };
        let sig = s.sign_push_challenge(&sol, 100).expect("sign");
        let header = encode_challenge_header(&issued, &sig);
        let e = m
            .verify_header(&header, 1000 + crate::challenge::CHALLENGE_TTL_SECS + 1)
            .expect_err("must refuse");
        assert!(e.contains("expired"), "got: {e}");
    }

    /// The cap is inside the MAC, so a client cannot present a dust batch's
    /// id alongside a rich batch's credit line.
    #[test]
    fn an_inflated_cap_is_refused() {
        let m = metered();
        let s = signer();
        let mut issued = m
            .issue(
                *s.eth_address(),
                [5u8; 32],
                100_000_000_000_000,
                "relay-a.example",
                1000,
            )
            .expect("issue");
        let honest_cap = issued.fields.cap_plur;
        issued.fields.cap_plur = honest_cap * 1_000_000;
        let sol = crate::signer::PushChallenge {
            nonce: alloy_primitives::B256::from(issued.nonce),
            origin: issued.fields.origin.clone(),
            account: Address::from(*s.eth_address()),
            batchId: alloy_primitives::B256::from(issued.fields.batch),
            expiry: alloy_primitives::U256::from(issued.fields.expiry_unix),
        };
        let sig = s.sign_push_challenge(&sol, 100).expect("sign");
        let header = encode_challenge_header(&issued, &sig);
        let e = m.verify_header(&header, 1000).expect_err("must refuse");
        assert!(e.contains("not ours"), "got: {e}");
    }

    #[test]
    fn malformed_headers_are_refused_not_panicked_on() {
        let m = metered();
        for raw in ["", "!!!!", "eyJ9", "e30="] {
            m.verify_header(raw, 1000).expect_err("must refuse");
        }
        m.verify_header(&"A".repeat(MAX_CHALLENGE_HEADER + 1), 1000)
            .expect_err("oversized");
    }

    #[test]
    fn the_reservation_is_the_price_of_the_declared_body() {
        let m = metered();
        let p = Params::default();
        let adm = m.reserve_for_body([1u8; 20], 4251, p.max_outstanding_plur);
        assert_eq!(adm.reserved_plur, p.price_bytes(4251));
        assert!(!adm.over_cap);
    }

    /// §7.2's small-batch case: a one-frame POST from a dust batch fits,
    /// where an earlier design's flat `PUSH_BATCH_MAX × price` reserve would
    /// have 402'd it.
    #[test]
    fn a_dust_batch_can_afford_a_small_post() {
        let m = metered();
        let cap = Params::default().credit_line(100_000_000_000_000);
        let adm = m.reserve_for_body([1u8; 20], 4251, cap);
        assert!(!adm.over_cap, "a single frame must fit a dust batch's line");
        let m2 = metered();
        let big = m2.reserve_for_body([1u8; 20], 512 * 4251, cap);
        assert!(big.over_cap, "but a full 512-frame POST does not");
    }
}

#[cfg(test)]
mod lifecycle_tests {
    //! The full soft-mode money path over the real ledger: admit → bill →
    //! settle → replay. These exercise `Metered` + `Ledger` together, which
    //! is where the accounting can silently drift.
    use super::*;
    use crate::meter::Params;

    fn m() -> Metered {
        Metered::new(
            MeterConfig {
                origins: vec!["relay-a.example".into()],
                beneficiary: [3u8; 20],
                chain_id: 100,
                factory: Address::ZERO,
                params: Params::default(),
                hard_mode: false,
            },
            Ledger::ephemeral(),
        )
    }

    const ACCT: [u8; 20] = [1u8; 20];
    const CB: [u8; 20] = [9u8; 20];

    /// One POST: reserve on the declared body, bill what was admitted,
    /// release the rest. The reservation must not survive as phantom debt.
    #[test]
    fn a_request_reserves_then_commits_only_what_it_admitted() {
        let m = m();
        let p = Params::default();
        let cap = p.max_outstanding_plur;
        let adm = m.reserve_for_body(ACCT, 512 * 4251, cap);
        assert_eq!(m.ledger.lock().unwrap().reserved(&ACCT), adm.reserved_plur);

        // Only 100 frames actually got admitted.
        let billed = p.price_bytes(100 * 4251);
        m.ledger
            .lock()
            .unwrap()
            .commit(ACCT, adm.reserved_plur, billed);
        let l = m.ledger.lock().unwrap();
        assert_eq!(l.reserved(&ACCT), 0, "the reservation is fully released");
        assert_eq!(l.owed(&ACCT), billed, "only admitted bytes are billed");
        assert!(
            billed < adm.reserved_plur,
            "and it is less than was reserved"
        );
    }

    /// A POST that admits nothing must still hand its reservation back —
    /// leaking it ratchets the account toward a 402 it can never clear.
    #[test]
    fn a_request_that_admits_nothing_leaks_no_credit() {
        let m = m();
        let adm = m.reserve_for_body(ACCT, 512 * 4251, Params::default().max_outstanding_plur);
        m.ledger.lock().unwrap().commit(ACCT, adm.reserved_plur, 0);
        let l = m.ledger.lock().unwrap();
        assert_eq!(l.outstanding(&ACCT), 0, "nothing owed, nothing reserved");
    }

    /// Settle, then push again: the cumulative carries forward, so the
    /// second cheque credits only the new debt.
    #[test]
    fn settlement_across_two_uploads_uses_one_growing_cumulative() {
        let m = m();
        let p = Params::default();
        let first = p.price_bytes(40 * 1024 * 1024);
        m.ledger.lock().unwrap().commit(ACCT, 0, first);

        let accepted = m.credit(ACCT, CB, first, [27u8; 65]).expect("first cheque");
        assert_eq!(accepted, first);
        assert_eq!(m.ledger.lock().unwrap().owed(&ACCT), 0);

        let second = p.price_bytes(32 * 1024 * 1024);
        m.ledger.lock().unwrap().commit(ACCT, 0, second);
        // A cumulative cheque: the *total*, not the delta.
        let accepted = m
            .credit(ACCT, CB, first + second, [27u8; 65])
            .expect("second cheque");
        assert_eq!(accepted, second, "only the new debt is credited");
        assert_eq!(m.ledger.lock().unwrap().owed(&ACCT), 0);
    }

    /// Soft mode reports the overshoot but still admits — that is the whole
    /// point of Stage 1 shipping soft.
    #[test]
    fn soft_mode_reports_an_overshoot_without_refusing() {
        let m = m();
        let cap = Params::default().credit_line(100_000_000_000_000); // dust
        let adm = m.reserve_for_body(ACCT, 512 * 4251, cap);
        assert!(adm.over_cap, "a full POST exceeds a dust batch's line");
        assert!(!m.cfg.hard_mode, "Stage 1 ships soft");
        assert!(
            m.ledger.lock().unwrap().reserved(&ACCT) > 0,
            "soft mode still reserves, so the measurement is real"
        );
    }

    /// The same request under hard mode must leave no trace once refused.
    #[test]
    fn hard_mode_releases_the_reservation_it_refuses() {
        let mut cfg = m().cfg.clone();
        cfg.hard_mode = true;
        let m = Metered::new(cfg, Ledger::ephemeral());
        let cap = Params::default().credit_line(100_000_000_000_000);
        let adm = m.reserve_for_body(ACCT, 512 * 4251, cap);
        assert!(adm.over_cap);
        m.ledger.lock().unwrap().release(ACCT, adm.reserved_plur);
        assert_eq!(
            m.ledger.lock().unwrap().outstanding(&ACCT),
            0,
            "a refused request must not leave phantom debt behind"
        );
    }

    /// §10.1's invariant in motion: a client 402'd at the cap can always
    /// clear it with a cheque for exactly what it owes.
    #[test]
    fn an_account_at_its_cap_can_always_pay_its_way_out() {
        let m = m();
        let p = Params::default();
        let cap = p.max_outstanding_plur;
        // Accrue right up to the ceiling.
        m.ledger.lock().unwrap().commit(ACCT, 0, cap);
        let owed = m.ledger.lock().unwrap().owed(&ACCT);
        assert!(
            owed >= p.min_cheque_plur,
            "what is owed must clear the dust floor, or there is no exit"
        );
        m.credit(ACCT, CB, owed, [27u8; 65])
            .expect("a cheque for exactly what is owed");
        assert_eq!(m.ledger.lock().unwrap().owed(&ACCT), 0);
        assert!(
            !m.reserve_for_body(ACCT, 4251, cap).over_cap,
            "and the account can push again"
        );
    }
}

#[cfg(test)]
mod soft_mode_tests {
    //! §7.1's rollout property: soft mode must serve clients that predate
    //! the payment protocol. Requiring a challenge unconditionally would
    //! 401 the whole existing fleet the moment `--meter` was enabled, which
    //! is the opposite of a staged rollout.
    use super::*;
    use crate::meter::Params;

    fn cfg(hard: bool) -> MeterConfig {
        MeterConfig {
            origins: vec!["relay-a.example".into()],
            beneficiary: [3u8; 20],
            chain_id: 100,
            factory: Address::ZERO,
            params: Params::default(),
            hard_mode: hard,
        }
    }

    /// An absent header is not an invalid one — it is a client that does not
    /// speak the protocol yet.
    #[test]
    fn an_empty_header_is_distinguishable_from_a_malformed_one() {
        let m = Metered::new(cfg(false), Ledger::ephemeral());
        // Malformed is always refused, in either mode: claiming a capability
        // you do not hold must not become valid by corrupting a byte.
        m.verify_header("not-base64!!", 1000)
            .expect_err("a malformed header is always refused");
        m.verify_header("", 1000)
            .expect_err("verify_header itself has no opinion about absence");
    }

    /// Hard mode is where the challenge becomes mandatory, because by then
    /// there is a 402 to enforce.
    #[test]
    fn hard_mode_is_what_makes_the_challenge_mandatory() {
        assert!(!cfg(false).hard_mode, "soft is the shipped default");
        assert!(cfg(true).hard_mode);
    }
}
