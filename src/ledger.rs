//! Relay-side payment ledger — `docs/pusher-incentives.md` §10.2, §11.4.
//!
//! Four coupled per-account quantities, written by N spawned push tasks and
//! read by admission, so they live under one lock:
//!
//! - `owed_plur` — billed and unpaid.
//! - `reserved_plur` — admitted but not yet completed.
//! - `last_cumulative[chequebook]` — the monotonic high-water mark that
//!   makes a re-presented cheque worth zero.
//! - the `chequebook → account` binding.
//!
//! **Three of those are persisted and one is not, and the asymmetry is
//! load-bearing.** A reservation belongs to an in-flight POST, and no
//! in-flight POST survives a restart — there is no task left to release it.
//! Restoring `reserved` from disk therefore leaks credit permanently and can
//! brick an account into 402 with no way out, which is exactly the no-exit
//! failure §10.1's invariant exists to prevent. So:
//!
//! > Persist `owed`, `last_cumulative`, the binding and `relay_secret`
//! > atomically. Reconstruct `reserved` as zero at boot.
//!
//! The exposure from zeroing is one body's worth of over-admission right
//! after a restart — cents of egress, against an accounting corruption that
//! never self-heals.
//!
//! Losing `last_cumulative` alone is worse than losing everything: a client
//! re-presents its most recent cheque and is credited the *full cumulative*
//! instead of the delta, repeatably, for free (§11.4). Hence one atomic
//! write covering all of it, never a field at a time.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Refuse a cumulative past this. Total BZZ supply is 10^8 BZZ = 10^24
/// PLUR, so anything above 10^30 is not a payment — it is an attempt to
/// find an overflow. Bounding it here keeps every downstream figure in
/// `u128` (max ≈ 3.4×10^38) with room to spare.
pub const MAX_CUMULATIVE_PLUR: u128 = 1_000_000_000_000_000_000_000_000_000_000;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LedgerError {
    #[error("cheque cumulative {got} is not greater than the {have} already accepted")]
    NotIncreasing { got: u128, have: u128 },
    #[error("chequebook 0x{chequebook} is already bound to a different account")]
    ChequebookBound { chequebook: String },
    #[error("cumulative {0} is implausibly large")]
    Absurd(u128),
    #[error("cheque credits {got} but only {owed} is owed")]
    Overpayment { got: u128, owed: u128 },
    #[error("ledger persist failed: {0}")]
    Store(String),
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io: {0}")]
    Io(String),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

/// Outcome of admitting a request against a credit line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admission {
    pub reserved_plur: u128,
    /// `owed + reserved` after this reservation.
    pub outstanding_plur: u128,
    pub cap_plur: u128,
    /// True when this request pushed the account past its line. Soft mode
    /// records it; hard mode releases the reservation and answers 402.
    pub over_cap: bool,
}

#[derive(Debug, Default, Clone)]
struct Account {
    owed_plur: u128,
    /// Deliberately absent from the on-disk form. See the module docs.
    reserved_plur: u128,
    last_cumulative: HashMap<[u8; 20], HeldCheque>,
}

/// The latest cheque accepted from one chequebook.
///
/// **The signature has to be kept.** Cheques are cumulative, so only the
/// newest one is ever worth presenting (§7.2) — but without its signature
/// the relay holds a number it can prove nothing about and can never cash.
/// The first cut stored only the cumulative, which made the whole ledger a
/// record of money that could not be collected.
#[derive(Debug, Clone, Copy)]
pub struct HeldCheque {
    pub cumulative_plur: u128,
    pub signature: [u8; 65],
}

impl Account {
    fn outstanding(&self) -> u128 {
        self.owed_plur.saturating_add(self.reserved_plur)
    }
}

pub struct Ledger {
    accounts: HashMap<[u8; 20], Account>,
    /// A chequebook belongs to the first account that paid with it and
    /// cannot move. Without this, two accounts could share a cumulative and
    /// one would ride the other's payments.
    binding: HashMap<[u8; 20], [u8; 20]>,
    secret: [u8; 32],
    path: Option<PathBuf>,
}

// ── On-disk form ─────────────────────────────────────────────────────────
// Hex-keyed and decimal-stringed: JSON has no u128, and PLUR amounts
// comfortably exceed what an f64 can hold exactly.

#[derive(Serialize, Deserialize)]
struct OnDisk {
    version: u32,
    secret_hex: String,
    accounts: Vec<OnDiskAccount>,
    binding: Vec<(String, String)>,
}

#[derive(Serialize, Deserialize)]
struct OnDiskAccount {
    account: String,
    owed_plur: String,
    /// `(chequebook, cumulative, signature_hex)`. Version 1 files carry no
    /// signature; they load, but nothing in them can be cashed.
    last_cumulative: Vec<(String, String, String)>,
}

impl Ledger {
    /// Fresh ledger with a random secret. Used when no `--state-dir` is
    /// configured, which metered mode forbids (§5) but open mode allows.
    pub fn ephemeral() -> Self {
        let mut secret = [0u8; 32];
        // A failure here would mean no entropy source at all; a zero secret
        // would make every nonce forgeable, so refuse to run instead.
        getrandom::fill(&mut secret).expect("system entropy for the relay secret");
        Self {
            accounts: HashMap::new(),
            binding: HashMap::new(),
            secret,
            path: None,
        }
    }

    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Load from disk, or create and immediately persist a new ledger.
    ///
    /// `relay_secret` is part of the same file: regenerating it at boot
    /// invalidates every outstanding challenge, which on a host that sleeps
    /// and cold-starts turns each restart into a 403 storm for clients
    /// mid-upload (§7.2).
    pub fn load_or_create<P: AsRef<Path>>(path: P) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        let text = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut fresh = Self::ephemeral();
                fresh.path = Some(path);
                fresh.persist()?;
                return Ok(fresh);
            }
            Err(e) => return Err(StoreError::Io(e.to_string())),
        };
        let disk: OnDisk = serde_json::from_str(&text)?;
        // Version dispatch: v1 entries load (missing sig → zeroed, skipped at
        // cashout) but an unknown future version must not load silently with
        // changed semantics.
        if disk.version != 1 && disk.version != 2 {
            return Err(StoreError::Io(format!(
                "unsupported ledger version {}",
                disk.version
            )));
        }
        let mut secret = [0u8; 32];
        let raw = hex::decode(disk.secret_hex.trim_start_matches("0x"))
            .map_err(|e| StoreError::Io(format!("secret hex: {e}")))?;
        if raw.len() != 32 {
            return Err(StoreError::Io(format!(
                "relay secret must be 32 bytes, got {}",
                raw.len()
            )));
        }
        secret.copy_from_slice(&raw);

        let mut accounts = HashMap::new();
        for a in disk.accounts {
            let key = parse_addr(&a.account)?;
            let mut last_cumulative = HashMap::new();
            for (cb, v, sig_hex) in a.last_cumulative {
                let raw = hex::decode(sig_hex.trim_start_matches("0x"))
                    .map_err(|e| StoreError::Io(format!("cheque signature hex: {e}")))?;
                // A v1 entry has no signature. Keep the cumulative — losing
                // it would let the client replay (§11.4) — but leave the
                // signature zeroed so cashout skips it rather than
                // submitting something the contract will reject.
                let mut signature = [0u8; 65];
                if raw.len() == 65 {
                    signature.copy_from_slice(&raw);
                }
                last_cumulative.insert(
                    parse_addr(&cb)?,
                    HeldCheque {
                        cumulative_plur: parse_u128(&v)?,
                        signature,
                    },
                );
            }
            accounts.insert(
                key,
                Account {
                    owed_plur: parse_u128(&a.owed_plur)?,
                    // Never restored. See the module docs.
                    reserved_plur: 0,
                    last_cumulative,
                },
            );
        }
        let mut binding = HashMap::new();
        for (cb, acct) in disk.binding {
            binding.insert(parse_addr(&cb)?, parse_addr(&acct)?);
        }
        Ok(Self {
            accounts,
            binding,
            secret,
            path: Some(path),
        })
    }

    /// Write the durable half atomically: a temp file in the same directory
    /// followed by a rename, so a crash mid-write leaves the previous state
    /// rather than a truncated one. Losing `last_cumulative` while keeping
    /// `owed` is the specific corruption this prevents.
    pub fn persist(&self) -> Result<(), StoreError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let mut accounts: Vec<OnDiskAccount> = self
            .accounts
            .iter()
            .filter(|(_, a)| a.owed_plur > 0 || !a.last_cumulative.is_empty())
            .map(|(k, a)| {
                let mut last: Vec<(String, String, String)> = a
                    .last_cumulative
                    .iter()
                    .map(|(cb, c)| {
                        (
                            hex::encode(cb),
                            c.cumulative_plur.to_string(),
                            hex::encode(c.signature),
                        )
                    })
                    .collect();
                last.sort();
                OnDiskAccount {
                    account: hex::encode(k),
                    owed_plur: a.owed_plur.to_string(),
                    last_cumulative: last,
                }
            })
            .collect();
        accounts.sort_by(|a, b| a.account.cmp(&b.account));
        let mut binding: Vec<(String, String)> = self
            .binding
            .iter()
            .map(|(cb, a)| (hex::encode(cb), hex::encode(a)))
            .collect();
        binding.sort();

        let disk = OnDisk {
            version: 2,
            secret_hex: hex::encode(self.secret),
            accounts,
            binding,
        };
        let body = serde_json::to_vec_pretty(&disk)?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &body).map_err(|e| StoreError::Io(e.to_string()))?;
        std::fs::rename(&tmp, path).map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(())
    }

    pub fn owed(&self, account: &[u8; 20]) -> u128 {
        self.accounts.get(account).map_or(0, |a| a.owed_plur)
    }

    pub fn reserved(&self, account: &[u8; 20]) -> u128 {
        self.accounts.get(account).map_or(0, |a| a.reserved_plur)
    }

    pub fn outstanding(&self, account: &[u8; 20]) -> u128 {
        self.accounts.get(account).map_or(0, Account::outstanding)
    }

    pub fn last_cumulative(&self, account: &[u8; 20], chequebook: &[u8; 20]) -> u128 {
        self.accounts
            .get(account)
            .and_then(|a| a.last_cumulative.get(chequebook))
            .map(|c| c.cumulative_plur)
            .unwrap_or(0)
    }

    pub fn held_cheque(&self, account: &[u8; 20], chequebook: &[u8; 20]) -> Option<HeldCheque> {
        self.accounts
            .get(account)
            .and_then(|a| a.last_cumulative.get(chequebook))
            .copied()
    }

    pub fn had_binding(&self, chequebook: &[u8; 20]) -> bool {
        self.binding.contains_key(chequebook)
    }

    /// Undo a `credit` whose persist failed, restoring owed + cumulative +
    /// binding to their pre-credit values so disk and memory agree (both
    /// old). Keeps the relay fail-closed: the client re-presents the same
    /// cheque and it credits once the disk is writable again.
    pub fn rollback_credit(
        &mut self,
        account: [u8; 20],
        chequebook: [u8; 20],
        prev_owed: u128,
        prev_held: Option<HeldCheque>,
        had_binding: bool,
    ) {
        if let Some(a) = self.accounts.get_mut(&account) {
            a.owed_plur = prev_owed;
            match prev_held {
                Some(h) => {
                    a.last_cumulative.insert(chequebook, h);
                }
                None => {
                    a.last_cumulative.remove(&chequebook);
                }
            }
        }
        if !had_binding {
            self.binding.remove(&chequebook);
        }
    }

    /// Every cheque the relay holds, newest per chequebook. This is what
    /// `hoverfly cashout` presents on-chain.
    pub fn held_cheques(&self) -> Vec<([u8; 20], [u8; 20], HeldCheque)> {
        let mut out = Vec::new();
        for (account, a) in &self.accounts {
            for (cb, held) in &a.last_cumulative {
                out.push((*account, *cb, *held));
            }
        }
        out.sort_by_key(|(_, cb, _)| *cb);
        out
    }

    /// Number of accounts holding a live reservation — the cardinality
    /// §7.2 says to bound, since the map is attacker-influenced.
    pub fn live_reservations(&self) -> usize {
        self.accounts
            .values()
            .filter(|a| a.reserved_plur > 0)
            .count()
    }

    /// Reserve against a credit line, atomically with respect to every
    /// other in-flight request for this account.
    ///
    /// Always reserves, and *reports* whether it went over rather than
    /// deciding: soft mode records the overshoot and serves anyway, hard
    /// mode releases and answers 402 (§7.1). Doing the arithmetic in one
    /// place means the two modes cannot disagree about what "over" means.
    pub fn reserve(&mut self, account: [u8; 20], amount: u128, cap: u128) -> Admission {
        let a = self.accounts.entry(account).or_default();
        a.reserved_plur = a.reserved_plur.saturating_add(amount);
        let outstanding = a.outstanding();
        Admission {
            reserved_plur: amount,
            outstanding_plur: outstanding,
            cap_plur: cap,
            over_cap: outstanding > cap,
        }
    }

    /// Give back an unused reservation, e.g. after a hard-mode 402.
    pub fn release(&mut self, account: [u8; 20], amount: u128) {
        if let Some(a) = self.accounts.get_mut(&account) {
            a.reserved_plur = a.reserved_plur.saturating_sub(amount);
        }
    }

    /// Turn a reservation into debt for what was actually admitted, and
    /// release the remainder.
    pub fn commit(&mut self, account: [u8; 20], reserved: u128, billed: u128) {
        let a = self.accounts.entry(account).or_default();
        a.reserved_plur = a.reserved_plur.saturating_sub(reserved);
        a.owed_plur = a.owed_plur.saturating_add(billed);
    }

    /// Accept a cheque and return the amount it newly credits.
    ///
    /// Monotonicity is what makes a cheque replay-proof *within a live
    /// relay* — a re-presented cheque credits zero — and it is why losing
    /// this map across a restart is an unbounded free-service loop (§11.4).
    pub fn credit(
        &mut self,
        account: [u8; 20],
        chequebook: [u8; 20],
        cumulative_plur: u128,
        signature: [u8; 65],
    ) -> Result<u128, LedgerError> {
        if cumulative_plur > MAX_CUMULATIVE_PLUR {
            return Err(LedgerError::Absurd(cumulative_plur));
        }
        match self.binding.get(&chequebook) {
            Some(bound) if *bound != account => {
                return Err(LedgerError::ChequebookBound {
                    chequebook: hex::encode(chequebook),
                });
            }
            _ => {}
        }
        let a = self.accounts.entry(account).or_default();
        let have = a
            .last_cumulative
            .get(&chequebook)
            .map(|c| c.cumulative_plur)
            .unwrap_or(0);
        if cumulative_plur <= have {
            return Err(LedgerError::NotIncreasing {
                got: cumulative_plur,
                have,
            });
        }
        let delta = cumulative_plur - have;
        // Refuse to bank more than is owed. Postpaid means a client should
        // never be ahead (§10), and accepting an overpayment would turn the
        // relay into a place to park value it cannot return.
        if delta > a.owed_plur {
            return Err(LedgerError::Overpayment {
                got: delta,
                owed: a.owed_plur,
            });
        }
        a.last_cumulative.insert(
            chequebook,
            HeldCheque {
                cumulative_plur,
                signature,
            },
        );
        a.owed_plur -= delta;
        self.binding.insert(chequebook, account);
        Ok(delta)
    }
}

fn parse_addr(s: &str) -> Result<[u8; 20], StoreError> {
    let raw = hex::decode(s.trim_start_matches("0x"))
        .map_err(|e| StoreError::Io(format!("address hex: {e}")))?;
    if raw.len() != 20 {
        return Err(StoreError::Io(format!("address must be 20 bytes: {s}")));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn parse_u128(s: &str) -> Result<u128, StoreError> {
    s.parse()
        .map_err(|e| StoreError::Io(format!("u128 parse {s}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 20] = [1u8; 20];
    const B: [u8; 20] = [2u8; 20];
    const CB: [u8; 20] = [9u8; 20];

    fn tmpdir() -> PathBuf {
        let base = std::env::var("CARGO_TARGET_TMPDIR").unwrap_or_else(|_| "/tmp".into());
        let p = PathBuf::from(base).join(format!("ledger-test-{}", std::process::id()));
        std::fs::create_dir_all(&p).expect("mkdir");
        p
    }

    #[test]
    fn a_reservation_shows_up_as_outstanding_and_releases_cleanly() {
        let mut l = Ledger::ephemeral();
        let adm = l.reserve(A, 500, 1000);
        assert_eq!(adm.outstanding_plur, 500);
        assert!(!adm.over_cap);
        assert_eq!(l.reserved(&A), 500);
        l.release(A, 500);
        assert_eq!(l.outstanding(&A), 0);
    }

    /// The concurrency case §10.2 is about: N requests each reserve before
    /// any of them completes, so the cap must see their sum.
    #[test]
    fn concurrent_reservations_accumulate_against_one_cap() {
        let mut l = Ledger::ephemeral();
        for _ in 0..7 {
            assert!(!l.reserve(A, 100, 1000).over_cap);
        }
        let adm = l.reserve(A, 100, 1000);
        assert_eq!(adm.outstanding_plur, 800);
        assert!(!adm.over_cap);
        let adm = l.reserve(A, 300, 1000);
        assert!(adm.over_cap, "1100 > 1000 must report over cap");
    }

    #[test]
    fn commit_turns_a_reservation_into_debt_and_frees_the_rest() {
        let mut l = Ledger::ephemeral();
        l.reserve(A, 1000, 10_000);
        l.commit(A, 1000, 240);
        assert_eq!(l.reserved(&A), 0, "the whole reservation is released");
        assert_eq!(l.owed(&A), 240, "only what was admitted is billed");
    }

    #[test]
    fn a_cheque_credits_only_the_delta() {
        let mut l = Ledger::ephemeral();
        l.commit(A, 0, 1000);
        assert_eq!(l.credit_test(A, CB, 400).expect("first"), 400);
        assert_eq!(l.owed(&A), 600);
        assert_eq!(l.credit_test(A, CB, 900).expect("second"), 500);
        assert_eq!(l.owed(&A), 100);
    }

    /// Replay within a live relay must be worth exactly zero.
    #[test]
    fn a_re_presented_cheque_credits_nothing() {
        let mut l = Ledger::ephemeral();
        l.commit(A, 0, 1000);
        l.credit_test(A, CB, 400).expect("first");
        assert_eq!(
            l.credit_test(A, CB, 400),
            Err(LedgerError::NotIncreasing {
                got: 400,
                have: 400
            })
        );
        assert_eq!(l.owed(&A), 600, "owed must not move");
    }

    #[test]
    fn a_chequebook_cannot_move_between_accounts() {
        let mut l = Ledger::ephemeral();
        l.commit(A, 0, 1000);
        l.credit_test(A, CB, 100).expect("bind to A");
        l.commit(B, 0, 1000);
        assert!(matches!(
            l.credit_test(B, CB, 500),
            Err(LedgerError::ChequebookBound { .. })
        ));
    }

    #[test]
    fn absurd_and_overpaying_cumulatives_are_refused() {
        let mut l = Ledger::ephemeral();
        l.commit(A, 0, 100);
        assert!(matches!(
            l.credit_test(A, CB, MAX_CUMULATIVE_PLUR + 1),
            Err(LedgerError::Absurd(_))
        ));
        assert!(matches!(
            l.credit_test(A, CB, 101),
            Err(LedgerError::Overpayment {
                got: 101,
                owed: 100
            })
        ));
        l.credit_test(A, CB, 100)
            .expect("paying exactly what is owed is fine");
        assert_eq!(l.owed(&A), 0);
    }

    /// The asymmetry the module exists to enforce: debt and the cumulative
    /// high-water mark survive a restart; a reservation does not.
    #[test]
    fn a_restart_keeps_debt_and_cumulative_but_drops_reservations() {
        let dir = tmpdir();
        let path = dir.join("restart.json");
        let _ = std::fs::remove_file(&path);

        let secret = {
            let mut l = Ledger::load_or_create(&path).expect("create");
            l.commit(A, 0, 5000);
            l.credit_test(A, CB, 1200).expect("pay");
            l.reserve(A, 900, 100_000);
            l.persist().expect("persist");
            *l.secret()
        };

        let l = Ledger::load_or_create(&path).expect("reload");
        assert_eq!(l.owed(&A), 3800, "debt survives");
        assert_eq!(l.last_cumulative(&A, &CB), 1200, "cumulative survives");
        assert_eq!(
            l.reserved(&A),
            0,
            "a reservation must NOT survive — no task remains to release it"
        );
        assert_eq!(
            l.secret(),
            &secret,
            "a regenerated secret would 403 every live client"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// §11.4's attack: pay once, consume, wait for a restart, re-present the
    /// same cheque. It must still credit zero.
    #[test]
    fn a_cheque_cannot_be_replayed_across_a_restart() {
        let dir = tmpdir();
        let path = dir.join("replay.json");
        let _ = std::fs::remove_file(&path);
        {
            let mut l = Ledger::load_or_create(&path).expect("create");
            l.commit(A, 0, 5000);
            l.credit_test(A, CB, 1200).expect("pay");
            l.persist().expect("persist");
        }
        let mut l = Ledger::load_or_create(&path).expect("reload");
        assert!(
            matches!(
                l.credit_test(A, CB, 1200),
                Err(LedgerError::NotIncreasing { .. })
            ),
            "re-presenting the same cheque after a restart must credit nothing"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_binding_survives_a_restart_too() {
        let dir = tmpdir();
        let path = dir.join("binding.json");
        let _ = std::fs::remove_file(&path);
        {
            let mut l = Ledger::load_or_create(&path).expect("create");
            l.commit(A, 0, 500);
            l.credit_test(A, CB, 100).expect("bind");
            l.persist().expect("persist");
        }
        let mut l = Ledger::load_or_create(&path).expect("reload");
        l.commit(B, 0, 500);
        assert!(
            matches!(
                l.credit_test(B, CB, 200),
                Err(LedgerError::ChequebookBound { .. })
            ),
            "the chequebook binding must survive a restart"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn live_reservations_are_countable_for_shedding() {
        let mut l = Ledger::ephemeral();
        assert_eq!(l.live_reservations(), 0);
        l.reserve(A, 10, 1000);
        l.reserve(B, 10, 1000);
        assert_eq!(l.live_reservations(), 2);
        l.release(A, 10);
        assert_eq!(l.live_reservations(), 1);
    }
}

#[cfg(test)]
mod leak_tests {
    //! A reservation that is never committed must never survive.
    //!
    //! Found by review: four early-return paths in `push_response` (oversize
    //! body, read timeout, frame-decode failure, empty batch) dropped the
    //! admission without releasing, and nothing else lowers `reserved_plur`
    //! — `credit` only touches `owed`. These pin the ledger-level invariants
    //! the RAII guard in `pusher.rs` relies on.
    use super::*;

    const A: [u8; 20] = [1u8; 20];
    const CB: [u8; 20] = [9u8; 20];

    /// Paying does **not** clear a reservation. This is the property that
    /// turns a leak into a permanent one, so it is worth stating outright.
    #[test]
    fn paying_a_cheque_does_not_release_a_reservation() {
        let mut l = Ledger::ephemeral();
        l.commit(A, 0, 1000);
        l.reserve(A, 500, 100_000);
        l.credit_test(A, CB, 1000).expect("pay off the debt");
        assert_eq!(l.owed(&A), 0, "the debt is cleared");
        assert_eq!(
            l.reserved(&A),
            500,
            "but the reservation is untouched — only commit or release move it"
        );
    }

    /// The ratchet: leaked reservations accumulate until `outstanding`
    /// exceeds the cap, and no cheque can bring it back down.
    #[test]
    fn leaked_reservations_ratchet_an_account_past_its_cap_with_no_way_back() {
        let mut l = Ledger::ephemeral();
        let cap = 10_000u128;
        for _ in 0..20 {
            l.reserve(A, 1000, cap); // admitted, then dropped without commit
        }
        assert!(l.outstanding(&A) > cap, "the account is now over its cap");
        // There is no debt to pay, so no cheque exists that could help.
        assert_eq!(l.owed(&A), 0);
        assert!(
            matches!(
                l.credit_test(A, CB, 1),
                Err(LedgerError::Overpayment { .. })
            ),
            "with nothing owed, a cheque cannot clear the overshoot"
        );
        // Only releasing does.
        for _ in 0..20 {
            l.release(A, 1000);
        }
        assert_eq!(l.outstanding(&A), 0);
    }

    /// Releasing an unused reservation must leave no residue at all — this
    /// is what every early-return path now does via `Drop`.
    #[test]
    fn releasing_an_unused_reservation_leaves_nothing_behind() {
        let mut l = Ledger::ephemeral();
        let adm = l.reserve(A, 4096, 100_000);
        l.release(A, adm.reserved_plur);
        assert_eq!(l.outstanding(&A), 0);
        assert_eq!(l.live_reservations(), 0, "and frees its shed-cap slot");
    }

    /// Committing zero bytes is equivalent to releasing: a POST that
    /// admitted nothing owes nothing and holds nothing.
    #[test]
    fn committing_nothing_is_equivalent_to_releasing() {
        let mut l = Ledger::ephemeral();
        let adm = l.reserve(A, 4096, 100_000);
        l.commit(A, adm.reserved_plur, 0);
        assert_eq!(l.outstanding(&A), 0);
        assert_eq!(l.live_reservations(), 0);
    }
}

#[cfg(test)]
impl Ledger {
    /// Test shim: cheques in unit tests carry a dummy signature, since the
    /// ledger never inspects it — only `hoverfly cashout` does.
    fn credit_test(
        &mut self,
        account: [u8; 20],
        chequebook: [u8; 20],
        cumulative_plur: u128,
    ) -> Result<u128, LedgerError> {
        let mut sig = [0u8; 65];
        sig[64] = 27;
        self.credit(account, chequebook, cumulative_plur, sig)
    }
}
