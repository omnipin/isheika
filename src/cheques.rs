//! Per-peer cumulative-payout state for issued SWAP cheques.
//!
//! Bee's `pkg/settlement/swap/chequestore.go::ReceiveCheque` rejects any
//! cheque whose `CumulativePayout` is **not strictly greater** than the
//! last accepted one from the same chequebook (lines 90-110 of
//! chequestore.go, roughly: `if cheque.CumulativePayout <= last accepted
//! then ErrChequeNotIncreasing`). That means we MUST persist the per-peer
//! cumulative across CLI runs — otherwise a second invocation issues
//! `CumulativePayout = base + amount` starting from 0, which is less
//! than what we already sent in run 1, and every peer rejects us.
//!
//! Persistence shape (`cheques.json`):
//!   {
//!     "version": 1,
//!     "chequebook": "0x...",      // sanity check: we don't reuse this
//!                                  // file with a different chequebook
//!     "peers": { "<overlay_hex>": "<u128 decimal>" }
//!   }
//!
//! Stored as a decimal string because JSON has no `u128` and PLUR/BZZ
//! payouts comfortably overflow `u64` (the BZZ supply is 100 M with
//! 16 decimals → 10^24, ~2^80).
//!
//! Native-only (`cfg(not(target_arch = "wasm32"))`). The wasm build
//! doesn't have a filesystem; if we ever do SWAP from a browser we'll
//! use IndexedDB or LocalStorage with the same logical shape.

#![cfg(not(target_arch = "wasm32"))]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ChequeStoreError {
    #[error("io: {0}")]
    Io(String),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("chequebook mismatch: file has {file}, runtime has {runtime}")]
    ChequebookMismatch { file: String, runtime: String },
    #[error("amount overflows u128")]
    Overflow,
    #[error("decimal parse: {0}")]
    Parse(String),
}

/// On-disk schema. Version-tagged so we can migrate later.
#[derive(Debug, Serialize, Deserialize)]
struct OnDisk {
    version: u32,
    chequebook: String,
    #[serde(default)]
    peers: BTreeMap<String, String>,
}

/// In-memory cheque-issuance state.
///
/// Cloneable + thread-safe via `Arc<Mutex<…>>` at the call site
/// (see transport.rs). The store itself is not internally locked
/// because we only mutate it from the per-session settle path, which
/// already serializes against `SessionState::settle_lock`.
#[derive(Debug, Clone)]
pub struct ChequeStore {
    chequebook: [u8; 20],
    /// `peer_overlay_hex_lowercase -> cumulative_payout_bzz_wei`.
    /// Keyed by overlay rather than Ethereum address because the
    /// only stable identity we have for a remote peer across runs
    /// is its swarm overlay. Bee re-derives our beneficiary (their
    /// Ethereum address) from the BzzAddress signature each time, so
    /// it stays stable too as long as their bee keystore doesn't
    /// rotate.
    payouts: BTreeMap<String, u128>,
    path: Option<PathBuf>,
}

impl ChequeStore {
    pub fn new(chequebook: [u8; 20]) -> Self {
        Self {
            chequebook,
            payouts: BTreeMap::new(),
            path: None,
        }
    }

    pub fn chequebook(&self) -> &[u8; 20] {
        &self.chequebook
    }

    /// Load from disk, or create a fresh empty store if the file is
    /// missing. Returns an error only if the file exists but is for a
    /// different chequebook (programmer / operator error — refuse to
    /// continue rather than overwrite live state).
    pub fn load_or_create<P: AsRef<Path>>(
        path: P,
        chequebook: [u8; 20],
    ) -> Result<Self, ChequeStoreError> {
        let path = path.as_ref().to_path_buf();
        let mut store = Self::new(chequebook);
        store.path = Some(path.clone());

        let text = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(store),
            Err(e) => return Err(ChequeStoreError::Io(e.to_string())),
        };
        let on_disk: OnDisk = serde_json::from_str(&text)?;
        let file_hex = on_disk.chequebook.trim_start_matches("0x").to_lowercase();
        let runtime_hex = hex::encode(chequebook);
        if file_hex != runtime_hex {
            return Err(ChequeStoreError::ChequebookMismatch {
                file: format!("0x{}", file_hex),
                runtime: format!("0x{}", runtime_hex),
            });
        }
        for (k, v) in on_disk.peers {
            let n: u128 = v
                .parse()
                .map_err(|e: std::num::ParseIntError| ChequeStoreError::Parse(e.to_string()))?;
            store.payouts.insert(k.to_lowercase(), n);
        }
        Ok(store)
    }

    /// Return the current cumulative payout we've sent this peer.
    pub fn cumulative(&self, peer_overlay_hex: &str) -> u128 {
        self.payouts
            .get(&peer_overlay_hex.to_lowercase())
            .copied()
            .unwrap_or(0)
    }

    /// Bump the cumulative for this peer by `delta` and return the
    /// new cumulative — this is the `CumulativePayout` to put in the
    /// cheque we're about to send. Caller is responsible for actually
    /// issuing the cheque after; if they fail to do so, the state will
    /// be inconsistent (we'll claim to have paid more than we did).
    /// That's OK — the cheque is only valuable if the peer presents
    /// it, and bee discards unwritten cheques on overlay key rotation
    /// anyway. The opposite mistake (under-reporting) would cause
    /// future cheques to bounce as `ErrChequeNotIncreasing`.
    pub fn bump_and_get(
        &mut self,
        peer_overlay_hex: &str,
        delta: u128,
    ) -> Result<u128, ChequeStoreError> {
        let key = peer_overlay_hex.to_lowercase();
        let cur = self.payouts.get(&key).copied().unwrap_or(0);
        let next = cur.checked_add(delta).ok_or(ChequeStoreError::Overflow)?;
        self.payouts.insert(key, next);
        Ok(next)
    }

    /// Atomically persist via write-rename. Cheap; the file is tiny
    /// (~50 bytes per peer we've ever paid). Called from the same
    /// `apply_log`-style flush path peers.json uses.
    pub fn save(&self) -> Result<(), ChequeStoreError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let on_disk = OnDisk {
            version: 1,
            chequebook: format!("0x{}", hex::encode(self.chequebook)),
            peers: self
                .payouts
                .iter()
                .map(|(k, v)| (k.clone(), v.to_string()))
                .collect(),
        };
        let s = serde_json::to_string_pretty(&on_disk)?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, s).map_err(|e| ChequeStoreError::Io(e.to_string()))?;
        std::fs::rename(&tmp, path).map_err(|e| ChequeStoreError::Io(e.to_string()))?;
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────
// Metered relays (docs/pusher-incentives.md §8.3)
// ──────────────────────────────────────────────────────────────────────

/// Key for a metered relay's cumulative.
///
/// **Namespaced by beneficiary, not by lane or overlay**, and deliberately
/// distinct from the bare-overlay keys the bee settlement path uses.
///
/// A cumulative is per `(chequebook, beneficiary)` — the beneficiary is what
/// `paidOut` is keyed on in the contract — while a *lane* is a URL. One
/// operator running four lane URLs behind one beneficiary EOA is the obvious
/// deployment, and keying per lane would deadlock it: lane 1 issues
/// cumulative 10, lane 2 counts from its own zero and issues 8, the relay
/// applies `ErrChequeNotIncreasing`, and the client recomputes 8 from the
/// same local counter forever. Two lanes sharing a beneficiary collapse to
/// one key here, which is exactly right — they are one settlement channel.
///
/// The overlay key stays correct for bee peers, where the overlay *is* the
/// stable cross-run identity, so the two namespaces coexist without a
/// migration.
pub fn relay_key(beneficiary: &[u8; 20]) -> String {
    format!("relay:{}", hex::encode(beneficiary))
}

impl ChequeStore {
    /// Everything promised against this chequebook, across every payee.
    ///
    /// Lanes with distinct beneficiaries are independent claims on **one**
    /// balance, so without this a cheque to the second lane silently
    /// exceeds it and bounces. Mirrors bee's `reserveTotalIssued`
    /// (`chequebook.go:163-178`) on the issuing side.
    pub fn total_issued(&self) -> u128 {
        self.payouts
            .values()
            .copied()
            .fold(0u128, u128::saturating_add)
    }

    /// Would raising `key` to `cumulative` push the total past `balance`?
    ///
    /// Checked *before* signing: an over-committed cheque is not refused by
    /// the relay, it is accepted and then fails at cashout, which looks like
    /// the relay's fault and costs the lane's trust rather than the
    /// client's.
    pub fn would_exceed_balance(&self, key: &str, cumulative: u128, balance: u128) -> bool {
        let others = self.total_issued().saturating_sub(self.cumulative(key));
        others.saturating_add(cumulative) > balance
    }

    /// Set an absolute cumulative, for payees where the client computes the
    /// running total itself (metered relays) rather than accruing deltas.
    /// Refuses to move backwards — that would produce a cheque the payee
    /// rejects as non-increasing.
    pub fn set_cumulative(&mut self, key: &str, cumulative: u128) -> Result<(), ChequeStoreError> {
        let k = key.to_lowercase();
        let cur = self.payouts.get(&k).copied().unwrap_or(0);
        if cumulative < cur {
            return Err(ChequeStoreError::Overflow);
        }
        self.payouts.insert(k, cumulative);
        Ok(())
    }
}

#[cfg(test)]
mod metered_tests {
    use super::*;

    const CB: [u8; 20] = [1u8; 20];
    const BEN_A: [u8; 20] = [0xAA; 20];
    const BEN_B: [u8; 20] = [0xBB; 20];

    /// The deployment that would otherwise deadlock: several lane URLs, one
    /// beneficiary. They must share a single running cumulative.
    #[test]
    fn two_lanes_behind_one_beneficiary_share_a_cumulative() {
        let mut s = ChequeStore::new(CB);
        let k = relay_key(&BEN_A);
        s.set_cumulative(&k, 1000).expect("lane 1 settles");
        // Lane 2, same operator, same beneficiary — must continue from 1000
        // rather than starting over at its own zero.
        assert_eq!(s.cumulative(&k), 1000);
        s.set_cumulative(&k, 1600).expect("lane 2 settles");
        assert_eq!(s.cumulative(&k), 1600);
    }

    #[test]
    fn a_cumulative_never_moves_backwards() {
        let mut s = ChequeStore::new(CB);
        let k = relay_key(&BEN_A);
        s.set_cumulative(&k, 500).expect("set");
        s.set_cumulative(&k, 400)
            .expect_err("a lower cumulative would be rejected as non-increasing");
        assert_eq!(s.cumulative(&k), 500);
    }

    /// Distinct beneficiaries are distinct channels but one balance.
    #[test]
    fn total_issued_sums_every_payee() {
        let mut s = ChequeStore::new(CB);
        s.set_cumulative(&relay_key(&BEN_A), 600).expect("a");
        s.set_cumulative(&relay_key(&BEN_B), 300).expect("b");
        // A bee peer drawing on the same chequebook counts too.
        s.bump_and_get("abc123", 100).expect("bee peer");
        assert_eq!(s.total_issued(), 1000);
    }

    #[test]
    fn over_committing_the_balance_is_caught_before_signing() {
        let mut s = ChequeStore::new(CB);
        s.set_cumulative(&relay_key(&BEN_A), 600).expect("a");
        s.set_cumulative(&relay_key(&BEN_B), 300).expect("b");
        let k = relay_key(&BEN_A);
        assert!(
            !s.would_exceed_balance(&k, 700, 1000),
            "raising A to 700 alongside B's 300 exactly fits"
        );
        assert!(
            s.would_exceed_balance(&k, 701, 1000),
            "one PLUR more does not"
        );
    }

    /// Relay and bee keys must not collide: an overlay is 32 bytes of hex
    /// and a beneficiary is 20, but the namespace makes it explicit rather
    /// than incidental.
    #[test]
    fn relay_keys_are_namespaced_away_from_bee_overlays() {
        let k = relay_key(&BEN_A);
        assert!(k.starts_with("relay:"));
        let mut s = ChequeStore::new(CB);
        s.set_cumulative(&k, 42).expect("relay");
        assert_eq!(
            s.cumulative(&hex::encode(BEN_A)),
            0,
            "a bare-hex key must not read the relay's entry"
        );
    }
}
