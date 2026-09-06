//! Client-side payment for metered lanes — `docs/pusher-incentives.md`
//! Stage 1, client half.
//!
//! Four jobs, in the order a client meets them:
//!
//! 1. **Pin the lane.** Parse and *verify* the signed quote from
//!    `/v1/status`, checking it against the identity in config rather than
//!    trusting what the lane says about itself (§7.3).
//! 2. **Get admitted.** Fetch a challenge, sign it, and carry the header on
//!    every `/v1/push` and `/v1/pay`.
//! 3. **Size the POST.** The challenge returns the credit line; a body that
//!    would exceed it is split rather than sent and refused (§7.2).
//! 4. **Settle.** Track what is owed by the same arithmetic the relay uses,
//!    and issue a cumulative cheque when it crosses `settle_every`.
//!
//! The client computes its bill from **bytes it sent**, not from anything
//! the relay reports. That is the property §8 is built on, and it is why
//! there is nothing here that verifies the relay's work: a disagreement is
//! arithmetic, visible immediately, and settled by not paying.

use crate::meter::Params;

/// A lane's signed `payment` block, after verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentQuote {
    pub beneficiary: [u8; 20],
    /// Recovered from `sig`. **This is what a client pins**, not the
    /// overlay — see [`PaymentQuote::verify`].
    pub node_eth_address: [u8; 20],
    pub overlay_nonce: [u8; 32],
    pub origin: String,
    pub chain_id: u64,
    pub params: Params,
    /// True when the relay enforces 402. Soft-mode lanes bill but serve.
    pub hard_enforcement: bool,
}

/// What a client pins in config for a lane it is willing to pay.
///
/// `PUSHER_URLS` is already a hardcoded list, so carrying two more fields
/// per entry costs nothing — and reading the beneficiary from `/v1/status`
/// at runtime instead would mean paying whoever answers the URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanePin {
    pub node_eth_address: [u8; 20],
    pub beneficiary: [u8; 20],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum QuoteError {
    #[error("quote field {0} missing or malformed")]
    Field(&'static str),
    #[error("quote signature does not verify: {0}")]
    Signature(String),
    #[error("quote signed by 0x{got} but this lane is pinned to 0x{want}")]
    WrongSigner { got: String, want: String },
    #[error("quote beneficiary 0x{got} is not the pinned 0x{want}")]
    WrongBeneficiary { got: String, want: String },
    #[error("advertised overlay does not derive from the signed identity")]
    OverlayMismatch,
    #[error("quote parameters are unusable: {0}")]
    BadParams(String),
    #[error("lane price {got} exceeds the client's ceiling {ceiling}")]
    TooExpensive { got: u128, ceiling: u128 },
}

impl PaymentQuote {
    /// Parse and verify a `/v1/status` `payment` block.
    ///
    /// `advertised_overlay` is the lane's own `overlay` field. Checking that
    /// it derives from the *signed* identity is what makes the overlay
    /// trustworthy at all: an overlay is
    /// `keccak(eth_addr ‖ network_id_LE8 ‖ nonce)`, so a signature alone
    /// yields the eth address while the nonce is neither transmitted nor
    /// derivable — which is why "pin `(url, overlay)`" was never
    /// implementable and the pin is on the address.
    pub fn verify(
        payment: &serde_json::Value,
        advertised_overlay: Option<&[u8; 32]>,
        network_id: u64,
        pin: Option<&LanePin>,
        price_ceiling_plur_per_kib: u128,
    ) -> Result<Self, QuoteError> {
        let sig_hex = payment
            .get("sig")
            .and_then(|s| s.as_str())
            .ok_or(QuoteError::Field("sig"))?;
        let sig = hex::decode(sig_hex.trim_start_matches("0x"))
            .map_err(|e| QuoteError::Signature(e.to_string()))?;

        // The relay signs the block *without* `sig`, and `serde_json`'s map
        // is a `BTreeMap`, so re-serializing after removing that one field
        // reproduces the signed bytes exactly.
        let mut unsigned = payment.clone();
        unsigned
            .as_object_mut()
            .ok_or(QuoteError::Field("payment"))?
            .remove("sig");
        let payload = unsigned.to_string();
        let node_eth_address =
            crate::signer::recover_eth_address_from_eip191(payload.as_bytes(), &sig)
                .map_err(|e| QuoteError::Signature(e.to_string()))?;

        let addr = |k: &'static str| -> Result<[u8; 20], QuoteError> {
            let s = payment
                .get(k)
                .and_then(|x| x.as_str())
                .ok_or(QuoteError::Field(k))?;
            let raw = hex::decode(s.trim_start_matches("0x")).map_err(|_| QuoteError::Field(k))?;
            <[u8; 20]>::try_from(raw.as_slice()).map_err(|_| QuoteError::Field(k))
        };
        let plur = |k: &'static str| -> Result<u128, QuoteError> {
            payment
                .get(k)
                .and_then(|x| x.as_str())
                .and_then(|s| s.parse().ok())
                .ok_or(QuoteError::Field(k))
        };

        let beneficiary = addr("beneficiary")?;
        let claimed_node = addr("node_eth_address")?;
        if claimed_node != node_eth_address {
            return Err(QuoteError::WrongSigner {
                got: hex::encode(node_eth_address),
                want: hex::encode(claimed_node),
            });
        }
        let overlay_nonce = {
            let s = payment
                .get("overlay_nonce")
                .and_then(|x| x.as_str())
                .ok_or(QuoteError::Field("overlay_nonce"))?;
            let raw = hex::decode(s.trim_start_matches("0x"))
                .map_err(|_| QuoteError::Field("overlay_nonce"))?;
            <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| QuoteError::Field("overlay_nonce"))?
        };

        // Pinning is the actual root of trust (§2): the lane URL over HTTPS
        // plus an identity the client already knew.
        if let Some(pin) = pin {
            if pin.node_eth_address != node_eth_address {
                return Err(QuoteError::WrongSigner {
                    got: hex::encode(node_eth_address),
                    want: hex::encode(pin.node_eth_address),
                });
            }
            if pin.beneficiary != beneficiary {
                return Err(QuoteError::WrongBeneficiary {
                    got: hex::encode(beneficiary),
                    want: hex::encode(pin.beneficiary),
                });
            }
        }

        if let Some(overlay) = advertised_overlay {
            let derived =
                crate::signer::derive_overlay(&node_eth_address, network_id, &overlay_nonce);
            if &derived != overlay {
                return Err(QuoteError::OverlayMismatch);
            }
        }

        let params = Params {
            price_plur_per_kib: plur("price_plur_per_kib")?,
            min_cheque_plur: plur("min_cheque_plur")?,
            settle_every_plur: plur("settle_every_plur")?,
            max_outstanding_plur: plur("max_outstanding_plur")?,
            credit_ratio: payment
                .get("credit_ratio")
                .and_then(|x| x.as_u64())
                .map(u128::from)
                .ok_or(QuoteError::Field("credit_ratio"))?,
        };
        // `quote_valid_secs` (§7.2/§11.9): how long this quote may be
        // cached. Optional for backward compat with pre-Stage-1 relays;
        // when present it must be a positive number of seconds.
        if let Some(v) = payment.get("quote_valid_secs") {
            let secs = v.as_u64().ok_or(QuoteError::Field("quote_valid_secs"))?;
            if secs == 0 {
                return Err(QuoteError::Field("quote_valid_secs"));
            }
        }
        // A lane whose parameters violate §10.1's invariant would brick this
        // client, so refuse it here rather than discovering it at the first
        // 402 with no cheque able to clear it.
        params.validate().map_err(QuoteError::BadParams)?;
        if params.price_plur_per_kib > price_ceiling_plur_per_kib {
            return Err(QuoteError::TooExpensive {
                got: params.price_plur_per_kib,
                ceiling: price_ceiling_plur_per_kib,
            });
        }

        Ok(Self {
            beneficiary,
            node_eth_address,
            overlay_nonce,
            origin: payment
                .get("origin")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string(),
            chain_id: payment
                .get("chain_id")
                .and_then(|x| x.as_u64())
                .ok_or(QuoteError::Field("chain_id"))?,
            params,
            hard_enforcement: payment.get("enforcement").and_then(|x| x.as_str()) == Some("hard"),
        })
    }
}

/// A challenge the relay issued, ready to sign.
#[derive(Debug, Clone)]
pub struct OfferedChallenge {
    pub nonce: [u8; 32],
    pub account: [u8; 20],
    pub batch: [u8; 32],
    pub origin: String,
    pub expiry_unix: u64,
    pub cap_plur: u128,
}

impl OfferedChallenge {
    pub fn parse(v: &serde_json::Value) -> Result<Self, String> {
        let fixed = |k: &str, n: usize| -> Result<Vec<u8>, String> {
            let s = v
                .get(k)
                .and_then(|x| x.as_str())
                .ok_or_else(|| format!("challenge: missing {k}"))?;
            let raw = hex::decode(s.trim_start_matches("0x"))
                .map_err(|e| format!("challenge {k}: {e}"))?;
            if raw.len() != n {
                return Err(format!("challenge {k}: want {n} bytes, got {}", raw.len()));
            }
            Ok(raw)
        };
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&fixed("nonce", 32)?);
        let mut account = [0u8; 20];
        account.copy_from_slice(&fixed("account", 20)?);
        let mut batch = [0u8; 32];
        batch.copy_from_slice(&fixed("batch", 32)?);
        Ok(Self {
            nonce,
            account,
            batch,
            origin: v
                .get("origin")
                .and_then(|x| x.as_str())
                .ok_or("challenge: missing origin")?
                .to_string(),
            expiry_unix: v
                .get("expiry")
                .and_then(|x| x.as_u64())
                .ok_or("challenge: missing expiry")?,
            cap_plur: v
                .get("max_outstanding_plur")
                .and_then(|x| x.as_str())
                .and_then(|s| s.parse().ok())
                .ok_or("challenge: missing max_outstanding_plur")?,
        })
    }

    /// Sign it and produce the header value.
    ///
    /// Signing binds `origin`, which is what makes this header useless at
    /// any other relay even if it is observed in flight (§11.1).
    pub fn sign(
        &self,
        signer: &crate::signer::SwarmSigner,
        chain_id: u64,
    ) -> Result<String, String> {
        let sol = crate::signer::PushChallenge {
            nonce: alloy_primitives::B256::from(self.nonce),
            origin: self.origin.clone(),
            account: alloy_primitives::Address::from(self.account),
            batchId: alloy_primitives::B256::from(self.batch),
            expiry: alloy_primitives::U256::from(self.expiry_unix),
        };
        let sig = signer
            .sign_push_challenge(&sol, chain_id)
            .map_err(|e| e.to_string())?;
        let issued = crate::challenge::IssuedChallenge {
            fields: crate::challenge::ChallengeFields {
                account: self.account,
                batch: self.batch,
                origin: self.origin.clone(),
                expiry_unix: self.expiry_unix,
                cap_plur: self.cap_plur,
            },
            nonce: self.nonce,
        };
        Ok(crate::challenge::encode_challenge_header(&issued, &sig))
    }

    /// Re-fetch before this, rather than racing the expiry with a POST in
    /// flight. A challenge is cheap; a mid-upload 401 is not.
    pub fn stale_after(&self) -> u64 {
        self.expiry_unix.saturating_sub(30)
    }
}

/// Per-lane running total, tracked by the client from bytes it sent.
#[derive(Debug, Clone)]
pub struct LaneAccount {
    pub params: Params,
    pub beneficiary: [u8; 20],
    /// Billed and not yet covered by a cheque.
    owed_plur: u128,
    /// Dispatched but not yet answered. Mirrors the relay's `reserved`:
    /// bytes on the wire are not yet a debt, because the relay bills what
    /// it *admits*, and a POST it refuses (402) or drops costs nothing.
    /// Counting these as owed made the client sign cheques for several
    /// times what the relay had booked.
    pending_plur: u128,
    /// Total already promised to this beneficiary. Cheques are cumulative,
    /// so this only grows.
    cumulative_plur: u128,
    /// This account's credit line, once a challenge has reported one.
    /// §10.1's thresholds are resolved against it — see
    /// [`Params::effective`] — because the configured floor can sit above
    /// everything a small batch is able to owe.
    cap_plur: u128,
}

impl LaneAccount {
    pub fn new(params: Params, beneficiary: [u8; 20]) -> Self {
        Self {
            params,
            beneficiary,
            owed_plur: 0,
            pending_plur: 0,
            cumulative_plur: 0,
            cap_plur: 0,
        }
    }

    /// Restore the cumulative from the on-disk store, so a second CLI run
    /// does not issue a cheque the relay rejects as non-increasing.
    pub fn with_cumulative(mut self, cumulative_plur: u128) -> Self {
        self.cumulative_plur = cumulative_plur;
        self
    }

    /// Advance the cumulative to a larger value observed in the shared
    /// store (another lane sharing this beneficiary settled first).
    /// Monotonic-only: never moves backwards, so it cannot produce a
    /// non-increasing cheque.
    pub fn set_cumulative_to(&mut self, cumulative_plur: u128) {
        if cumulative_plur > self.cumulative_plur {
            self.cumulative_plur = cumulative_plur;
        }
    }

    pub fn owed(&self) -> u128 {
        self.owed_plur
    }

    /// Bytes dispatched but not yet answered, priced. Not debt yet — see
    /// [`Self::adopt_relay_debt`] for why the distinction matters.
    pub fn pending(&self) -> u128 {
        self.pending_plur
    }

    /// Owed plus in-flight — the client's mirror of the relay's
    /// `owed + reserved`, and what the credit line actually binds on.
    pub fn outstanding(&self) -> u128 {
        self.owed_plur.saturating_add(self.pending_plur)
    }

    pub fn cumulative(&self) -> u128 {
        self.cumulative_plur
    }

    /// A POST is on the wire. Held as *pending*, not owed — see
    /// [`Self::pending_plur`].
    pub fn record_sent(&mut self, body_bytes: u64) {
        self.pending_plur = self
            .pending_plur
            .saturating_add(self.params.price_bytes(body_bytes));
    }

    /// A POST came back. `reached_relay` is false only when the relay
    /// refused it at admission (402) — before reading a byte, so neither
    /// side bills it. Any other outcome, *including a broken stream*, means
    /// the body arrived and the relay billed it, so we must too.
    ///
    /// This mirrors the relay's reserve→commit exactly, which is what keeps
    /// the two sides' arithmetic identical without them exchanging totals.
    pub fn record_answered(&mut self, body_bytes: u64, reached_relay: bool) {
        let price = self.params.price_bytes(body_bytes);
        self.pending_plur = self.pending_plur.saturating_sub(price);
        if reached_relay {
            self.owed_plur = self.owed_plur.saturating_add(price);
        }
    }

    /// A dedup hit costs nothing, so give it back when the ack says so
    /// (§8.2). The relay's claim only ever lowers the bill, so believing it
    /// is safe.
    pub fn refund_dedup(&mut self, body_bytes: u64) {
        self.owed_plur = self
            .owed_plur
            .saturating_sub(self.params.price_bytes(body_bytes));
    }

    /// The credit line the relay reported. Setting it is what lets the
    /// thresholds below scale down to a small batch.
    pub fn set_cap(&mut self, cap: u128) {
        self.cap_plur = cap;
    }

    /// §10.1's thresholds as they apply to this account. Falls back to the
    /// configured values before any challenge has reported a line.
    fn thresholds(&self) -> crate::meter::EffectiveParams {
        if self.cap_plur == 0 {
            return crate::meter::EffectiveParams {
                min_cheque_plur: self.params.min_cheque_plur,
                settle_every_plur: self.params.settle_every_plur,
            };
        }
        self.params.effective(self.cap_plur)
    }

    pub fn should_settle(&self) -> bool {
        self.owed_plur >= self.thresholds().settle_every_plur
    }

    /// The cumulative for the next cheque, or `None` when what is owed is
    /// still under the lane's dust floor and would be refused.
    pub fn next_cumulative(&self) -> Option<u128> {
        if self.owed_plur < self.thresholds().min_cheque_plur {
            return None;
        }
        Some(self.cumulative_plur.saturating_add(self.owed_plur))
    }

    /// Drop debt the relay will not accept. See the caller in
    /// [`LanePayer::settle`] — this is a divergence artifact, not a
    /// discount, and it can only ever move in the client's favour by
    /// removing an obligation the counterparty has already disclaimed.
    pub fn forgive_phantom_debt(&mut self) {
        self.owed_plur = 0;
    }

    /// Take the relay's figure as ours outright, in whichever direction.
    ///
    /// Only correct after it has **rejected** a cheque: nothing was issued,
    /// so there is no cumulative to be inconsistent with, and the relay has
    /// just told us what it is prepared to accept.
    ///
    /// The divergence this repairs is §7.3's ack-tail. A POST whose
    /// response stream breaks was still read, so the client bills it — but
    /// if the relay's task is cancelled before it commits, its `Admitted`
    /// guard releases the reservation and it never books those bytes. The
    /// client cannot tell the two apart from its side, so it over-counts,
    /// and every subsequent cheque is refused as an overpayment until
    /// somebody yields. The relay is the party deciding what to accept, so
    /// it yields to the relay.
    pub fn sync_relay_debt(&mut self, relay_owed: u128) {
        self.owed_plur = relay_owed;
    }

    /// Adopt a larger debt figure the relay reports for us.
    ///
    /// The mirror of [`Self::forgive_phantom_debt`], and the half that is
    /// load-bearing across *sessions*. The relay's ledger is durable and
    /// ours is not: every run ends leaving the sub-dust residual unpaid
    /// (see the final settle in `drive_pushers`), and the relay keeps
    /// counting it against the credit line while a fresh client process
    /// starts believing it owes nothing. Enough runs of that and the
    /// account is over its cap with a client that cannot compute a cheque
    /// to clear it — refused forever, having genuinely incurred the debt.
    ///
    /// `relay_owed` must be the relay's *owed*, never the `outstanding` in
    /// a 402 body: that one is quoted with the just-refused reservation
    /// already added, so adopting it over-pays by exactly the body that was
    /// turned away and the next cheque is rejected as an overpayment.
    /// Reservations are excluded for the same reason on our side — bytes
    /// still in flight are already counted in `pending_plur`, and would be
    /// billed twice when those POSTs land.
    ///
    /// Only ever raises, and only by what is not already accounted for in
    /// flight. An under-count is safe and self-correcting (the next settle
    /// picks up the rest); an over-count is a cheque the relay refuses.
    pub fn adopt_relay_debt(&mut self, relay_owed: u128) -> bool {
        // Deduct what is still on the wire. A POST the relay has finished
        // reading is already in the figure it just reported, while locally
        // it is still `pending` until its response closes — so adopting the
        // raw number and then letting `record_answered` move those same
        // bytes into `owed` counts them twice. That surfaces as a cheque
        // the relay rejects for overpayment, which jams settlement for the
        // rest of the run. Under-adopting is safe: the remainder is still
        // owed, and the next settle collects it.
        let adopt = relay_owed.saturating_sub(self.pending_plur);
        if adopt <= self.owed_plur {
            return false;
        }
        self.owed_plur = adopt;
        true
    }

    /// Call once a cheque for `cumulative` has been accepted.
    pub fn settled(&mut self, cumulative: u128) {
        let credited = cumulative.saturating_sub(self.cumulative_plur);
        self.cumulative_plur = cumulative;
        self.owed_plur = self.owed_plur.saturating_sub(credited);
    }

    /// Largest body this lane will admit right now, in bytes.
    ///
    /// The client sizes its POST to fit rather than discovering the ceiling
    /// as a 402 — which matters most for exactly the small batches §10.3
    /// exists to keep, whose whole credit line is under one full POST.
    ///
    /// Measured against `outstanding`, not `owed`: the relay reserves each
    /// body at admission, so concurrent POSTs hold credit that is not yet
    /// debt. Sizing against `owed` alone hands every in-flight POST the
    /// whole line as if it were the only one, and with several on the wire
    /// their reservations sum past the cap — the relay 402s a client that
    /// believes it has headroom, and nothing is owed that paying could
    /// clear. `has_headroom` and `would_exceed` already bind on
    /// `outstanding`; this is the same quantity.
    pub fn max_body_bytes(&self, cap_plur: u128) -> u64 {
        let headroom = cap_plur.saturating_sub(self.outstanding());
        let kib = headroom / self.params.price_plur_per_kib.max(1);
        (kib.saturating_mul(1024)).min(u64::MAX as u128) as u64
    }
}

// Aggregate exposure across beneficiaries lives in exactly one place:
// `crate::cheques::ChequeStore::{total_issued, would_exceed_balance,
// set_cumulative}` (§8.3, mirroring bee's `reserveTotalIssued`). An earlier
// cut kept a second copy here (`TotalIssued`); it drifted (`sum()` vs
// `saturating_add`) while the store was the one `pay()` actually gated on,
// so the duplicate was removed rather than kept in step.

// ──────────────────────────────────────────────────────────────────────
// The payment loop (docs/pusher-incentives.md §12)
// ──────────────────────────────────────────────────────────────────────

/// Everything the client needs to pay a metered lane.
///
/// The account key is the **batch owner's** signer — the same key that
/// stamps chunks (§6) — so a metered upload needs no extra credential and,
/// in a browser, no wallet prompt.
#[cfg(not(target_arch = "wasm32"))]
pub struct PaymentConfig {
    pub signer: crate::signer::SwarmSigner,
    pub batch: [u8; 32],
    pub chequebook: [u8; 20],
    pub chain_id: u64,
    /// Shared across lanes: N beneficiaries are N claims on **one** balance
    /// (§8.3), so the cumulative store has to be common.
    pub cheques: std::sync::Arc<std::sync::Mutex<crate::cheques::ChequeStore>>,
    /// On-chain liquid balance of the chequebook, read once at startup. A
    /// cheque that would push total issuance past this is not signed — it
    /// would be accepted and then fail at cashout, which looks like the
    /// relay's fault and costs the lane's trust rather than ours.
    pub balance_plur: u128,
    /// Pinned identities per lane URL (§2). A lane whose quote is signed by
    /// an unknown key or names an unknown beneficiary is refused rather than
    /// paid — otherwise any host answering the URL could mint its own quote
    /// and be paid. Empty means TOFU-with-warning (first-seen identity is
    /// trusted for this run but logged); callers with stable fleets should
    /// pass `--lane-pin` entries.
    pub pins: std::collections::HashMap<String, LanePin>,
}

/// Per-lane payment state: the verified quote, a cached capability, and the
/// running total.
#[cfg(not(target_arch = "wasm32"))]
pub struct LanePayer {
    pub base_url: String,
    pub quote: PaymentQuote,
    pub account: LaneAccount,
    header: Option<String>,
    header_stale_after: u64,
    cap_plur: u128,
}

#[cfg(not(target_arch = "wasm32"))]
impl LanePayer {
    pub fn new(base_url: String, quote: PaymentQuote, cumulative: u128) -> Self {
        let account = LaneAccount::new(quote.params, quote.beneficiary).with_cumulative(cumulative);
        Self {
            base_url,
            quote,
            account,
            header: None,
            header_stale_after: 0,
            cap_plur: 0,
        }
    }

    /// The credit line the relay last told us about, or 0 before the first
    /// challenge. Used to size POSTs (§7.2).
    pub fn cap_plur(&self) -> u128 {
        self.cap_plur
    }

    /// The credit line normally arrives with a challenge, which needs a
    /// relay; sizing is pure arithmetic and worth testing without one.
    #[cfg(test)]
    pub(crate) fn set_cap_for_test(&mut self, cap: u128) {
        self.cap_plur = cap;
    }

    /// Drop the cached capability so the next `header()` refetches. A 401
    /// (expired/invalid challenge, wrong origin/account/batch) means the
    /// cached header is stale — retrying it until expiry only burns lane
    /// health.
    pub fn clear_header(&mut self) {
        self.header = None;
        self.header_stale_after = 0;
    }

    /// Re-read the shared cumulative store and adopt it if another lane
    /// sharing this beneficiary settled first. Lanes behind one beneficiary
    /// are one settlement channel (§8.3): computing `next_cumulative` from
    /// a stale snapshot re-issues a cumulative the relay rejects as
    /// non-increasing, or — worse — records a lower cumulative *after* the
    /// relay accepted and jams settlement.
    pub fn sync_cumulative(&mut self, cfg: &PaymentConfig) {
        let key = crate::cheques::relay_key(&self.quote.beneficiary);
        let stored = cfg
            .cheques
            .lock()
            .expect("cheque store poisoned")
            .cumulative(&key);
        self.account.set_cumulative_to(stored);
    }

    /// Whether the credit line is known yet. `cap == 0` means no challenge
    /// has been fetched — sizing must be skipped (keep the relay's
    /// advertised ceiling), not raised to `MAX`.
    pub fn cap_known(&self) -> bool {
        self.cap_plur != 0
    }

    /// A valid challenge header, fetching and signing one if needed.
    ///
    /// Re-fetched 30 s before expiry rather than on failure: racing the
    /// expiry with a POST already in flight turns a cheap GET into a
    /// mid-upload 401.
    pub async fn header(
        &mut self,
        http: &reqwest::Client,
        cfg: &PaymentConfig,
    ) -> Result<&str, String> {
        // The relay chooses the chain in its quote; the client must not sign
        // for a different one. `--chequebook-chain-id` is the guard.
        if self.quote.chain_id != cfg.chain_id {
            return Err(format!(
                "lane {} quotes chain {} but this client pays on chain {}",
                self.base_url, self.quote.chain_id, cfg.chain_id
            ));
        }
        let now = crate::challenge::now_unix();
        if self.header.is_none() || now >= self.header_stale_after {
            let account = *cfg.signer.eth_address();
            let url = format!(
                "{}/v1/challenge?account=0x{}&batch=0x{}",
                self.base_url.trim_end_matches('/'),
                hex::encode(account),
                hex::encode(cfg.batch),
            );
            let resp = http
                .get(&url)
                .timeout(std::time::Duration::from_secs(60))
                .send()
                .await
                .map_err(|e| format!("challenge fetch: {e}"))?;
            if !resp.status().is_success() {
                let code = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(format!("challenge {code}: {}", body.trim()));
            }
            let v: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| format!("challenge json: {e}"))?;
            let offered = OfferedChallenge::parse(&v)?;
            self.cap_plur = offered.cap_plur;
            // §10.1's thresholds scale with the line, so the account needs
            // it too — see `Params::effective`.
            self.account.set_cap(offered.cap_plur);
            self.header_stale_after = offered.stale_after();
            self.header = Some(offered.sign(&cfg.signer, self.quote.chain_id)?);
        }
        Ok(self.header.as_deref().unwrap_or_default())
    }

    /// Frames per POST this lane can ever afford, ignoring current debt.
    ///
    /// This is what the scheduler needs: a body larger than the *whole*
    /// credit line can never be admitted no matter how promptly we settle,
    /// so it must never be built. Computed against a full frame and then
    /// walked down until it genuinely fits, because the relay bills a
    /// KiB-rounded body and an off-by-one here is an unfixable 402 loop.
    pub fn max_frames(&self) -> usize {
        // A zero cap is "no credit line known", i.e. an open lane — not a
        // lane that can afford nothing.
        if self.cap_plur == 0 {
            return usize::MAX;
        }
        self.frames_within(self.cap_plur)
    }

    /// Frames per POST affordable *right now*, with current debt and
    /// in-flight bytes deducted.
    ///
    /// This is what each dispatch must be sized by. Gating instead on
    /// whether a *full* POST would fit stalls the lane outright whenever
    /// the leftover debt cannot be settled: a residual under
    /// `min_cheque_plur` is unpayable by construction (§10.2), so if a
    /// full-size POST needs the whole line, no cheque can ever restore the
    /// headroom the guard is waiting for and the upload fails with chunks
    /// still pending. Observed exactly that way against a batch whose
    /// credit line had decayed to roughly one POST.
    ///
    /// Returns 0 when not even one frame fits, which is the caller's cue to
    /// settle or wait rather than to dispatch.
    pub fn affordable_frames(&self) -> usize {
        if self.cap_plur == 0 {
            return usize::MAX;
        }
        let headroom = self.cap_plur.saturating_sub(self.account.outstanding());
        let frame = crate::pushframe::MAX_FRAME_LEN as u64;
        if self.quote.params.price_bytes(frame) > headroom {
            return 0;
        }
        self.frames_within(headroom)
    }

    /// Largest frame count whose KiB-rounded body prices at or under
    /// `budget`. Estimated, then walked down until it genuinely fits: the
    /// relay bills a rounded body, and an off-by-one here is an unfixable
    /// 402 loop.
    fn frames_within(&self, budget: u128) -> usize {
        if budget == 0 {
            return 0;
        }
        let frame = crate::pushframe::MAX_FRAME_LEN as u128;
        let mut n = (budget / self.quote.params.price_plur_per_kib)
            .saturating_mul(1024)
            .checked_div(frame)
            .unwrap_or(0)
            .min(usize::MAX as u128) as usize;
        while n > 1 && self.quote.params.price_bytes(n as u64 * frame as u64) > budget {
            n -= 1;
        }
        n.max(1)
    }

    /// Is there room for a POST of any useful size right now?
    ///
    /// Checked *before* asking the scheduler for work: taking an assignment
    /// and handing it back costs the chunks a retry attempt each time, so a
    /// tight credit line would exhaust their budget and fail the upload
    /// rather than merely pausing it.
    /// One frame is the smallest thing worth dispatching, so that is what
    /// this asks about. It is *not* a licence to then send a full batch:
    /// the body is sized separately by [`Self::affordable_frames`], and the
    /// two must be read together. Asking here about a full POST instead
    /// looks safer and is not — see `affordable_frames` for the stall it
    /// causes when the leftover debt is under the dust floor.
    pub fn has_headroom(&self) -> bool {
        if self.cap_plur == 0 {
            return true;
        }
        let one_frame = self
            .quote
            .params
            .price_bytes(crate::pushframe::MAX_FRAME_LEN as u64);
        self.account.outstanding().saturating_add(one_frame) <= self.cap_plur
    }

    /// Would dispatching `body_bytes` right now exceed the credit line?
    /// The caller settles first if so, which is what keeps an upload from
    /// ever reaching its cap rather than recovering from it.
    pub fn would_exceed(&self, body_bytes: u64) -> bool {
        self.cap_plur > 0
            && self
                .account
                .outstanding()
                .saturating_add(self.quote.params.price_bytes(body_bytes))
                > self.cap_plur
    }

    /// What the relay's ledger says this account owes, from `/v1/account`.
    ///
    /// The relay is authoritative here — it is the party deciding what to
    /// accept — so this is the number both the upward reconcile and a
    /// rejected cheque correct themselves against.
    async fn relay_owed(
        &mut self,
        http: &reqwest::Client,
        cfg: &PaymentConfig,
    ) -> Result<u128, String> {
        let header = self.header(http, cfg).await?.to_string();
        let resp = http
            .get(format!(
                "{}/v1/account",
                self.base_url.trim_end_matches('/')
            ))
            .header(crate::challenge::CHALLENGE_HEADER, header)
            .timeout(std::time::Duration::from_secs(60))
            .send()
            .await
            .map_err(|e| format!("account fetch: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("account: http {}", resp.status()));
        }
        let v: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("account decode: {e}"))?;
        v.get("owed_plur")
            .and_then(|x| x.as_str())
            .ok_or("account: missing owed_plur")?
            .parse()
            .map_err(|e| format!("account: bad owed_plur: {e}"))
    }

    /// Ask the relay what it thinks we owe, and adopt the figure if it is
    /// larger than ours.
    ///
    /// Called only when a 402 arrives that our own books say we cannot pay
    /// — the deadlock in [`LaneAccount::adopt_relay_debt`]. `/v1/account`
    /// is used rather than the number in the 402 body because the body
    /// quotes `owed + reserved` *including the refused request*, which is
    /// not a payable amount.
    ///
    /// Returns whether the debt moved.
    pub async fn reconcile(
        &mut self,
        http: &reqwest::Client,
        cfg: &PaymentConfig,
    ) -> Result<bool, String> {
        let owed = self.relay_owed(http, cfg).await?;
        self.check_reported_debt(owed, cfg.balance_plur)?;
        Ok(self.account.adopt_relay_debt(owed))
    }

    /// Is a debt figure the relay reports one it could legitimately hold,
    /// and one we could pay?
    ///
    /// Split out of [`Self::reconcile`] because it is the only part of the
    /// reconcile that *decides* anything, and it should be testable without
    /// standing up a server.
    ///
    /// Two ceilings, and the tighter one binds.
    ///
    /// The first is the quote's global `max_outstanding_plur`. The relay
    /// refuses admission whenever `outstanding + reserve > cap`, and §10.3
    /// makes every per-batch cap `min(value / ratio, ceiling)` — never above
    /// the ceiling. So no debt can *legitimately* stand above it, whatever
    /// our own books say.
    ///
    /// Deliberately not the per-batch credit line, which §17.1 rejected for
    /// a reason that still holds: the line shrinks as the batch is spent
    /// down, so it can fall below debt properly incurred when the batch was
    /// worth more, and refusing on that basis preserves the very deadlock
    /// this reconcile exists to break. The ceiling is a constant of the
    /// signed quote and does not move.
    ///
    /// Why bound at all, when the relay is the one keeping the ledger: a
    /// relay is not a curated identity. It is an HTTP service the client
    /// chose and pinned (§7.3) — anyone can run one, and there is no
    /// registry to be admitted to. Pinning buys the right to trust its
    /// arithmetic *within the credit it granted*. Trusting it past that puts
    /// the entire chequebook behind one JSON field.
    fn check_reported_debt(&self, owed: u128, balance_plur: u128) -> Result<(), String> {
        let ceiling = self.quote.params.max_outstanding_plur;
        if owed > ceiling {
            return Err(format!(
                "relay claims {owed} owed, above the {ceiling} ceiling it signed \
                 — it cannot have admitted that much"
            ));
        }
        // Then what we can actually pay. `settle` enforces this exactly
        // across all lanes (§8.3); stating it here turns a confusing failure
        // at signing time into a legible one at reconcile time.
        if owed > balance_plur {
            return Err(format!(
                "relay claims {owed} owed, more than the chequebook's {balance_plur} balance"
            ));
        }
        Ok(())
    }

    /// Settle if there is enough owed to be worth a cheque.
    ///
    /// Returns the amount accepted, or `None` when nothing was owed above
    /// the lane's dust floor. Errors are the caller's cue to stop using the
    /// lane, not to retry blindly — a rejected cheque usually means the two
    /// sides disagree about the cumulative, which retrying cannot fix.
    pub async fn settle(
        &mut self,
        http: &reqwest::Client,
        cfg: &PaymentConfig,
    ) -> Result<Option<u128>, String> {
        // Another lane sharing this beneficiary may have settled first:
        // re-read the shared store so `next_cumulative` continues from the
        // true high-water mark, not a stale snapshot.
        self.sync_cumulative(cfg);
        let Some(cumulative) = self.account.next_cumulative() else {
            return Ok(None);
        };
        self.pay(http, cfg, cumulative, true).await
    }

    /// Sign and present one cheque.
    ///
    /// `correct_once` allows a single re-present against the relay's own
    /// figure when it rejects ours as an overpayment; the retry passes
    /// `false` so a relay that keeps refusing cannot loop us.
    async fn pay(
        &mut self,
        http: &reqwest::Client,
        cfg: &PaymentConfig,
        cumulative: u128,
        correct_once: bool,
    ) -> Result<Option<u128>, String> {
        if self.quote.chain_id != cfg.chain_id {
            return Err(format!(
                "lane {} quotes chain {} but this client pays on chain {}",
                self.base_url, self.quote.chain_id, cfg.chain_id
            ));
        }
        // Aggregate exposure across every beneficiary drawn on this one
        // chequebook (§8.3): the second lane's cheque is what silently
        // bounces without this.
        let key = crate::cheques::relay_key(&self.quote.beneficiary);
        {
            let store = cfg.cheques.lock().expect("cheque store poisoned");
            if store.would_exceed_balance(&key, cumulative, cfg.balance_plur) {
                return Err(format!(
                    "cheque for {cumulative} would push total issuance past the chequebook's \
                     {} balance across all lanes",
                    cfg.balance_plur
                ));
            }
        }
        let sig = cfg
            .signer
            .sign_cheque(
                &cfg.chequebook,
                &self.quote.beneficiary,
                alloy_primitives::U256::from(cumulative),
                self.quote.chain_id,
            )
            .map_err(|e| format!("sign cheque: {e}"))?;
        let body = crate::protocols::swap::encode_signed_cheque_json(
            &cfg.chequebook,
            &self.quote.beneficiary,
            alloy_primitives::U256::from(cumulative),
            &sig,
        );
        let header = self.header(http, cfg).await?.to_string();
        let resp = http
            .post(format!("{}/v1/pay", self.base_url.trim_end_matches('/')))
            .header(crate::challenge::CHALLENGE_HEADER, header)
            .header("content-type", "application/json")
            .body(body)
            .timeout(std::time::Duration::from_secs(120))
            .send()
            .await
            .map_err(|e| format!("pay: {e}"))?;
        if !resp.status().is_success() {
            let code = resp.status();
            let text = resp.text().await.unwrap_or_default();
            // The relay's ledger is authoritative for what it will accept.
            // If it says nothing is owed, our extra is an artifact — bytes
            // we charged ourselves for a POST whose completion we never
            // saw, and which the relay therefore never billed. Carrying it
            // forever would only eat our own headroom, since a cheque for
            // it is refused every time.
            if text.contains("nothing owed") {
                self.account.forgive_phantom_debt();
                return Ok(None);
            }
            // Same divergence, partial rather than total: the relay booked
            // *less* than we billed ourselves, so our cumulative overshoots
            // and it refuses. Nothing was issued, so we can simply take its
            // figure and re-present. Without this the overshoot is
            // permanent — every later cheque carries it and is refused for
            // the same reason, and the lane never settles again.
            if correct_once && text.contains("is owed") {
                let relay = self.relay_owed(http, cfg).await?;
                self.account.sync_relay_debt(relay);
                let Some(corrected) = self.account.next_cumulative() else {
                    return Ok(None);
                };
                return Box::pin(self.pay(http, cfg, corrected, false)).await;
            }
            return Err(format!("pay {code}: {}", text.trim()));
        }
        // Record the cumulative *before* trusting the reply: we have
        // certainly issued it, and under-recording is what causes the next
        // cheque to be rejected as non-increasing.
        //
        // Re-check the aggregate balance under the same lock that records:
        // the pre-sign check races a concurrent lane settling on the same
        // chequebook (both pass, sum exceeds balance, second bounces at
        // cashout). The second gate turns the race into a legible error
        // before the cheque is counted locally.
        {
            let mut store = cfg.cheques.lock().expect("cheque store poisoned");
            if store.would_exceed_balance(&key, cumulative, cfg.balance_plur) {
                return Err(format!(
                    "cheque for {cumulative} would push total issuance past the chequebook's \
                     {} balance across all lanes",
                    cfg.balance_plur
                ));
            }
            store
                .set_cumulative(&key, cumulative)
                .map_err(|e| format!("cheque store: {e}"))?;
            let _ = store.save();
        }
        self.account.settled(cumulative);
        Ok(Some(cumulative))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::SwarmSigner;

    const KEY: &str = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
    const NONCE: [u8; 32] = [0u8; 32];

    fn node() -> SwarmSigner {
        SwarmSigner::from_hex_with_nonce(KEY, &format!("0x{}", hex::encode(NONCE)), 1).expect("key")
    }

    /// Build a quote exactly the way the relay does, so the test exercises
    /// the real signed bytes rather than a hand-rolled approximation.
    fn quote_json(beneficiary: [u8; 20]) -> serde_json::Value {
        let n = node();
        let p = Params::default();
        let mut body = serde_json::json!({
            "mode": "metered",
            "enforcement": "soft",
            "beneficiary": format!("0x{}", hex::encode(beneficiary)),
            "node_eth_address": format!("0x{}", hex::encode(n.eth_address())),
            "overlay_nonce": format!("0x{}", hex::encode(NONCE)),
            "origin": "relay-a.example",
            "chain_id": 100,
            "factory": format!("0x{}", hex::encode([0u8; 20])),
            "price_plur_per_kib": p.price_plur_per_kib.to_string(),
            "min_cheque_plur": p.min_cheque_plur.to_string(),
            "settle_every_plur": p.settle_every_plur.to_string(),
            "max_outstanding_plur": p.max_outstanding_plur.to_string(),
            "credit_ratio": p.credit_ratio as u64,
            "challenge_ttl_secs": 300,
            "quote_valid_secs": 86400,
        });
        let sig = n.sign_eip191(body.to_string().as_bytes()).expect("sign");
        body["sig"] = serde_json::Value::String(format!("0x{}", hex::encode(sig)));
        body
    }

    fn ceiling() -> u128 {
        Params::default().price_plur_per_kib * 4
    }

    #[test]
    fn a_signed_quote_verifies_and_yields_the_signing_identity() {
        let q = PaymentQuote::verify(&quote_json([3u8; 20]), None, 1, None, ceiling())
            .expect("must verify");
        assert_eq!(q.node_eth_address, *node().eth_address());
        assert_eq!(q.beneficiary, [3u8; 20]);
        assert_eq!(q.params, Params::default());
        assert!(!q.hard_enforcement);
    }

    /// The reason the pin is on the address and the nonce is published:
    /// the client can now check the lane's overlay claim instead of taking
    /// it on faith.
    #[test]
    fn the_advertised_overlay_must_derive_from_the_signed_identity() {
        let good = crate::signer::derive_overlay(node().eth_address(), 1, &NONCE);
        PaymentQuote::verify(&quote_json([3u8; 20]), Some(&good), 1, None, ceiling())
            .expect("a derivable overlay verifies");
        assert_eq!(
            PaymentQuote::verify(&quote_json([3u8; 20]), Some(&[9u8; 32]), 1, None, ceiling()),
            Err(QuoteError::OverlayMismatch)
        );
    }

    /// Tampering with any signed field must break the signature — otherwise
    /// a lane could serve one price and bill another.
    #[test]
    fn tampering_with_the_quote_breaks_it() {
        for field in ["price_plur_per_kib", "beneficiary", "origin", "chain_id"] {
            let mut q = quote_json([3u8; 20]);
            q[field] = match field {
                "price_plur_per_kib" => serde_json::json!("1"),
                "beneficiary" => serde_json::json!(format!("0x{}", hex::encode([0xAAu8; 20]))),
                "origin" => serde_json::json!("evil.example"),
                _ => serde_json::json!(1u64),
            };
            assert!(
                PaymentQuote::verify(&q, None, 1, None, ceiling()).is_err(),
                "tampering with {field} must be caught"
            );
        }
    }

    /// The root of trust: an identity the client already knew, not one the
    /// lane asserts about itself.
    #[test]
    fn a_quote_from_an_unpinned_identity_is_refused() {
        let pin = LanePin {
            node_eth_address: [0xEE; 20],
            beneficiary: [3u8; 20],
        };
        let e = PaymentQuote::verify(&quote_json([3u8; 20]), None, 1, Some(&pin), ceiling())
            .expect_err("must refuse");
        assert!(matches!(e, QuoteError::WrongSigner { .. }), "got {e:?}");
    }

    /// §11.3: a correctly-signed relay advertising someone else's
    /// beneficiary must not be paid.
    #[test]
    fn a_quote_with_an_unpinned_beneficiary_is_refused() {
        let pin = LanePin {
            node_eth_address: *node().eth_address(),
            beneficiary: [3u8; 20],
        };
        let e = PaymentQuote::verify(&quote_json([0xBB; 20]), None, 1, Some(&pin), ceiling())
            .expect_err("must refuse");
        assert!(
            matches!(e, QuoteError::WrongBeneficiary { .. }),
            "got {e:?}"
        );
    }

    #[test]
    fn an_overpriced_or_bricking_lane_is_refused() {
        let e = PaymentQuote::verify(&quote_json([3u8; 20]), None, 1, None, 1)
            .expect_err("price ceiling");
        assert!(matches!(e, QuoteError::TooExpensive { .. }), "got {e:?}");

        // A lane whose dust floor exceeds its settlement window would brick
        // this client with no cheque able to clear the 402.
        let n = node();
        let mut body = quote_json([3u8; 20]);
        body["min_cheque_plur"] =
            serde_json::json!((Params::default().settle_every_plur * 87).to_string());
        let mut unsigned = body.clone();
        unsigned.as_object_mut().unwrap().remove("sig");
        let sig = n
            .sign_eip191(unsigned.to_string().as_bytes())
            .expect("sign");
        body["sig"] = serde_json::Value::String(format!("0x{}", hex::encode(sig)));
        let e = PaymentQuote::verify(&body, None, 1, None, ceiling()).expect_err("bricking lane");
        assert!(matches!(e, QuoteError::BadParams(_)), "got {e:?}");
    }

    // The only test here that needs the relay half, to prove the two ends
    // of the header agree. Everything else about paying is testable without
    // a server, which is the point of building the client half separately.
    #[test]
    #[cfg(feature = "pusher")]
    fn a_challenge_round_trips_into_a_header_the_relay_accepts() {
        use crate::ledger::Ledger;
        use crate::metered::{MeterConfig, Metered};
        let acct_signer = node();
        let account = *acct_signer.eth_address();
        let m = Metered::new(
            MeterConfig {
                origins: vec!["relay-a.example".into()],
                beneficiary: [3u8; 20],
                chain_id: 100,
                factory: alloy_primitives::Address::ZERO,
                params: Params::default(),
                hard_mode: false,
            },
            Ledger::ephemeral(),
        );
        let issued = m
            .issue(
                account,
                [7u8; 32],
                6_200_000_000_000_000_000,
                "relay-a.example",
                1000,
            )
            .expect("issue");
        // Straight through the wire form the relay actually serves.
        let offered = OfferedChallenge::parse(&issued.to_json()).expect("parse");
        let header = offered.sign(&acct_signer, 100).expect("sign");
        let v = m.verify_header(&header, 1000).expect("relay must accept");
        assert_eq!(v.account, account);
        assert_eq!(v.batch, [7u8; 32]);
    }

    #[test]
    fn owed_tracks_bytes_sent_and_a_cheque_clears_it() {
        let p = Params::default();
        let mut a = LaneAccount::new(p, [3u8; 20]);
        let body = 32 * 1024 * 1024;
        a.record_sent(body);
        a.record_answered(body, true);
        assert_eq!(a.owed(), p.price_bytes(body));
        assert!(a.should_settle(), "32 MiB crosses the settlement window");
        let c = a.next_cumulative().expect("above the dust floor");
        a.settled(c);
        assert_eq!(a.owed(), 0);
        assert_eq!(a.cumulative(), c);
    }

    /// Cheques are cumulative, so a second upload adds to the same running
    /// total rather than starting over — which is what a relay's
    /// monotonicity check requires.
    #[test]
    fn a_second_upload_grows_the_same_cumulative() {
        let p = Params::default();
        let mut a = LaneAccount::new(p, [3u8; 20]);
        a.record_sent(40 * 1024 * 1024);
        a.record_answered(40 * 1024 * 1024, true);
        let first = a.next_cumulative().expect("cheque");
        a.settled(first);
        a.record_sent(40 * 1024 * 1024);
        a.record_answered(40 * 1024 * 1024, true);
        let second = a.next_cumulative().expect("cheque");
        assert!(
            second > first,
            "cumulative must increase: {second} > {first}"
        );
        assert_eq!(second - first, p.price_bytes(40 * 1024 * 1024));
    }

    #[test]
    fn a_cumulative_restored_from_disk_keeps_increasing() {
        let p = Params::default();
        let mut a = LaneAccount::new(p, [3u8; 20]).with_cumulative(5_000_000_000_000_000);
        a.record_sent(40 * 1024 * 1024);
        a.record_answered(40 * 1024 * 1024, true);
        let c = a.next_cumulative().expect("cheque");
        assert!(
            c > 5_000_000_000_000_000,
            "a fresh run must not re-issue below what a previous run already sent"
        );
    }

    #[test]
    fn dust_owings_do_not_produce_a_cheque_the_relay_would_refuse() {
        let p = Params::default();
        let mut a = LaneAccount::new(p, [3u8; 20]);
        a.record_sent(1024);
        assert!(!a.should_settle());
        assert_eq!(a.next_cumulative(), None, "below the lane's dust floor");
    }

    /// The divergence a live run found: recording debt at dispatch made the
    /// client sign cheques for several times what the relay had booked,
    /// because a 402'd POST is never billed on the relay side.
    /// A POST whose response broke still cost the relay the bytes it read,
    /// so it must still be billed — otherwise the client silently
    /// under-pays for every interrupted stream (§7.3).
    #[test]
    fn an_interrupted_post_is_still_billed() {
        let p = Params::default();
        let mut a = LaneAccount::new(p, [3u8; 20]);
        let body = 64 * 1024;
        a.record_sent(body);
        a.record_answered(body, true); // stream broke, but the body arrived
        assert_eq!(a.owed(), p.price_bytes(body));
    }

    #[test]
    fn a_refused_post_never_becomes_debt() {
        let p = Params::default();
        let mut a = LaneAccount::new(p, [3u8; 20]);
        a.record_sent(100 * 4251);
        assert_eq!(a.owed(), 0, "in flight is not yet owed");
        assert!(a.outstanding() > 0, "but it does count against the cap");
        a.record_answered(100 * 4251, false); // 402
        assert_eq!(a.owed(), 0, "a refused POST is never billed");
        assert_eq!(a.outstanding(), 0, "and stops holding headroom");
    }

    #[test]
    fn an_accepted_post_becomes_debt_exactly_once() {
        let p = Params::default();
        let mut a = LaneAccount::new(p, [3u8; 20]);
        let body = 100 * 4251;
        a.record_sent(body);
        a.record_answered(body, true);
        assert_eq!(a.owed(), p.price_bytes(body));
        assert_eq!(a.outstanding(), a.owed(), "nothing left in flight");
    }

    /// Several POSTs dispatch before any completes; the cap must see their
    /// sum, or the client blows through it and 402s on the tail.
    #[test]
    fn concurrent_posts_all_count_against_the_cap() {
        let p = Params::default();
        let mut a = LaneAccount::new(p, [3u8; 20]);
        for _ in 0..8 {
            a.record_sent(64 * 1024);
        }
        assert_eq!(a.outstanding(), p.price_bytes(64 * 1024) * 8);
        assert_eq!(a.owed(), 0);
    }

    /// A client can charge itself for a POST whose completion it never
    /// saw; the relay never billed it, so it refuses the cheque. Carrying
    /// that debt forever would slowly eat the client's own credit line.
    #[test]
    fn phantom_debt_can_be_dropped() {
        let p = Params::default();
        let mut a = LaneAccount::new(p, [3u8; 20]);
        a.record_sent(4251);
        a.record_answered(4251, true);
        assert!(a.owed() > 0);
        a.forgive_phantom_debt();
        assert_eq!(a.owed(), 0);
        assert_eq!(a.outstanding(), 0, "and it stops holding headroom");
    }

    #[test]
    fn dedup_hits_are_refunded() {
        let p = Params::default();
        let mut a = LaneAccount::new(p, [3u8; 20]);
        a.record_sent(100 * 4251);
        a.record_answered(100 * 4251, true);
        let before = a.owed();
        a.refund_dedup(10 * 4251);
        assert!(a.owed() < before);
    }

    /// §7.2: size the POST to the credit line instead of discovering the
    /// ceiling as a 402. A dust batch gets a small but usable body.
    #[test]
    fn post_size_is_bounded_by_the_credit_line() {
        let p = Params::default();
        let a = LaneAccount::new(p, [3u8; 20]);
        let dust_cap = p.credit_line(100_000_000_000_000);
        let max = a.max_body_bytes(dust_cap);
        assert_eq!(max, 208 * 1024, "~208 KiB, matching the credit line");
        assert!(max >= 4251, "and still enough for at least one frame");
        // A rich batch is bounded by the global ceiling instead.
        let rich = a.max_body_bytes(p.max_outstanding_plur);
        assert!(rich > 512 * 4251, "a full POST fits comfortably");
    }

    /// Concurrent POSTs hold reservations on the relay before they are
    /// debt. Sizing the next body against `owed` alone gave each in-flight
    /// POST the whole line, so their reservations summed past the cap and
    /// the relay 402'd a client with nothing to pay — an unpayable refusal
    /// that only clears by waiting.
    #[test]
    fn post_size_accounts_for_bytes_already_in_flight() {
        let p = Params::default();
        let mut a = LaneAccount::new(p, [3u8; 20]);
        let cap = p.credit_line(100_000_000_000_000);
        let whole_line = a.max_body_bytes(cap);
        // Put half the line on the wire, unanswered: still pending, not owed.
        let in_flight = whole_line / 2;
        a.record_sent(in_flight);
        assert_eq!(a.owed(), 0, "in-flight bytes are not debt yet");
        let next = a.max_body_bytes(cap);
        assert!(
            next <= whole_line - in_flight,
            "sized {next} with {in_flight} already on the wire against a {whole_line} line"
        );
        // And the two together must fit, which is the property the relay
        // actually enforces.
        assert!(a.outstanding().saturating_add(p.price_bytes(next)) <= cap);
    }

    #[test]
    fn headroom_shrinks_as_debt_accrues() {
        let p = Params::default();
        let mut a = LaneAccount::new(p, [3u8; 20]);
        let cap = p.max_outstanding_plur;
        let before = a.max_body_bytes(cap);
        a.record_sent(64 * 1024 * 1024);
        a.record_answered(64 * 1024 * 1024, true);
        assert!(a.max_body_bytes(cap) < before, "unpaid debt eats the line");
    }

    /// A lane whose credit line is about one POST wide must keep making
    /// progress, in smaller POSTs.
    ///
    /// Regression: gating dispatch on whether a *full* POST fits stalled
    /// the upload outright here. The leftover debt is under
    /// `min_cheque_plur`, so it cannot be settled (§10.2) and the headroom
    /// the guard waited for could never come back — 60 of 76 chunks were
    /// left unacked against a live relay.
    /// A relay's reported debt is trusted only up to the ceiling it signed.
    ///
    /// Reconcile adopts the relay's own figure (§17.1), which is sound
    /// *within the credit it granted*: admission refuses above the cap, and
    /// every per-batch cap is `min(value / ratio, ceiling)`. Above the
    /// ceiling there is no story in which the debt was legitimately
    /// incurred, so the figure is refused rather than signed for.
    ///
    /// This matters because a relay is not a curated identity — it is an
    /// HTTP service the client pinned. Bounding only by the chequebook
    /// balance, as an earlier version did, let any lane a client pointed at
    /// name the whole balance and be paid it.
    #[test]
    fn a_relay_cannot_claim_more_debt_than_the_ceiling_it_signed() {
        let q =
            PaymentQuote::verify(&quote_json([3u8; 20]), None, 1, None, ceiling()).expect("quote");
        let cap = q.params.max_outstanding_plur;
        let payer = LanePayer::new("http://lane".into(), q, 0);
        // A chequebook far richer than the credit line, which is the normal
        // case and exactly what made the old bound useless.
        let balance = cap * 1000;

        payer
            .check_reported_debt(cap, balance)
            .expect("debt exactly at the ceiling is legitimate");
        payer
            .check_reported_debt(cap - 1, balance)
            .expect("and anything under it");

        let e = payer
            .check_reported_debt(cap + 1, balance)
            .expect_err("one PLUR above the ceiling cannot have been admitted");
        assert!(e.contains("ceiling"), "got {e}");

        let e = payer
            .check_reported_debt(balance, balance)
            .expect_err("and the whole chequebook certainly cannot");
        assert!(e.contains("ceiling"), "got {e}");
    }

    /// The balance still bounds, for a chequebook too thin to cover a
    /// legitimate debt — caught here rather than as a confusing failure at
    /// signing time.
    #[test]
    fn debt_within_the_ceiling_but_over_the_balance_is_refused() {
        let q =
            PaymentQuote::verify(&quote_json([3u8; 20]), None, 1, None, ceiling()).expect("quote");
        let cap = q.params.max_outstanding_plur;
        let payer = LanePayer::new("http://lane".into(), q, 0);

        let e = payer
            .check_reported_debt(cap, cap / 2)
            .expect_err("we cannot sign for more than the chequebook holds");
        assert!(e.contains("balance"), "got {e}");
    }

    #[test]
    fn a_line_barely_wider_than_one_post_still_makes_progress() {
        let q =
            PaymentQuote::verify(&quote_json([3u8; 20]), None, 1, None, ceiling()).expect("quote");
        let p = q.params;
        let mut payer = LanePayer::new("http://lane".into(), q, 0);

        // A line that fits one full POST and very little more — the shape a
        // batch decays into as its remaining value is spent down.
        let full_post = p.price_bytes((512 * crate::pushframe::MAX_FRAME_LEN) as u64);
        payer.set_cap_for_test(full_post + full_post / 20);

        let first = payer.affordable_frames();
        assert!(first > 0, "a fresh lane can dispatch");

        // Send one small POST and leave the debt unsettleable.
        let sent = 16 * crate::pushframe::MAX_FRAME_LEN as u64;
        payer.account.record_sent(sent);
        payer.account.record_answered(sent, true);
        assert!(payer.account.owed() > 0);
        assert!(
            payer.account.next_cumulative().is_none(),
            "this residual is below the dust floor, so no cheque can clear it"
        );

        let next = payer.affordable_frames();
        assert!(
            next > 0,
            "must still dispatch a smaller POST; a lane that can never settle \
             and never send has stalled the upload"
        );
        // And whatever it sizes must actually fit, or the relay 402s it.
        let body = p.price_bytes((next * crate::pushframe::MAX_FRAME_LEN) as u64);
        assert!(
            payer.account.outstanding().saturating_add(body) <= payer.cap_plur(),
            "sized {next} frames but that does not fit the remaining line"
        );
    }

    /// The relay's ledger outlives the client's. Every run ends leaving the
    /// sub-dust residual unpaid, and a fresh process starts believing it
    /// owes nothing — so the relay refuses service for debt the client
    /// cannot compute a cheque for. Adopting the relay's figure is the only
    /// way out, and it is what the 402 recovery path does.
    #[test]
    fn carried_debt_from_a_previous_run_is_adoptable() {
        let p = Params::default();
        let mut a = LaneAccount::new(p, [3u8; 20]);
        // Fresh process: no debt, and nothing to pay with.
        assert_eq!(a.owed(), 0);
        assert_eq!(
            a.next_cumulative(),
            None,
            "cannot pay what it does not know"
        );

        let carried = p.min_cheque_plur * 3;
        assert!(a.adopt_relay_debt(carried), "relay knows more than we do");
        assert_eq!(a.owed(), carried);
        assert_eq!(
            a.next_cumulative(),
            Some(carried),
            "now a cheque clears the refusal"
        );
    }

    /// §7.3's ack-tail leaves the two sides disagreeing in the *other*
    /// direction, and the client must yield.
    ///
    /// A POST whose response stream breaks was still read, so the client
    /// bills it — but if the relay's task is cancelled before it commits,
    /// the `Admitted` guard releases the reservation and it books nothing.
    /// The overshoot then rides on every later cheque, each refused for the
    /// same reason, and the lane never settles again. Seen over a real
    /// proxy: `credits 212640000000 but only 148800000000 is owed`.
    #[test]
    fn a_relay_that_booked_less_than_we_billed_is_taken_at_its_word() {
        let p = Params::default();
        let mut a = LaneAccount::new(p, [3u8; 20]);
        // Large enough that both figures clear the dust floor, so the
        // assertion is about the correction and not about §10.2.
        let sent = 16 * 1024 * 1024u64;
        a.record_sent(sent);
        a.record_answered(sent, true);
        let ours = a.owed();
        assert!(ours > p.min_cheque_plur);

        // The relay booked less than we billed ourselves.
        let theirs = ours - p.price_bytes(133 * 1024);
        assert!(theirs > p.min_cheque_plur);
        a.sync_relay_debt(theirs);
        assert_eq!(a.owed(), theirs, "the relay decides what it will accept");
        assert_eq!(
            a.next_cumulative(),
            Some(theirs),
            "and the corrected cheque is exactly its figure"
        );
    }

    /// Reconciling mid-flight must not bill the same POST twice.
    ///
    /// Regression: the relay finishes reading a body and books it, so its
    /// reported `owed` already covers a POST the client still has in
    /// `pending`. Adopting that figure raw and then letting
    /// `record_answered` move the same bytes into `owed` over-counted by
    /// one POST, and the run ended with `cheque credits 535680000000 but
    /// only 510240000000 is owed` — settlement jammed for the rest of it.
    #[test]
    fn adopting_relay_debt_does_not_double_count_bytes_in_flight() {
        let p = Params::default();
        let mut a = LaneAccount::new(p, [3u8; 20]);

        let body = 64 * 1024u64;
        let priced = p.price_bytes(body);
        a.record_sent(body);
        assert_eq!(a.pending(), priced, "on the wire, not yet debt");

        // The relay has read that body and reports it as owed, while our
        // response has not closed yet.
        a.adopt_relay_debt(priced);
        // Now it closes.
        a.record_answered(body, true);

        assert_eq!(
            a.owed(),
            priced,
            "billed once, not twice: adopted {priced} then answered the same body"
        );
    }

    /// Only ever upward. The downward direction is `forgive_phantom_debt`,
    /// which is reached from a rejected cheque — a relay reporting *less*
    /// than we think must not silently shrink a debt we are still liable
    /// for, and an over-count is a cheque the relay refuses outright.
    #[test]
    fn adopting_relay_debt_never_lowers_our_own() {
        let p = Params::default();
        let mut a = LaneAccount::new(p, [3u8; 20]);
        a.record_sent(1024 * 1024);
        a.record_answered(1024 * 1024, true);
        let owed = a.owed();
        assert!(owed > 0);

        assert_eq!(a.pending(), 0, "nothing in flight, so nothing to deduct");
        assert!(!a.adopt_relay_debt(owed - 1), "a smaller figure is ignored");
        assert_eq!(a.owed(), owed);
        assert!(!a.adopt_relay_debt(0), "and zero especially so");
        assert_eq!(a.owed(), owed);
        assert!(a.adopt_relay_debt(owed + 1), "larger still wins");
        assert_eq!(a.owed(), owed + 1);
    }

    // N-lanes-one-balance aggregation is covered where it lives:
    // `cheques::metered_tests::{total_issued_sums_every_payee,
    // over_committing_the_balance_is_caught_before_signing,
    // a_cumulative_never_moves_backwards}`.
}
