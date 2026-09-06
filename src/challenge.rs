//! Admission challenge for metered relay — `docs/pusher-incentives.md` §7.2.
//!
//! A challenge is a **capability**. Holding one proves the relay already
//! resolved the batch's standing on-chain and already priced its credit
//! line, so `/v1/push` admission reads no chain state at all — which is the
//! whole reason the design can afford to check standing before accepting a
//! body (§7.2's amplification argument).
//!
//! It is stateless: the relay keeps no table of issued nonces, so a free
//! `GET /v1/challenge` cannot exhaust memory. The nonce is a MAC over the
//! fields it authorises, and the fields travel back with the request.
//!
//! Two independent checks run at admission, and conflating them is the
//! easiest way to get this wrong:
//!
//! 1. **The relay's MAC over the nonce** proves *this relay* issued the
//!    capability, with these exact fields. Symmetric, no RPC.
//! 2. **The client's EIP-712 signature** over the same fields proves the
//!    caller holds the account key — and, because `origin` is inside the
//!    signed struct, that it signed for *this* relay. That is what stops a
//!    signature gathered during a normal upload through relay A being
//!    replayed at relay B alongside the victim's harvested stamps (§11.1).
//!
//! Check 2 is only worth anything if `origin` is compared against a
//! **configured** hostname. Comparing it to the request's `Host` header
//! compares one attacker-supplied value to another and silently restores
//! the replay — see [`verify`].

use sha3::{Digest, Keccak256};

/// Domain tag, fixed 28 bytes. First field after the secret so no other
/// scheme using the same key can collide with this one.
pub const DOMAIN_TAG: &[u8; 28] = b"hoverfly-pusher-challenge-v1";

/// Default lifetime of a challenge (§7.2). Short on purpose: re-issuing
/// costs one local ecrecover, and a narrow window shrinks the replay
/// surface to near nothing.
pub const CHALLENGE_TTL_SECS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeFields {
    pub account: [u8; 20],
    pub batch: [u8; 32],
    /// The host the client dialled. Compared against configuration, never
    /// against a request header.
    pub origin: String,
    pub expiry_unix: u64,
    /// The credit line §10.3 granted this batch, in PLUR. Inside the MAC so
    /// a client cannot present a nonce issued for a rich batch alongside a
    /// cheap one's id.
    pub cap_plur: u128,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChallengeError {
    #[error("challenge nonce is not ours")]
    BadMac,
    #[error("challenge expired {0}s ago")]
    Expired(u64),
    #[error("challenge origin {got:?} is not this relay ({want:?})")]
    OriginMismatch { got: String, want: String },
    #[error("challenge origin is empty")]
    EmptyOrigin,
    #[error("origin too long: {0} bytes (max 65535)")]
    OriginTooLong(usize),
}

/// Bytes the MAC covers.
///
/// **Fixed-width and length-prefixed, not a concatenation.** `origin` is
/// variable-length, so a bare `A ‖ B ‖ origin ‖ …` makes `("host.a", "bc")`
/// and `("host.ab", "c")` share a preimage — a relay serving several
/// hostnames would issue one nonce valid for two of them. Every fixed field
/// comes first at a known width, then a 2-byte length, then `origin` last.
pub fn preimage(f: &ChallengeFields) -> Result<Vec<u8>, ChallengeError> {
    if f.origin.is_empty() {
        return Err(ChallengeError::EmptyOrigin);
    }
    let olen = f.origin.len();
    if olen > u16::MAX as usize {
        return Err(ChallengeError::OriginTooLong(olen));
    }
    let mut out = Vec::with_capacity(28 + 20 + 32 + 8 + 16 + 2 + olen);
    out.extend_from_slice(DOMAIN_TAG);
    out.extend_from_slice(&f.account);
    out.extend_from_slice(&f.batch);
    out.extend_from_slice(&f.expiry_unix.to_be_bytes());
    out.extend_from_slice(&f.cap_plur.to_be_bytes());
    out.extend_from_slice(&(olen as u16).to_be_bytes());
    out.extend_from_slice(f.origin.as_bytes());
    Ok(out)
}

/// `keccak256(secret ‖ preimage)`.
///
/// A prefix-MAC rather than HMAC, which is sound here specifically because
/// Keccak is a sponge and has no length-extension weakness — the property
/// that forces HMAC's nested construction on Merkle–Damgård hashes like
/// SHA-256. The secret is a fixed 32 bytes and every field after it is
/// fixed-width or length-prefixed, so no two distinct inputs share a
/// preimage. (This is the same reasoning KMAC is built on.)
pub fn nonce(secret: &[u8; 32], f: &ChallengeFields) -> Result<[u8; 32], ChallengeError> {
    let mut h = Keccak256::new();
    h.update(secret);
    h.update(preimage(f)?);
    Ok(h.finalize().into())
}

/// Verify a presented nonce against the fields it claims to authorise.
///
/// `origins` is the relay's **configured** hostname list (`--origin`). It
/// must never be derived from `Host` or `X-Forwarded-Host`: those are
/// supplied by the same client supplying the challenge, so comparing them
/// is a no-op that leaves §11.1's cross-relay replay wide open while
/// appearing to close it.
pub fn verify(
    secret: &[u8; 32],
    f: &ChallengeFields,
    presented: &[u8],
    now_unix: u64,
    origins: &[String],
) -> Result<(), ChallengeError> {
    if !origins.iter().any(|o| o == &f.origin) {
        return Err(ChallengeError::OriginMismatch {
            got: f.origin.clone(),
            want: origins.join(","),
        });
    }
    let want = nonce(secret, f)?;
    if !constant_time_eq(presented, &want) {
        return Err(ChallengeError::BadMac);
    }
    // Expiry last: a caller holding a valid-but-stale capability learns
    // only that it is stale, while a forged one learns nothing about which
    // field was wrong.
    if now_unix > f.expiry_unix {
        return Err(ChallengeError::Expired(now_unix - f.expiry_unix));
    }
    Ok(())
}

/// Equal-length, data-independent comparison. A byte-wise early exit on the
/// MAC would let a nonce be ground out one byte at a time, which is exactly
/// the forgery this whole construction exists to prevent.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Seconds since the Unix epoch, saturating at 0 on a clock before 1970.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---- the header, on the wire ----
//
// Both ends of the challenge need this codec: the relay issues and decodes,
// the client encodes and presents. It lives here rather than in `metered.rs`
// because `metered.rs` is the relay's state machine — reserving, billing,
// crediting — and a client that pays a relay must be buildable without it.

/// Header carrying the capability plus the client's proof it holds the
/// account key. One custom header, so the CORS preflight allow-list grows
/// by exactly one entry (§7.2's browser blocker).
pub const CHALLENGE_HEADER: &str = "x-hoverfly-challenge";

/// Cap on the header itself. The fields are fixed-width apart from
/// `origin`, so anything larger is not a challenge.
pub const MAX_CHALLENGE_HEADER: usize = 2048;

/// A capability the relay minted: the authorised fields plus our MAC over
/// them.
pub struct IssuedChallenge {
    pub fields: ChallengeFields,
    pub nonce: [u8; 32],
}

impl IssuedChallenge {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "nonce": format!("0x{}", hex::encode(self.nonce)),
            "account": format!("0x{}", hex::encode(self.fields.account)),
            "batch": format!("0x{}", hex::encode(self.fields.batch)),
            "origin": self.fields.origin,
            "expiry": self.fields.expiry_unix,
            "max_outstanding_plur": self.fields.cap_plur.to_string(),
            "expires_ms": self.fields.expiry_unix.saturating_mul(1000),
        })
    }
}

/// What the client sends back: the capability it was issued plus its
/// signature over the same fields.
pub struct PresentedChallenge {
    pub fields: ChallengeFields,
    pub nonce: [u8; 32],
    pub sig: [u8; 65],
}

impl PresentedChallenge {
    /// `base64(json)` in one header, so the CORS allow-list grows by one.
    pub fn decode(raw: &str) -> Result<Self, String> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(raw.trim())
            .map_err(|e| format!("challenge header base64: {e}"))?;
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| format!("challenge header json: {e}"))?;
        let get = |k: &str| -> Result<String, String> {
            v.get(k)
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| format!("challenge header: missing {k}"))
        };
        let fixed = |k: &str, n: usize| -> Result<Vec<u8>, String> {
            let raw = hex::decode(get(k)?.trim_start_matches("0x"))
                .map_err(|e| format!("challenge {k} hex: {e}"))?;
            if raw.len() != n {
                return Err(format!(
                    "challenge {k} must be {n} bytes, got {}",
                    raw.len()
                ));
            }
            Ok(raw)
        };
        let mut account = [0u8; 20];
        account.copy_from_slice(&fixed("account", 20)?);
        let mut batch = [0u8; 32];
        batch.copy_from_slice(&fixed("batch", 32)?);
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&fixed("nonce", 32)?);
        let mut sig = [0u8; 65];
        sig.copy_from_slice(&fixed("sig", 65)?);
        let expiry_unix = v
            .get("expiry")
            .and_then(|x| x.as_u64())
            .ok_or("challenge header: missing expiry")?;
        let cap_plur: u128 = get("max_outstanding_plur")?
            .parse()
            .map_err(|e| format!("challenge cap: {e}"))?;
        Ok(Self {
            fields: ChallengeFields {
                account,
                batch,
                origin: get("origin")?,
                expiry_unix,
                cap_plur,
            },
            nonce,
            sig,
        })
    }
}

/// Encode a challenge plus signature into the header value. Client side,
/// and used by the tests to drive the relay path end to end.
pub fn encode_challenge_header(issued: &IssuedChallenge, sig: &[u8; 65]) -> String {
    use base64::Engine;
    let body = serde_json::json!({
        "nonce": format!("0x{}", hex::encode(issued.nonce)),
        "account": format!("0x{}", hex::encode(issued.fields.account)),
        "batch": format!("0x{}", hex::encode(issued.fields.batch)),
        "origin": issued.fields.origin,
        "expiry": issued.fields.expiry_unix,
        "max_outstanding_plur": issued.fields.cap_plur.to_string(),
        "sig": format!("0x{}", hex::encode(sig)),
    });
    base64::engine::general_purpose::STANDARD.encode(body.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [7u8; 32];

    fn fields() -> ChallengeFields {
        ChallengeFields {
            account: [1u8; 20],
            batch: [2u8; 32],
            origin: "relay-a.example".into(),
            expiry_unix: 1_000_000,
            cap_plur: 62_200_000_000_000,
        }
    }

    fn origins() -> Vec<String> {
        vec!["relay-a.example".into()]
    }

    #[test]
    fn a_nonce_we_issued_verifies() {
        let f = fields();
        let n = nonce(&SECRET, &f).expect("nonce");
        verify(&SECRET, &f, &n, 999_999, &origins()).expect("must verify");
    }

    #[test]
    fn a_nonce_from_another_relays_secret_does_not() {
        let f = fields();
        let n = nonce(&[9u8; 32], &f).expect("nonce");
        assert_eq!(
            verify(&SECRET, &f, &n, 999_999, &origins()),
            Err(ChallengeError::BadMac)
        );
    }

    /// Every field is inside the MAC, so tampering with any of them after
    /// issue must fail. The `cap` case is the sharp one: without it a client
    /// could present a rich batch's credit line alongside a dust batch's id.
    #[test]
    fn every_field_is_covered_by_the_mac() {
        let f = fields();
        let n = nonce(&SECRET, &f).expect("nonce");
        let mut cases = Vec::new();

        let mut g = f.clone();
        g.account = [0xAA; 20];
        cases.push(("account", g));
        let mut g = f.clone();
        g.batch = [0xBB; 32];
        cases.push(("batch", g));
        let mut g = f.clone();
        g.expiry_unix += 1;
        cases.push(("expiry", g));
        let mut g = f.clone();
        g.cap_plur *= 1000;
        cases.push(("cap", g));

        for (what, g) in cases {
            assert_eq!(
                verify(&SECRET, &g, &n, 999_999, &origins()),
                Err(ChallengeError::BadMac),
                "{what} must be covered by the MAC"
            );
        }
    }

    /// The ambiguity the doc rejects for the client's signature and then
    /// very nearly repeated in the relay's own MAC. `("host.a","bc")` and
    /// `("host.ab","c")` must not collide.
    #[test]
    fn the_preimage_is_unambiguous_across_a_variable_length_origin() {
        let mut a = fields();
        a.origin = "host.a".into();
        let mut b = fields();
        b.origin = "host.ab".into();
        assert_ne!(
            preimage(&a).expect("a"),
            preimage(&b).expect("b"),
            "a shorter origin must not be a prefix-collision of a longer one"
        );
        assert_ne!(nonce(&SECRET, &a).unwrap(), nonce(&SECRET, &b).unwrap());
    }

    /// The origin the relay compares against is configuration. A nonce
    /// issued for another host must not verify here even though the MAC
    /// itself is intact — this is the check that stops §11.1.
    #[test]
    fn an_origin_outside_the_configured_set_is_refused() {
        let mut f = fields();
        f.origin = "relay-b.example".into();
        let n = nonce(&SECRET, &f).expect("nonce");
        let got = verify(&SECRET, &f, &n, 999_999, &origins());
        assert!(
            matches!(got, Err(ChallengeError::OriginMismatch { .. })),
            "got {got:?}"
        );
    }

    #[test]
    fn a_relay_serving_several_hostnames_accepts_each_of_them() {
        let all: Vec<String> = vec!["relay-a.example".into(), "alias.example".into()];
        for host in &all {
            let mut f = fields();
            f.origin = host.clone();
            let n = nonce(&SECRET, &f).expect("nonce");
            verify(&SECRET, &f, &n, 999_999, &all).expect("each configured host verifies");
        }
    }

    #[test]
    fn an_expired_challenge_is_refused() {
        let f = fields();
        let n = nonce(&SECRET, &f).expect("nonce");
        verify(&SECRET, &f, &n, f.expiry_unix, &origins()).expect("valid up to the instant");
        assert_eq!(
            verify(&SECRET, &f, &n, f.expiry_unix + 1, &origins()),
            Err(ChallengeError::Expired(1))
        );
    }

    #[test]
    fn a_truncated_or_padded_nonce_is_refused() {
        let f = fields();
        let n = nonce(&SECRET, &f).expect("nonce");
        assert_eq!(
            verify(&SECRET, &f, &n[..31], 1, &origins()),
            Err(ChallengeError::BadMac)
        );
        let mut long = n.to_vec();
        long.push(0);
        assert_eq!(
            verify(&SECRET, &f, &long, 1, &origins()),
            Err(ChallengeError::BadMac)
        );
        assert_eq!(
            verify(&SECRET, &f, &[], 1, &origins()),
            Err(ChallengeError::BadMac)
        );
    }

    #[test]
    fn an_empty_origin_is_rejected_rather_than_hashed() {
        let mut f = fields();
        f.origin = String::new();
        assert_eq!(preimage(&f), Err(ChallengeError::EmptyOrigin));
    }

    #[test]
    fn constant_time_eq_agrees_with_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }
}
