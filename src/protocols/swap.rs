//! Bee SWAP protocol — `/swarm/swap/1.0.0/swap`.
//!
//! Wire-compatible with bee's `pkg/settlement/swap/swapprotocol`. Two
//! exchanges over libp2p-stream:
//!
//! 1. **Per-connection handshake** (bee triggers via `ConnectIn`/`ConnectOut`
//!    in `swapprotocol.go::Protocol()`). We open a `swap` substream
//!    and send `Handshake { Beneficiary: our_eth_address }`. Bee stores
//!    that as our beneficiary so it can later validate cheques drawn
//!    against our chequebook. We send empty headers first per the
//!    bee p2p protocol framework convention (`headers.go::sendHeaders`).
//!
//! 2. **Per-cheque emit** (we initiate via the `EmitCheque` stream
//!    every time accrued PLUR-debt warrants a monetary settlement).
//!    Sequence:
//!      a. Open new substream on the same connection.
//!      b. Write our empty `Headers`.
//!      c. Read bee's `Headers` — these carry `exchange` (PLUR-per-BZZ
//!         rate) and `deduction` keys, sourced from bee's on-chain
//!         priceoracle poll (see `swapprotocol.go::headler` at line 148).
//!      d. Write `EmitCheque { Cheque: json(SignedCheque) }`.
//!      e. No response. Bee closes the stream on success or resets it
//!         on validation failure.
//!
//! Bee's `ReceiveCheque` (`chequestore.go::ReceiveCheque`) performs an
//! on-chain `chequebook.issuer()` + `balance()` + `paidOut(beneficiary)`
//! triplet of RPC calls for every cheque, so the perceived latency of
//! a single cheque can be hundreds of ms. The integration in
//! `transport.rs` runs cheque emission off the dispatch path so it
//! doesn't block in-flight pushes.

use crate::proto::headers as hdr;
use crate::proto::swap as pb;
use crate::protocols::framing::{FrameError, read_message, write_message};
use alloy_primitives::U256;
use thiserror::Error;

pub const PROTOCOL: &str = "/swarm/swap/1.0.0/swap";

/// Per-stream header key names — must match bee verbatim
/// (`pkg/settlement/swap/headers/utilities.go`).
const HDR_EXCHANGE: &str = "exchange";
const HDR_DEDUCTION: &str = "deduction";

#[derive(Debug, Error)]
pub enum SwapError {
    #[error("frame: {0}")]
    Frame(#[from] FrameError),
    #[error("missing exchange header — bee priceoracle not yet warm or peer is non-paying")]
    NoExchangeRate,
    #[error("missing deduction header")]
    NoDeduction,
    #[error("json encode: {0}")]
    Json(String),
    #[error("amount overflows u256")]
    Overflow,
}

/// Decoded swap-stream headers.
#[derive(Debug, Clone)]
pub struct SettlementRates {
    /// PLUR-per-BZZ-wei exchange rate, set by bee's on-chain priceoracle.
    /// To convert a PLUR amount to BZZ-wei: `bzz = plur * exchange + deduction`.
    /// (Bee uses the same formula on the receive side in
    /// `chequestore.go:139` after subtracting deduction.)
    pub exchange_rate: U256,
    /// Per-cheque additive deduction (BZZ-wei). Usually 0 unless a peer
    /// is on the new-peer ramp.
    pub deduction: U256,
}

/// Hand-encoded JSON for `chequebook.SignedCheque` because Go's
/// `encoding/json` emits `*big.Int` as a **bare JSON number**, not a
/// string — and `CumulativePayout` is u256, which serde-json's number
/// type can't hold without losing precision. We bypass serde and
/// produce the exact bytes Go would emit, byte-for-byte, so bee's
/// `json.Unmarshal(req.Cheque, &signedCheque)` round-trips.
///
/// Field names are PascalCase to match the Go struct tag defaults
/// for `chequebook.SignedCheque` and its embedded `Cheque`. Go's
/// `Address.MarshalJSON` quotes the hex (with 0x prefix); `[]byte`
/// (the Signature field) is JSON-encoded as base64 standard encoding
/// by `encoding/json`.
pub fn encode_signed_cheque_json(
    chequebook: &[u8; 20],
    beneficiary: &[u8; 20],
    cumulative_payout: U256,
    signature: &[u8; 65],
) -> Vec<u8> {
    use base64::Engine;
    let cb_hex = hex::encode(chequebook);
    let bn_hex = hex::encode(beneficiary);
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature);
    let cumulative = cumulative_payout.to_string();
    // Go's `common.Address.MarshalJSON` emits the EIP-55 checksummed
    // form, but bee's decoder accepts any-case hex via `common.HexToAddress`
    // (and `UnmarshalJSON` on `common.Address` is case-insensitive).
    // We emit lowercase for simplicity; signature recovery is on the
    // typed-data hash, not on this JSON, so casing is irrelevant to
    // signature validity.
    format!(
        "{{\"Chequebook\":\"0x{cb_hex}\",\"Beneficiary\":\"0x{bn_hex}\",\
         \"CumulativePayout\":{cumulative},\"Signature\":\"{sig_b64}\"}}"
    )
    .into_bytes()
}

/// Outbound `Handshake { Beneficiary }`. Called once per session by
/// the connection-setup path. Caller exchanges empty headers first.
pub async fn send_handshake<S>(stream: &mut S, beneficiary: &[u8; 20]) -> Result<(), SwapError>
where
    S: futures::AsyncRead + futures::AsyncWrite + Unpin,
{
    // Headers framework preamble (bee opens streams expecting this).
    write_message(stream, &hdr::Headers { headers: vec![] }).await?;
    let _: hdr::Headers = read_message(stream).await?;

    let msg = pb::Handshake {
        beneficiary: beneficiary.to_vec(),
    };
    write_message(stream, &msg).await?;
    Ok(())
}

/// Open the `EmitCheque` exchange: write empty headers, read bee's
/// headers (with exchange rate + deduction), and return them so the
/// caller can compute the BZZ-wei amount for the cheque it's about
/// to sign and send.
pub async fn read_settlement_rates<S>(stream: &mut S) -> Result<SettlementRates, SwapError>
where
    S: futures::AsyncRead + futures::AsyncWrite + Unpin,
{
    write_message(stream, &hdr::Headers { headers: vec![] }).await?;
    let resp: hdr::Headers = read_message(stream).await?;

    let mut exchange: Option<U256> = None;
    let mut deduction: Option<U256> = None;
    for h in resp.headers {
        // Bee uses `big.Int.Bytes()` for serialization (big-endian,
        // minimum number of bytes, no leading zeros). U256::from_be_slice
        // accepts variable-length input as long as it's <= 32 bytes.
        if h.key == HDR_EXCHANGE {
            if h.value.len() > 32 {
                return Err(SwapError::Overflow);
            }
            exchange = Some(U256::from_be_slice(&h.value));
        } else if h.key == HDR_DEDUCTION {
            if h.value.len() > 32 {
                return Err(SwapError::Overflow);
            }
            deduction = Some(U256::from_be_slice(&h.value));
        }
    }
    let Some(exchange_rate) = exchange else {
        return Err(SwapError::NoExchangeRate);
    };
    let deduction = deduction.unwrap_or(U256::ZERO);
    Ok(SettlementRates {
        exchange_rate,
        deduction,
    })
}

/// Encode and send the cheque message. Stream is consumed by the
/// caller via drop after this returns (we don't read a response —
/// bee's handler closes on success, resets on failure).
pub async fn emit_cheque<S>(
    stream: &mut S,
    chequebook: &[u8; 20],
    beneficiary: &[u8; 20],
    cumulative_payout: U256,
    signature: &[u8; 65],
) -> Result<(), SwapError>
where
    S: futures::AsyncWrite + Unpin,
{
    let json = encode_signed_cheque_json(chequebook, beneficiary, cumulative_payout, signature);
    let msg = pb::EmitCheque { cheque: json };
    write_message(stream, &msg).await?;
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────
// Inbound cheques (metered relay — docs/pusher-incentives.md Stage 1)
// ──────────────────────────────────────────────────────────────────────

/// A cheque as it arrives at `POST /v1/pay`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCheque {
    pub chequebook: [u8; 20],
    pub beneficiary: [u8; 20],
    pub cumulative_payout: U256,
    pub signature: [u8; 65],
}

/// Largest body we will even look at. A cheque is ~250 bytes; anything
/// bigger is not one, and scanning it is work an unauthenticated caller
/// should not be able to buy (§11.6).
pub const MAX_CHEQUE_JSON: usize = 4096;

/// Decode the JSON `encode_signed_cheque_json` produces — and that bee's
/// `json.Marshal(SignedCheque)` produces, which is the same bytes.
///
/// `CumulativePayout` is extracted from the raw input rather than through
/// `serde_json`, for the same reason the encoder is hand-written: Go emits
/// `*big.Int` as a **bare JSON number**, and `serde_json` without
/// `arbitrary_precision` silently widens anything past `u64` into `f64`.
/// A cheque for 10^20 PLUR would round to a different number and still
/// parse, so the relay would credit an amount the signature does not cover
/// and the recovered issuer would be garbage. Losing precision here is not
/// a rounding bug, it is a money bug.
pub fn decode_signed_cheque_json(bytes: &[u8]) -> Result<SignedCheque, SwapError> {
    if bytes.len() > MAX_CHEQUE_JSON {
        return Err(SwapError::Json(format!(
            "cheque body too large: {} bytes (max {MAX_CHEQUE_JSON})",
            bytes.len()
        )));
    }
    let v: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| SwapError::Json(e.to_string()))?;

    let chequebook = json_address(&v, "Chequebook")?;
    let beneficiary = json_address(&v, "Beneficiary")?;
    let cumulative_payout = extract_cumulative(bytes)?;

    let sig_b64 = v
        .get("Signature")
        .and_then(|s| s.as_str())
        .ok_or_else(|| SwapError::Json("missing Signature".into()))?;
    let sig_bytes = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .map_err(|e| SwapError::Json(format!("Signature base64: {e}")))?
    };
    // Canonical form is checked *here*, at the only place every cheque
    // passes through, rather than left to each caller. A high-`s` or
    // `v ∈ {0,1}` cheque recovers fine off-chain and reverts at cashout
    // (§11.6), so accepting one means giving away service for a signature
    // that can never be redeemed.
    crate::signer::check_canonical_signature(&sig_bytes)
        .map_err(|e| SwapError::Json(e.to_string()))?;
    let mut signature = [0u8; 65];
    signature.copy_from_slice(&sig_bytes);

    Ok(SignedCheque {
        chequebook,
        beneficiary,
        cumulative_payout,
        signature,
    })
}

fn json_address(v: &serde_json::Value, field: &str) -> Result<[u8; 20], SwapError> {
    let s = v
        .get(field)
        .and_then(|x| x.as_str())
        .ok_or_else(|| SwapError::Json(format!("missing {field}")))?;
    let hex_str = s.trim_start_matches("0x").trim_start_matches("0X");
    let raw = hex::decode(hex_str).map_err(|e| SwapError::Json(format!("{field} not hex: {e}")))?;
    if raw.len() != 20 {
        return Err(SwapError::Json(format!(
            "{field} must be 20 bytes, got {}",
            raw.len()
        )));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Pull `CumulativePayout`'s digits straight out of the input.
///
/// Rejects a repeated key rather than picking one: duplicate keys are legal
/// JSON and `serde_json` keeps the last, so if the scan and the parser
/// disagreed about which one counts, an attacker could show the relay one
/// amount and the signature check another.
fn extract_cumulative(bytes: &[u8]) -> Result<U256, SwapError> {
    const KEY: &[u8] = b"\"CumulativePayout\"";
    let mut hits = bytes
        .windows(KEY.len())
        .enumerate()
        .filter(|(_, w)| *w == KEY)
        .map(|(i, _)| i);
    let at = hits
        .next()
        .ok_or_else(|| SwapError::Json("missing CumulativePayout".into()))?;
    if hits.next().is_some() {
        return Err(SwapError::Json("duplicate CumulativePayout key".into()));
    }
    let mut i = at + KEY.len();
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b':' {
        return Err(SwapError::Json("CumulativePayout is not a field".into()));
    }
    i += 1;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    let start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if start == i {
        return Err(SwapError::Json(
            "CumulativePayout must be a bare JSON integer, as Go emits it".into(),
        ));
    }
    let digits = std::str::from_utf8(&bytes[start..i])
        .map_err(|e| SwapError::Json(format!("CumulativePayout utf8: {e}")))?;
    // `123e5` / `123.45` are valid JSON numbers but not bare integers: the
    // scan above stops at the first non-digit, so require a value terminator
    // to avoid crediting a prefix of what a JSON auditor reads.
    if i < bytes.len() && !(bytes[i] == b',' || bytes[i] == b'}' || bytes[i].is_ascii_whitespace())
    {
        return Err(SwapError::Json(
            "CumulativePayout must be a bare JSON integer, as Go emits it".into(),
        ));
    }
    U256::from_str_radix(digits, 10)
        .map_err(|e| SwapError::Json(format!("CumulativePayout overflows u256: {e}")))
}

#[cfg(test)]
mod cheque_decode_tests {
    use super::*;

    fn sample(cumulative: U256) -> Vec<u8> {
        encode_signed_cheque_json(&[0x11; 20], &[0x22; 20], cumulative, &canonical_sig())
    }

    /// `v = 27` and a low `s`, so it survives the canonical check.
    fn canonical_sig() -> [u8; 65] {
        let mut s = [0x01u8; 65];
        s[64] = 27;
        s
    }

    #[test]
    fn round_trips_our_own_encoder() {
        let amount = U256::from(1_234_567u64);
        let got = decode_signed_cheque_json(&sample(amount)).expect("decode");
        assert_eq!(got.chequebook, [0x11; 20]);
        assert_eq!(got.beneficiary, [0x22; 20]);
        assert_eq!(got.cumulative_payout, amount);
        assert_eq!(got.signature, canonical_sig());
    }

    /// The reason the decoder is hand-written. `serde_json` without
    /// `arbitrary_precision` widens this to `f64` and hands back a
    /// *different number* — which would have the relay credit an amount the
    /// signature never covered.
    #[test]
    fn a_payout_past_u64_survives_exactly() {
        // 2^80 + 1: needs u256, and is not representable in f64.
        let amount = U256::from(1u64) << 80 | U256::from(1u64);
        let body = sample(amount);
        let got = decode_signed_cheque_json(&body).expect("decode");
        assert_eq!(got.cumulative_payout, amount);

        let lossy = serde_json::from_slice::<serde_json::Value>(&body)
            .expect("parses")
            .get("CumulativePayout")
            .and_then(|n| n.as_u64());
        assert!(
            lossy.is_none(),
            "if serde ever parses this exactly, the hand-rolled scan can go"
        );
    }

    #[test]
    fn a_payout_at_the_u256_ceiling_decodes() {
        let amount = U256::MAX;
        let got = decode_signed_cheque_json(&sample(amount)).expect("decode");
        assert_eq!(got.cumulative_payout, amount);
    }

    #[test]
    fn a_payout_past_the_u256_ceiling_is_rejected() {
        let mut body = String::from_utf8(sample(U256::from(1u64))).expect("utf8");
        body = body.replace(
            "\"CumulativePayout\":1,",
            &format!("\"CumulativePayout\":{},", "9".repeat(78)),
        );
        decode_signed_cheque_json(body.as_bytes()).expect_err("must not wrap around");
    }

    /// Duplicate keys are legal JSON and serde keeps the last. If the scan
    /// picked the first, the relay would credit one amount while verifying
    /// a signature over another.
    #[test]
    fn a_duplicated_payout_key_is_rejected_not_guessed() {
        let body = br#"{"Chequebook":"0x1111111111111111111111111111111111111111","Beneficiary":"0x2222222222222222222222222222222222222222","CumulativePayout":1,"CumulativePayout":999999,"Signature":"AQ=="}"#;
        let e = decode_signed_cheque_json(body).expect_err("ambiguous");
        assert!(format!("{e}").contains("duplicate"), "got: {e}");
    }

    #[test]
    fn non_canonical_signatures_are_rejected_at_the_boundary() {
        let mut bad = canonical_sig();
        bad[64] = 1;
        let body = encode_signed_cheque_json(&[0x11; 20], &[0x22; 20], U256::from(5u64), &bad);
        let e = decode_signed_cheque_json(&body).expect_err("uncashable cheque");
        assert!(format!("{e}").contains("non-canonical"), "got: {e}");
    }

    #[test]
    fn a_scientific_or_fractional_payout_is_rejected_not_truncated() {
        // `123e5` / `123.45` are valid JSON but not bare integers: the scan
        // must not credit the `123` prefix.
        for body in [
            br#"{"Chequebook":"0x1111111111111111111111111111111111111111","Beneficiary":"0x2222222222222222222222222222222222222222","CumulativePayout":123e5,"Signature":"AQ=="}"#.as_slice(),
            br#"{"Chequebook":"0x1111111111111111111111111111111111111111","Beneficiary":"0x2222222222222222222222222222222222222222","CumulativePayout":123.45,"Signature":"AQ=="}"#.as_slice(),
        ] {
            let e = decode_signed_cheque_json(body).expect_err("must reject non-bare integer");
            assert!(format!("{e}").contains("bare JSON integer"), "got: {e}");
        }
    }

    #[test]
    fn malformed_bodies_are_rejected_not_panicked_on() {
        for body in [
            &b"{}"[..],
            b"not json",
            b"[]",
            br#"{"Chequebook":"0x11","Beneficiary":"0x22","CumulativePayout":1,"Signature":"AQ=="}"#,
            br#"{"Chequebook":"0x1111111111111111111111111111111111111111","Beneficiary":"0x2222222222222222222222222222222222222222","CumulativePayout":"1","Signature":"AQ=="}"#,
        ] {
            decode_signed_cheque_json(body).expect_err("must reject");
        }
        decode_signed_cheque_json(&vec![b'x'; MAX_CHEQUE_JSON + 1]).expect_err("oversized");
    }
}
