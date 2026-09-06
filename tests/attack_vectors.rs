//! Adversarial validation for `docs/pusher-incentives.md` §11.
//!
//! Each test is an attacker. Each assertion is a mitigation the doc claims.
//! Nothing here touches the network or chain: challenge MACs, ledger
//! monotonicity, cheque decoding, quote verification, credit arithmetic and
//! scheduler accounting are all pure logic and testable as such.
//!
//! Run: `cargo test --test attack_vectors`

use hoverfly::challenge;
use hoverfly::ledger::{Ledger, LedgerError, MAX_CUMULATIVE_PLUR};
use hoverfly::meter::Params;

// ── helpers ──────────────────────────────────────────────────────────────

const RELAY_KEY: &str = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const ATTACK_KEY: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

fn signer(key: &str) -> hoverfly::SwarmSigner {
    hoverfly::SwarmSigner::from_hex_with_nonce(key, &format!("0x{}", hex::encode([0u8; 32])), 1)
        .expect("key")
}

fn metered_two_relays() -> (hoverfly::metered::Metered, hoverfly::metered::Metered) {
    use hoverfly::metered::{MeterConfig, Metered};
    let mk = |origin: &str| {
        Metered::new(
            MeterConfig {
                origins: vec![origin.into()],
                beneficiary: [3u8; 20],
                chain_id: 100,
                factory: alloy_primitives::Address::ZERO,
                params: Params::default(),
                hard_mode: true,
            },
            Ledger::ephemeral(),
        )
    };
    (mk("relay-a.example"), mk("relay-b.example"))
}

fn issue_for(m: &hoverfly::metered::Metered, s: &hoverfly::SwarmSigner, now: u64) -> String {
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
    let sol = hoverfly::signer::PushChallenge {
        nonce: alloy_primitives::B256::from(issued.nonce),
        origin: issued.fields.origin.clone(),
        account: alloy_primitives::Address::from(account),
        batchId: alloy_primitives::B256::from(issued.fields.batch),
        expiry: alloy_primitives::U256::from(issued.fields.expiry_unix),
    };
    let sig = s.sign_push_challenge(&sol, 100).expect("sign");
    challenge::encode_challenge_header(&issued, &sig)
}

// ── §11.1: stamp replay becomes billing griefing ──────────────────────────

/// Harvested stamps are not enough: the challenge must be signed by the
/// account key. An attacker signing the victim's challenge with its own key
/// is refused.
#[test]
fn stolen_challenge_signed_by_wrong_key_is_refused() {
    let (a, _) = metered_two_relays();
    let victim = signer(RELAY_KEY);
    let attacker = signer(ATTACK_KEY);
    let v_acct = *victim.eth_address();
    let issued = a
        .issue(
            v_acct,
            [5u8; 32],
            1_000_000_000_000_000,
            "relay-a.example",
            1000,
        )
        .expect("issue");
    let sol = hoverfly::signer::PushChallenge {
        nonce: alloy_primitives::B256::from(issued.nonce),
        origin: issued.fields.origin.clone(),
        account: alloy_primitives::Address::from(v_acct),
        batchId: alloy_primitives::B256::from(issued.fields.batch),
        expiry: alloy_primitives::U256::from(issued.fields.expiry_unix),
    };
    let sig = attacker.sign_push_challenge(&sol, 100).expect("sign");
    let header = challenge::encode_challenge_header(&issued, &sig);
    let e = a.verify_header(&header, 1000).expect_err("must refuse");
    assert!(e.contains("claims account"), "got: {e}");
}

/// A capability for relay A is useless at relay B (origin bound to
/// configured hostname, never to the Host header).
#[test]
fn cross_relay_replay_is_refused() {
    let (a, b) = metered_two_relays();
    let s = signer(RELAY_KEY);
    let header = issue_for(&a, &s, 1000);
    let e = b.verify_header(&header, 1000).expect_err("must refuse");
    assert!(e.contains("origin"), "got: {e}");
}

/// Inflating the cap inside a validly-issued challenge breaks the MAC.
#[test]
fn inflated_cap_is_refused() {
    let (m, _) = metered_two_relays();
    let s = signer(RELAY_KEY);
    let mut issued = m
        .issue(
            *s.eth_address(),
            [5u8; 32],
            100_000_000_000_000,
            "relay-a.example",
            1000,
        )
        .expect("issue");
    issued.fields.cap_plur *= 1_000_000;
    let sol = hoverfly::signer::PushChallenge {
        nonce: alloy_primitives::B256::from(issued.nonce),
        origin: issued.fields.origin.clone(),
        account: alloy_primitives::Address::from(*s.eth_address()),
        batchId: alloy_primitives::B256::from(issued.fields.batch),
        expiry: alloy_primitives::U256::from(issued.fields.expiry_unix),
    };
    let sig = s.sign_push_challenge(&sol, 100).expect("sign");
    let header = challenge::encode_challenge_header(&issued, &sig);
    let e = m.verify_header(&header, 1000).expect_err("must refuse");
    assert!(e.contains("not ours"), "got: {e}");
}

#[test]
fn expired_challenge_is_refused() {
    let (m, _) = metered_two_relays();
    let s = signer(RELAY_KEY);
    let header = issue_for(&m, &s, 1000);
    let e = m
        .verify_header(&header, 1000 + challenge::CHALLENGE_TTL_SECS + 1)
        .expect_err("must refuse");
    assert!(e.contains("expired"), "got: {e}");
}

// ── §11.4: state loss → free-service loop ─────────────────────────────────

const A: [u8; 20] = [1u8; 20];
const B: [u8; 20] = [2u8; 20];
const CB: [u8; 20] = [9u8; 20];

fn sig27() -> [u8; 65] {
    let mut s = [0u8; 65];
    s[64] = 27;
    s
}

/// Re-presenting the same cheque credits zero — no replay, live or after a
/// restart (atomic persist of owed+cumulative+binding+secret).
#[test]
fn cheque_replay_credits_zero_live_and_after_restart() {
    let dir = std::env::temp_dir().join(format!("atk-replay-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ledger.json");
    let _ = std::fs::remove_file(&path);
    {
        let mut l = Ledger::load_or_create(&path).expect("create");
        l.commit(A, 0, 5000);
        assert_eq!(l.credit(A, CB, 1200, sig27()).expect("pay"), 1200);
        l.persist().expect("persist");
    }
    let mut l = Ledger::load_or_create(&path).expect("reload");
    assert!(matches!(
        l.credit(A, CB, 1200, sig27()),
        Err(LedgerError::NotIncreasing { .. })
    ));
    assert_eq!(l.owed(&A), 3800);
    let _ = std::fs::remove_file(&path);
}

/// Overpayment is refused: the relay never banks more than is owed (no
/// parking value it cannot return).
#[test]
fn overpayment_is_refused() {
    let mut l = Ledger::ephemeral();
    l.commit(A, 0, 100);
    assert!(matches!(
        l.credit(A, CB, 101, sig27()),
        Err(LedgerError::Overpayment { .. })
    ));
    l.credit(A, CB, 100, sig27()).expect("exact is fine");
    assert_eq!(l.owed(&A), 0);
}

/// Absurd cumulatives are refused (overflow probe bound at 1e30 ≪ u128::MAX).
#[test]
fn absurd_cumulative_is_refused() {
    let mut l = Ledger::ephemeral();
    l.commit(A, 0, 100);
    assert!(matches!(
        l.credit(A, CB, MAX_CUMULATIVE_PLUR + 1, sig27()),
        Err(LedgerError::Absurd(_))
    ));
}

/// A chequebook cannot move between accounts.
#[test]
fn chequebook_binding_is_immobile() {
    let mut l = Ledger::ephemeral();
    l.commit(A, 0, 1000);
    l.credit(A, CB, 100, sig27()).expect("bind to A");
    l.commit(B, 0, 1000);
    assert!(matches!(
        l.credit(B, CB, 500, sig27()),
        Err(LedgerError::ChequebookBound { .. })
    ));
}

/// Persist failure rolls back in memory (no divergence → no double credit
/// after restart). Exercises the rollback path directly.
#[test]
fn failed_credit_rolls_back_monetary_state() {
    let mut l = Ledger::ephemeral();
    l.commit(A, 0, 5000);
    let prev_owed = l.owed(&A);
    let prev_held = l.held_cheque(&A, &CB);
    let had_binding = l.had_binding(&CB);
    l.credit(A, CB, 1200, sig27()).expect("credit");
    assert_eq!(l.owed(&A), 3800);
    l.rollback_credit(A, CB, prev_owed, prev_held, had_binding);
    assert_eq!(l.owed(&A), 5000);
    assert_eq!(l.last_cumulative(&A, &CB), 0);
    // And the same cheque credits exactly once after rollback.
    assert_eq!(l.credit(A, CB, 1200, sig27()).expect("re-credit"), 1200);
}

/// Unknown future ledger versions must not load silently.
#[test]
fn unknown_ledger_version_is_rejected() {
    let dir = std::env::temp_dir().join(format!("atk-ver-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("v999.json");
    std::fs::write(
        &path,
        r#"{"version":999,"secret_hex":"00","accounts":[],"binding":[]}"#,
    )
    .unwrap();
    let res = Ledger::load_or_create(&path);
    let e = match res {
        Ok(_) => panic!("must reject v999"),
        Err(e) => e,
    };
    assert!(
        format!("{e}").contains("unsupported ledger version"),
        "got: {e}"
    );
    let _ = std::fs::remove_file(&path);
}

/// Reservations never survive a restart (no task left to release them —
/// restoring them would brick the account into an unpayable 402).
#[test]
fn reservations_are_zeroed_at_boot() {
    let dir = std::env::temp_dir().join(format!("atk-res-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("res.json");
    let _ = std::fs::remove_file(&path);
    {
        let mut l = Ledger::load_or_create(&path).expect("create");
        l.commit(A, 0, 5000);
        l.reserve(A, 900, 100_000);
        l.persist().expect("persist");
    }
    let l = Ledger::load_or_create(&path).expect("reload");
    assert_eq!(l.reserved(&A), 0);
    assert_eq!(l.owed(&A), 5000);
    let _ = std::fs::remove_file(&path);
}

// ── §11.6: cheque decoding ────────────────────────────────────────────────

fn canonical_test_sig() -> [u8; 65] {
    let mut s = [0x01u8; 65];
    s[64] = 27;
    s
}

fn cheque_bytes(cumulative: &str) -> Vec<u8> {
    // Build a fully valid cheque for 123, then rewrite the cumulative digits.
    // The signature still covers 123, but `extract_cumulative` (the terminator
    // check under test) runs before signature verification, so malformed
    // numbers fail on the number itself — exactly the relay's behavior.
    let valid = hoverfly::protocols::swap::encode_signed_cheque_json(
        &[0x11; 20],
        &[0x22; 20],
        alloy_primitives::U256::from(123u64),
        &canonical_test_sig(),
    );
    let mut s = String::from_utf8(valid).expect("utf8");
    if cumulative != "123" {
        s = s.replacen(
            "\"CumulativePayout\":123",
            &format!("\"CumulativePayout\":{cumulative}"),
            1,
        );
    }
    s.into_bytes()
}

#[test]
fn duplicate_payout_key_is_rejected() {
    let body = br#"{"Chequebook":"0x1111111111111111111111111111111111111111","Beneficiary":"0x2222222222222222222222222222222222222222","CumulativePayout":1,"CumulativePayout":999999,"Signature":"AQ=="}"#;
    hoverfly::protocols::swap::decode_signed_cheque_json(body).expect_err("ambiguous");
}

#[test]
fn scientific_and_fractional_payouts_are_rejected_not_truncated() {
    // Without the terminator check these would scan as `123`.
    for body in [cheque_bytes("123e5"), cheque_bytes("123.45")] {
        let e = hoverfly::protocols::swap::decode_signed_cheque_json(&body)
            .expect_err("must reject non-bare integer");
        assert!(format!("{e}").contains("bare JSON integer"), "got: {e}");
    }
    // And the bare integer still decodes.
    let got = hoverfly::protocols::swap::decode_signed_cheque_json(&cheque_bytes("123"))
        .expect("bare int");
    assert_eq!(got.cumulative_payout, alloy_primitives::U256::from(123u64));
}

// ── §7.3/§11.3: quote verification ────────────────────────────────────────

fn quote_json(beneficiary: [u8; 20]) -> serde_json::Value {
    let n = signer(RELAY_KEY);
    let p = Params::default();
    let mut body = serde_json::json!({
        "mode": "metered",
        "enforcement": "soft",
        "beneficiary": format!("0x{}", hex::encode(beneficiary)),
        "node_eth_address": format!("0x{}", hex::encode(n.eth_address())),
        "overlay_nonce": format!("0x{}", hex::encode([0u8; 32])),
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
    Params::default().price_plur_per_kib * 8
}

#[test]
fn quote_tampering_breaks_verification() {
    for field in ["price_plur_per_kib", "beneficiary", "origin", "chain_id"] {
        let mut q = quote_json([3u8; 20]);
        q[field] = match field {
            "price_plur_per_kib" => serde_json::json!("1"),
            "beneficiary" => serde_json::json!(format!("0x{}", hex::encode([0xAAu8; 20]))),
            "origin" => serde_json::json!("evil.example"),
            _ => serde_json::json!(1u64),
        };
        assert!(
            hoverfly::payer::PaymentQuote::verify(&q, None, 1, None, ceiling()).is_err(),
            "tampering with {field} must be caught"
        );
    }
}

#[test]
fn unpinned_identity_and_beneficiary_are_refused() {
    use hoverfly::payer::{LanePin, PaymentQuote, QuoteError};
    let pin = LanePin {
        node_eth_address: [0xEE; 20],
        beneficiary: [3u8; 20],
    };
    assert!(matches!(
        PaymentQuote::verify(&quote_json([3u8; 20]), None, 1, Some(&pin), ceiling()),
        Err(QuoteError::WrongSigner { .. })
    ));
    let pin = LanePin {
        node_eth_address: *signer(RELAY_KEY).eth_address(),
        beneficiary: [3u8; 20],
    };
    assert!(matches!(
        PaymentQuote::verify(&quote_json([0xBB; 20]), None, 1, Some(&pin), ceiling()),
        Err(QuoteError::WrongBeneficiary { .. })
    ));
}

#[test]
fn zero_quote_validity_is_refused() {
    let mut q = quote_json([3u8; 20]);
    q["quote_valid_secs"] = serde_json::json!(0u64);
    assert!(
        hoverfly::payer::PaymentQuote::verify(&q, None, 1, None, ceiling()).is_err(),
        "quote_valid_secs=0 must be refused"
    );
}

// ── §10: credit arithmetic ────────────────────────────────────────────────

#[test]
fn invariant_rejects_bricking_params() {
    let mut p = Params::default();
    p.min_cheque_plur = p.settle_every_plur * 87;
    p.validate()
        .expect_err("dust above window must refuse to boot");
    let mut p = Params::default();
    p.max_outstanding_plur = p.settle_every_plur;
    p.validate().expect_err("cap must exceed window");
}

#[test]
fn effective_thresholds_exit_at_any_line() {
    let p = Params::default();
    // Even a 1-PLUR line yields a clearable, non-zero floor.
    for cap in [1u128, 2, 679_783_122_862, p.max_outstanding_plur] {
        let e = p.effective(cap);
        assert!(e.min_cheque_plur >= 1, "cap {cap}: floor must be ≥1");
        assert!(
            e.min_cheque_plur <= e.settle_every_plur,
            "cap {cap}: 402 must be clearable"
        );
    }
}

#[test]
fn credit_line_scales_with_batch_value() {
    let p = Params::default();
    // Sybil margin is exactly the ratio at any size.
    assert_eq!(p.credit_line(100_000_000_000_000), 100_000_000_000);
    // Rich batches clamp to the ceiling, never above.
    assert_eq!(p.credit_line(u128::MAX), p.max_outstanding_plur);
    // The per-account cap prices to ~$0.0024 at $0.02/GiB.
    let kib = p.max_outstanding_plur / p.price_plur_per_kib;
    let gib = kib as f64 / 1_048_576.0;
    let usd = gib * 0.02;
    assert!(
        (0.002..0.003).contains(&usd),
        "cap must bound yield to ~$0.0024, got ${usd:.5}"
    );
}

// ── §8: billing symmetry ──────────────────────────────────────────────────

#[test]
fn refused_post_never_becomes_debt_but_interrupted_does() {
    use hoverfly::payer::LaneAccount;
    let p = Params::default();
    let mut a = LaneAccount::new(p, [3u8; 20]);
    a.record_sent(100 * 4251);
    a.record_answered(100 * 4251, false); // 402: refused before a byte read
    assert_eq!(a.owed(), 0);
    assert_eq!(a.outstanding(), 0);
    a.record_sent(64 * 1024);
    a.record_answered(64 * 1024, true); // broken stream: relay read it
    assert_eq!(a.owed(), p.price_bytes(64 * 1024));
}

#[test]
fn adopting_debt_is_upward_only_and_deducts_in_flight() {
    use hoverfly::payer::LaneAccount;
    let p = Params::default();
    let mut a = LaneAccount::new(p, [3u8; 20]);
    let body = 64 * 1024u64;
    let priced = p.price_bytes(body);
    a.record_sent(body);
    a.adopt_relay_debt(priced); // relay already booked what is still pending
    a.record_answered(body, true);
    assert_eq!(a.owed(), priced, "billed once, not twice");
    assert!(!a.adopt_relay_debt(0), "downward adopt refused");
}

// ── scheduler: 402 economics ──────────────────────────────────────────────

#[test]
fn payment_required_burns_no_attempt_and_no_health() {
    use hoverfly::pushsched::{Config, LaneInfo, Scheduler};
    let infos = vec![LaneInfo::default(), LaneInfo::default()];
    let mut s = Scheduler::new(infos, Config::default());
    let mk = |i: u8| {
        let mut a = [0u8; 32];
        a[0] = i;
        (a, 4096u32)
    };
    s.admit((0..64u8).map(mk));
    for _ in 0..20 {
        let a = s.next(0).expect("work");
        s.on_batch_result(
            a.batch,
            hoverfly::pushsched::BatchOutcome::PaymentRequired,
            0,
        );
        for l in s.unfunded_lanes() {
            s.fund_lane(l);
        }
    }
    assert_eq!(s.failed(), 0, "402s must never fail chunks");
}
