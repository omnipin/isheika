//! Postage batch creation against the on-chain `PostageStamp` contract.
//!
//! Unlike every other module in this crate, `batch::create` makes
//! real on-chain RPC calls. The rest of hoverfly stays RPC-free —
//! this is the one exception, fenced off behind a dedicated CLI
//! subcommand (`hoverfly batch create`) so it doesn't contaminate
//! the upload / fetch / daemon paths.
//!
//! ## Flow
//!
//! Per bee's `postagecontract.CreateBatch`
//! (`~/Coding/forks/bee/pkg/postage/postagecontract/contract.go`):
//!
//! 1. Read `lastPrice` and `minimumValidityBlocks` from the
//!    `PostageStamp` contract → compute the minimum
//!    `initialBalancePerChunk` required for the 24h-validity rule.
//! 2. Read the signer's BZZ balance, verify it covers
//!    `initialBalancePerChunk * 2^depth`.
//! 3. `BZZ.approve(PostageStamp, initialBalancePerChunk * 2^depth)`.
//! 4. `PostageStamp.createBatch(owner, initialBalancePerChunk,
//!    depth, bucketDepth=16, nonce, immutable)` with a random nonce.
//! 5. Parse `BatchCreated(batchId, totalAmount, normalisedBalance,
//!    owner, depth, bucketDepth, immutableFlag)` event from the
//!    receipt logs → emit `batchId`.
//!
//! `batchId` could also be computed client-side as
//! `keccak256(abi.encode(signer, nonce))` (see `PostageStamp.sol`),
//! but parsing the event is the bee-canonical path and surfaces any
//! revert / reordering at the same time.
//!
//! ## Why hand-rolled, not alloy-provider
//!
//! `alloy-provider` would pull `alloy-consensus`, `alloy-trie`,
//! `c-kzg`, and the full transport stack — ~20 transitive crates
//! for one signed transaction. We already have `alloy-signer-local`
//! (for cheques) and `alloy-sol-types` (for ABI encoding); adding
//! `alloy-rlp` + reqwest JSON-RPC keeps the dep delta to one crate.
//!
//! ## Transaction shape
//!
//! EIP-1559 transactions (type-2). This was legacy type-0 originally,
//! on the reasoning that fees are negligible on Gnosis so there was
//! nothing to optimize. That reasoning was about *cost* and missed the
//! *liveness* failure it implies: a legacy `gasPrice` is fixed at
//! signing time, and Gnosis's `eth_gasPrice` returns roughly
//! `base_fee + 1 wei`. If base fee ticks up before inclusion — it can
//! rise 12.5% per block — the transaction is permanently unmineable and
//! wedges the sender's nonce, queueing every later transaction behind
//! it until it is manually replaced. Observed in practice.
//!
//! Type-2 removes the trade-off rather than tuning it. `maxFeePerGas`
//! is a ceiling, not a payment: the chain charges
//! `base_fee + min(tip, maxFee - base_fee)` and never spends the rest.
//! So the fee paid is exactly the prevailing rate, while the headroom
//! that keeps the transaction mineable costs nothing.

use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_rlp::Encodable;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolCall, SolEvent, sol};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

/// Swarm-on-Gnosis mainnet `PostageStamp` contract address.
/// From bee's `go-storage-incentives-abi` v0.9.4.
pub const MAINNET_POSTAGE_STAMP: &str = "0x45a1502382541Cd610CC9068e88727426b696293";

/// Swarm-on-Gnosis mainnet BZZ ERC-20 token address.
pub const MAINNET_BZZ_TOKEN: &str = "0xdBF3Ea6F5beE45c02255B2c26a16F300502F68da";

/// Gnosis chain ID.
pub const MAINNET_CHAIN_ID: u64 = 100;

/// Bucket depth `PostageStamp` requires. Hard-coded by bee as a
/// global constant (`postagecontract.BucketDepth = 16`) — the
/// contract rejects anything below `minimumBucketDepth` (also 16
/// on mainnet at deploy time) and anything `>= depth`.
pub const BUCKET_DEPTH: u8 = 16;

/// Effective volume in binary gibibytes (1 GiB = 1024^3 bytes) for
/// each batch depth 17..=41, in the bee-canonical default config:
/// unencrypted, erasure-coding level NONE. Values copied verbatim
/// from the `gb` field of the official postage stamp calculator at
/// <https://github.com/ethersphere/bee-docs/blob/master/src/components/AmountAndDepthCalc.js>
/// (Gyuri's simulations, 0.1% failure quantile, PAC overhead
/// included). The calculator treats kB/MB/GB/TB/PB as binary units
/// throughout — we follow the same convention so our depth choice
/// matches the docs site's "Suggested Safe Depth" output.
const EFFECTIVE_VOLUME_GIB: [(u8, f64); 25] = [
    (17, 0.000043),
    (18, 0.006504),
    (19, 0.109434),
    (20, 0.671504),
    (21, 2.60),
    (22, 7.73),
    (23, 19.94),
    (24, 47.06),
    (25, 105.51),
    (26, 227.98),
    (27, 476.68),
    (28, 993.65),
    (29, 2088.96),
    (30, 4270.08),
    (31, 8652.80),
    (32, 17479.68),
    (33, 35184.64),
    (34, 70696.96),
    (35, 141864.96),
    (36, 284385.28),
    (37, 569702.40),
    (38, 1163919.36),
    (39, 2338324.48),
    (40, 4676648.96),
    (41, 9363783.68),
];

/// Gnosis chain block time in seconds. Stable since chain launch.
pub const GNOSIS_BLOCK_TIME_SECS: u64 = 5;

/// Pick the smallest batch depth whose effective volume covers
/// `requested_bytes`. Matches the "Suggested Safe Depth" output of
/// <https://docs.ethswarm.org/docs/develop/tools-and-features/buy-a-stamp-batch/#calculators>.
///
/// Bytes are converted to binary GiB (`bytes / 1024^3`) before
/// comparison, matching the calculator's unit semantics.
pub fn depth_for_size(requested_bytes: u64) -> Option<u8> {
    let requested_gib = requested_bytes as f64 / (1024.0_f64.powi(3));
    EFFECTIVE_VOLUME_GIB
        .iter()
        .find(|(_, eff)| *eff >= requested_gib)
        .map(|(d, _)| *d)
}

/// Compute the per-chunk `amount` (PLUR) needed for at least
/// `duration_secs` of storage at the current on-chain price.
///
/// Formula (from the bee-docs calculator and PostageStamp.sol
/// `minimumInitialBalancePerChunk = minimumValidityBlocks × lastPrice`):
///
///   amount = ceil(duration_secs / block_time) × last_price
///
/// The contract requires `amount > minimumInitialBalancePerChunk`
/// strictly (`<=` reverts), so we add a small buffer (+10 PLUR,
/// matching the docs calculator's "Suggested Minimum Amount").
pub fn amount_for_duration(last_price: u64, duration_secs: u64) -> U256 {
    let blocks = duration_secs.div_ceil(GNOSIS_BLOCK_TIME_SECS);
    U256::from(blocks).saturating_mul(U256::from(last_price)) + U256::from(10u64)
}

/// Parse a human-readable size like `100MB`, `2GB`, `1.5TB` into bytes
/// using binary multipliers (1 KB = 1024 B, 1 MB = 1024 KB, ...).
/// Matches the unit semantics of the official bee-docs calculator.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num_part, unit_part) = s
        .find(|c: char| c.is_alphabetic())
        .map(|i| s.split_at(i))
        .ok_or_else(|| format!("size '{s}' missing unit (kB / MB / GB / TB / PB)"))?;
    let num: f64 = num_part
        .trim()
        .parse()
        .map_err(|e| format!("size '{s}': bad number '{num_part}': {e}"))?;
    let unit = unit_part.trim().to_ascii_lowercase();
    let mult: u64 = match unit.as_str() {
        "b" => 1,
        "kb" | "k" => 1024,
        "mb" | "m" => 1024 * 1024,
        "gb" | "g" => 1024 * 1024 * 1024,
        "tb" | "t" => 1024_u64.pow(4),
        "pb" | "p" => 1024_u64.pow(5),
        _ => {
            return Err(format!(
                "size '{s}': unknown unit '{unit_part}' (use kB/MB/GB/TB/PB)"
            ));
        }
    };
    let bytes = (num * mult as f64) as u64;
    Ok(bytes)
}

/// Parse a human-readable duration like `24h`, `30d`, `2w`, `1y`
/// into seconds. Single unit suffix only.
pub fn parse_duration(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num_part, unit) = s
        .find(|c: char| c.is_alphabetic())
        .map(|i| s.split_at(i))
        .ok_or_else(|| format!("duration '{s}' missing unit (h / d / w / y)"))?;
    let num: f64 = num_part
        .trim()
        .parse()
        .map_err(|e| format!("duration '{s}': bad number '{num_part}': {e}"))?;
    let mult: f64 = match unit.trim().to_ascii_lowercase().as_str() {
        "s" | "sec" | "secs" | "second" | "seconds" => 1.0,
        "m" | "min" | "mins" | "minute" | "minutes" => 60.0,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3600.0,
        "d" | "day" | "days" => 86400.0,
        "w" | "wk" | "wks" | "week" | "weeks" => 7.0 * 86400.0,
        "y" | "yr" | "yrs" | "year" | "years" => 365.0 * 86400.0,
        _ => {
            return Err(format!(
                "duration '{s}': unknown unit '{unit}' (use h/d/w/y)"
            ));
        }
    };
    Ok((num * mult) as u64)
}

/// Read the current `lastPrice` from the PostageStamp contract.
/// Useful for previewing batch cost / amount before calling
/// [`create_batch`]. Returns PLUR per chunk per block.
pub async fn read_last_price(rpc_url: &str, postage_stamp: Address) -> Result<u64, BatchError> {
    let rpc = EthRpc::new(rpc_url.to_string());
    rpc.call_view::<lastPriceCall, _>(postage_stamp, lastPriceCall {})
        .await
}

/// On-chain metadata for a postage batch, read from the PostageStamp
/// contract's `batches(bytes32)` getter.
#[derive(Debug, Clone)]
pub struct BatchOnChain {
    /// Batch owner — the address whose signer must sign every stamp for
    /// bee to accept it. An upload key whose address differs from this
    /// will produce stamps bee rejects.
    pub owner: Address,
    /// Batch depth (`2^depth` total stamps). The stamper must be built
    /// with this exact depth or the per-bucket index math diverges from
    /// what bee expects for the batch.
    pub depth: u8,
    /// Bucket depth (bee hard-codes 16).
    pub bucket_depth: u8,
    /// Immutable batches reject any bucket over-fill outright.
    pub immutable: bool,
    /// `true` when the batch does not exist on-chain (getter returned the
    /// zero owner / zero depth). Callers should treat this as "unknown
    /// batch" rather than a depth-0 batch.
    pub not_found: bool,
}

/// Read a batch's on-chain metadata (owner, depth, …) from the
/// PostageStamp contract via a single `eth_call`. No transaction, no gas.
///
/// `batch_id_hex` is the 32-byte batch ID as hex (`0x`-optional). Returns
/// `not_found = true` when the batch ID isn't registered on-chain (the
/// getter returns an all-zero struct).
pub async fn read_batch(
    rpc_url: &str,
    postage_stamp: Address,
    batch_id_hex: &str,
) -> Result<BatchOnChain, BatchError> {
    let trimmed = batch_id_hex
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    let raw = hex::decode(trimmed).map_err(|e| BatchError::Rpc(format!("batch id hex: {e}")))?;
    if raw.len() != 32 {
        return Err(BatchError::Rpc(format!(
            "batch id must be 32 bytes, got {}",
            raw.len()
        )));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&raw);

    let rpc = EthRpc::new(rpc_url.to_string());
    let ret = rpc
        .call_view::<batchesCall, _>(postage_stamp, batchesCall { id: id.into() })
        .await?;

    let owner = ret.owner;
    let not_found = owner == Address::ZERO && ret.depth == 0;
    Ok(BatchOnChain {
        owner,
        depth: ret.depth,
        bucket_depth: ret.bucketDepth,
        immutable: ret.immutableFlag,
        not_found,
    })
}

/// Read a batch's remaining balance (PLUR per chunk still funded) from
/// the PostageStamp contract's `remainingBalance(bytes32)` getter. Zero
/// means the batch has expired — bee nodes garbage-collect its chunks
/// and reject new stamps against it. Reverts on-chain (surfacing as an
/// RPC error here) when the batch does not exist; call [`read_batch`]
/// first if "unknown batch" must be distinguished from "RPC down".
pub async fn read_remaining_balance(
    rpc_url: &str,
    postage_stamp: Address,
    batch_id_hex: &str,
) -> Result<U256, BatchError> {
    let trimmed = batch_id_hex
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    let raw = hex::decode(trimmed).map_err(|e| BatchError::Rpc(format!("batch id hex: {e}")))?;
    if raw.len() != 32 {
        return Err(BatchError::Rpc(format!(
            "batch id must be 32 bytes, got {}",
            raw.len()
        )));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&raw);

    let rpc = EthRpc::new(rpc_url.to_string());
    rpc.call_view::<remainingBalanceCall, _>(postage_stamp, remainingBalanceCall { id: id.into() })
        .await
}

sol! {
    // PostageStamp.createBatch(address,uint256,uint8,uint8,bytes32,bool)
    function createBatch(
        address owner,
        uint256 initialBalancePerChunk,
        uint8 depth,
        uint8 bucketDepth,
        bytes32 nonce,
        bool immutable_
    ) external returns (bytes32);

    // PostageStamp.batches(bytes32) public mapping getter. Returns the
    // on-chain Batch struct fields in storage order. Used to infer a
    // batch's depth and verify its owner before an upload.
    function batches(bytes32 id) external view returns (
        address owner,
        uint8 depth,
        uint8 bucketDepth,
        bool immutableFlag,
        uint256 normalisedBalance,
        uint256 lastUpdatedBlockNumber
    );

    // PostageStamp.remainingBalance(bytes32) — PLUR per chunk still
    // funded; 0 = expired batch. Reverts when the batch doesn't exist.
    function remainingBalance(bytes32 id) external view returns (uint256);

    // PostageStamp.lastPrice() returns (uint64)
    function lastPrice() external view returns (uint64);

    // PostageStamp.minimumValidityBlocks() returns (uint64)
    function minimumValidityBlocks() external view returns (uint64);

    // ERC20.balanceOf(address)
    function balanceOf(address account) external view returns (uint256);

    // ERC20.allowance(address,address)
    function allowance(address owner, address spender) external view returns (uint256);

    // ERC20.approve(address,uint256)
    function approve(address spender, uint256 amount) external returns (bool);

    // event BatchCreated(
    //     bytes32 indexed batchId,
    //     uint256 totalAmount,
    //     uint256 normalisedBalance,
    //     address owner,
    //     uint8 depth,
    //     uint8 bucketDepth,
    //     bool immutableFlag
    // )
    event BatchCreated(
        bytes32 indexed batchId,
        uint256 totalAmount,
        uint256 normalisedBalance,
        address owner,
        uint8 depth,
        uint8 bucketDepth,
        bool immutableFlag
    );
}

#[derive(Debug, Error)]
pub enum BatchError {
    #[error("rpc error: {0}")]
    Rpc(String),
    #[error("rpc transport: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("transaction reverted (status=0) — check approve/balance/depth")]
    Reverted,
    #[error("insufficient BZZ balance: have {have} PLUR, need {need} PLUR")]
    InsufficientBalance { have: U256, need: U256 },
    #[error("initial balance per chunk too low for 24h validity: have {have}, need >= {need}")]
    InsufficientValidity { have: U256, need: U256 },
    #[error("invalid depth: must be > bucket depth ({BUCKET_DEPTH}), got {0}")]
    InvalidDepth(u8),
    #[error("BatchCreated event not found in receipt logs")]
    NoBatchEvent,
    #[error("receipt not found within timeout")]
    ReceiptTimeout,
    #[error("abi decode: {0}")]
    AbiDecode(String),
}

/// Inputs for `create_batch`.
#[derive(Debug, Clone)]
pub struct CreateBatchParams {
    /// JSON-RPC endpoint (e.g. `https://rpc.gnosischain.com`).
    pub rpc_url: String,
    /// Owner of the resulting batch. Defaults to the signer's
    /// address when invoked from the CLI.
    pub owner: Address,
    /// PostageStamp contract address (mainnet default elsewhere).
    pub postage_stamp: Address,
    /// BZZ ERC-20 token address (mainnet default elsewhere).
    pub bzz_token: Address,
    /// Per-chunk initial balance, in BZZ-PLUR (1 BZZ = 10^16 PLUR).
    /// Must be `>= lastPrice * minimumValidityBlocks` or the contract
    /// reverts with `InsufficientBalance`. The total BZZ pulled from
    /// the signer is `initial_balance_per_chunk * 2^depth`.
    pub initial_balance_per_chunk: U256,
    /// Batch depth. Stamp count = `2^depth`. Must be `> BUCKET_DEPTH` (16).
    pub depth: u8,
    /// Immutable batch flag. Mutable batches can be diluted/topped up;
    /// immutable batches cannot.
    pub immutable: bool,
    /// EIP-155 chain id (Gnosis mainnet = 100).
    pub chain_id: u64,
    /// Receipt polling timeout. Gnosis blocks are ~5s, so 120s covers
    /// >20 blocks of headroom.
    pub receipt_timeout: Duration,
}

impl CreateBatchParams {
    pub fn mainnet(rpc_url: String, signer_addr: Address) -> Self {
        Self {
            rpc_url,
            owner: signer_addr,
            postage_stamp: MAINNET_POSTAGE_STAMP.parse().expect("hardcoded valid"),
            bzz_token: MAINNET_BZZ_TOKEN.parse().expect("hardcoded valid"),
            initial_balance_per_chunk: U256::ZERO, // caller fills
            depth: 20,
            immutable: false,
            chain_id: MAINNET_CHAIN_ID,
            receipt_timeout: Duration::from_secs(120),
        }
    }
}

/// Result of a successful `create_batch` call.
#[derive(Debug, Clone)]
pub struct BatchCreatedInfo {
    pub batch_id: B256,
    pub total_amount: U256,
    pub normalised_balance: U256,
    pub owner: Address,
    pub depth: u8,
    pub bucket_depth: u8,
    pub immutable: bool,
    pub create_tx: B256,
    pub approve_tx: B256,
}

/// Run the full bee-style createBatch flow: read price/validity →
/// sanity-check balance → approve → createBatch → parse event.
pub async fn create_batch(
    signer: &PrivateKeySigner,
    params: CreateBatchParams,
) -> Result<BatchCreatedInfo, BatchError> {
    if params.depth <= BUCKET_DEPTH {
        return Err(BatchError::InvalidDepth(params.depth));
    }

    let rpc = EthRpc::new(params.rpc_url.clone());
    let from = signer.address();

    // Read on-chain state to compute / validate amounts.
    let last_price: u64 = rpc
        .call_view::<lastPriceCall, _>(params.postage_stamp, lastPriceCall {})
        .await?;
    let min_validity: u64 = rpc
        .call_view::<minimumValidityBlocksCall, _>(
            params.postage_stamp,
            minimumValidityBlocksCall {},
        )
        .await?;
    let min_initial =
        U256::from(last_price as u128).saturating_mul(U256::from(min_validity as u128));

    if params.initial_balance_per_chunk <= min_initial {
        return Err(BatchError::InsufficientValidity {
            have: params.initial_balance_per_chunk,
            need: min_initial,
        });
    }

    // total = initial * 2^depth (overflow check via U256 mul).
    let total = params
        .initial_balance_per_chunk
        .checked_mul(U256::from(1u128 << params.depth))
        .ok_or_else(|| BatchError::Rpc("total amount overflow".into()))?;

    let balance: U256 = rpc
        .call_view::<balanceOfCall, _>(params.bzz_token, balanceOfCall { account: from })
        .await?;
    if balance < total {
        return Err(BatchError::InsufficientBalance {
            have: balance,
            need: total,
        });
    }

    // Approve. Skip if existing allowance already covers it.
    let current_allowance: U256 = rpc
        .call_view::<allowanceCall, _>(
            params.bzz_token,
            allowanceCall {
                owner: from,
                spender: params.postage_stamp,
            },
        )
        .await?;
    let approve_tx = if current_allowance >= total {
        // Already approved — return the zero hash to signal skipped.
        B256::ZERO
    } else {
        let approve_call = approveCall {
            spender: params.postage_stamp,
            amount: total,
        }
        .abi_encode();
        rpc.send_signed(signer, params.chain_id, params.bzz_token, &approve_call)
            .await?
    };
    if approve_tx != B256::ZERO {
        rpc.wait_for_success(approve_tx, params.receipt_timeout)
            .await?;
    }

    // createBatch with a random 32-byte nonce.
    let mut nonce_bytes = [0u8; 32];
    getrandom::fill(&mut nonce_bytes).map_err(|e| BatchError::Rpc(format!("getrandom: {e}")))?;
    let nonce = B256::from(nonce_bytes);

    let create_call = createBatchCall {
        owner: params.owner,
        initialBalancePerChunk: params.initial_balance_per_chunk,
        depth: params.depth,
        bucketDepth: BUCKET_DEPTH,
        nonce,
        immutable_: params.immutable,
    }
    .abi_encode();

    let create_tx = rpc
        .send_signed(signer, params.chain_id, params.postage_stamp, &create_call)
        .await?;
    let receipt = rpc
        .wait_for_success(create_tx, params.receipt_timeout)
        .await?;

    // Parse BatchCreated event from logs. The event signature topic
    // is keccak256("BatchCreated(bytes32,uint256,uint256,address,uint8,uint8,bool)").
    let topic = BatchCreated::SIGNATURE_HASH;
    for log in &receipt.logs {
        if log.address.parse::<Address>().ok() != Some(params.postage_stamp) {
            continue;
        }
        if log.topics.is_empty() || log.topics[0].parse::<B256>().ok() != Some(topic) {
            continue;
        }
        // Decode the event using alloy-sol-types
        let topics: Vec<B256> = log.topics.iter().filter_map(|s| s.parse().ok()).collect();
        let data = hex::decode(log.data.trim_start_matches("0x"))
            .map_err(|e| BatchError::AbiDecode(format!("log data hex: {e}")))?;
        let decoded = BatchCreated::decode_raw_log(topics.iter().copied(), &data)
            .map_err(|e| BatchError::AbiDecode(format!("BatchCreated: {e}")))?;
        return Ok(BatchCreatedInfo {
            batch_id: decoded.batchId,
            total_amount: decoded.totalAmount,
            normalised_balance: decoded.normalisedBalance,
            owner: decoded.owner,
            depth: decoded.depth,
            bucket_depth: decoded.bucketDepth,
            immutable: decoded.immutableFlag,
            create_tx,
            approve_tx,
        });
    }
    Err(BatchError::NoBatchEvent)
}

// ──────────────────────────────────────────────────────────────────────
// Minimal JSON-RPC + tx signing
// ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct RpcReq<'a, P: Serialize> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: P,
}

#[derive(Debug, Deserialize)]
struct RpcResp<R> {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    #[allow(dead_code)]
    id: Option<u64>,
    result: Option<R>,
    error: Option<RpcErr>,
}

#[derive(Debug, Deserialize)]
struct RpcErr {
    code: i64,
    message: String,
}

#[derive(Debug, Serialize)]
struct CallObj {
    from: String,
    to: String,
    data: String,
}

/// Just the fee-relevant part of a block header. `baseFeePerGas` is absent
/// on pre-London chains, so it stays optional rather than defaulting to 0
/// implicitly.
#[derive(Debug, Deserialize)]
struct BlockHeader {
    #[serde(rename = "baseFeePerGas")]
    base_fee_per_gas: Option<String>,
}

/// Parse a `0x`-prefixed, non-zero-padded JSON-RPC quantity into a `U256`.
fn parse_u256_hex(s: &str) -> Result<U256, BatchError> {
    let bytes = hex::decode(format!("{:0>64}", s.trim_start_matches("0x")))?;
    Ok(U256::from_be_slice(&bytes))
}

#[derive(Debug, Deserialize)]
struct ReceiptResp {
    status: String,
    #[serde(rename = "transactionHash")]
    #[allow(dead_code)]
    tx_hash: String,
    logs: Vec<RpcLog>,
}

#[derive(Debug, Deserialize)]
struct RpcLog {
    address: String,
    topics: Vec<String>,
    data: String,
}

struct EthRpc {
    url: String,
    http: reqwest::Client,
}

/// One process-wide HTTP client for every `eth_call`.
///
/// `EthRpc::new` is called per read (`read_batch`, `read_remaining_balance`,
/// `read_last_price`, …), and building a fresh `reqwest::Client` each time
/// means a fresh connection pool, so every read paid a full TLS handshake
/// and none were ever reused. On the pusher's hot path that is one handshake
/// per batch resolution; under a flood of unresolvable batch ids it was one
/// per frame. `reqwest::Client` is an `Arc` internally, so cloning it shares
/// the pool.
fn shared_http() -> &'static reqwest::Client {
    static HTTP: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    HTTP.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("reqwest client")
    })
}

impl EthRpc {
    fn new(url: String) -> Self {
        Self {
            url,
            http: shared_http().clone(),
        }
    }

    async fn raw<P: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R, BatchError> {
        let v = self.raw_opt::<P, R>(method, params).await?;
        v.ok_or_else(|| BatchError::Rpc(format!("{method}: empty result")))
    }

    /// Like `raw` but tolerates a JSON `null` `result` — converts it
    /// to `Ok(None)` instead of an error. Used for poll-style methods
    /// (`eth_getTransactionReceipt`) where `null` means "not mined yet".
    async fn raw_opt<P: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: P,
    ) -> Result<Option<R>, BatchError> {
        let body = RpcReq {
            jsonrpc: "2.0",
            id: 1,
            method,
            params,
        };
        let resp: RpcResp<R> = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;
        if let Some(e) = resp.error {
            return Err(BatchError::Rpc(format!(
                "{}: {} (code {})",
                method, e.message, e.code
            )));
        }
        Ok(resp.result)
    }

    /// `eth_call`-based view call. Returns the decoded sol return type.
    async fn call_view<C, T>(&self, to: Address, call: C) -> Result<C::Return, BatchError>
    where
        C: SolCall<Return = T>,
    {
        let data = format!("0x{}", hex::encode(call.abi_encode()));
        let result_hex: String = self
            .raw(
                "eth_call",
                (
                    CallObj {
                        from: format!("0x{}", hex::encode(Address::ZERO)),
                        to: format!("0x{}", hex::encode(to)),
                        data,
                    },
                    "latest",
                ),
            )
            .await?;
        let bytes = hex::decode(result_hex.trim_start_matches("0x"))?;
        C::abi_decode_returns(&bytes).map_err(|e| BatchError::AbiDecode(e.to_string()))
    }

    async fn nonce(&self, addr: Address) -> Result<u64, BatchError> {
        let hex_str: String = self
            .raw(
                "eth_getTransactionCount",
                (format!("0x{}", hex::encode(addr)), "pending"),
            )
            .await?;
        u64::from_str_radix(hex_str.trim_start_matches("0x"), 16)
            .map_err(|e| BatchError::Rpc(format!("nonce parse: {e}")))
    }

    /// EIP-1559 fee parameters as `(max_priority_fee_per_gas, max_fee_per_gas)`.
    ///
    /// The ceiling is `2 × base_fee + tip`. Base fee can rise at most
    /// 12.5% per block, so 2× survives ~6 consecutive maximally-full
    /// blocks — and because the excess is never charged, the headroom is
    /// free. The amount actually paid is `base_fee + tip` at inclusion.
    async fn fee_params(&self) -> Result<(U256, U256), BatchError> {
        let head: BlockHeader = self.raw("eth_getBlockByNumber", ("pending", false)).await?;
        let base_fee = match head.base_fee_per_gas.as_deref() {
            Some(h) => parse_u256_hex(h)?,
            // Pre-London or a non-1559 chain: nothing to outrun.
            None => U256::ZERO,
        };
        // Node-suggested tip. Not every endpoint implements
        // `eth_maxPriorityFeePerGas`; fall back to deriving it from the
        // legacy suggestion.
        let tip = match self
            .raw::<_, String>("eth_maxPriorityFeePerGas", Vec::<()>::new())
            .await
        {
            Ok(h) => parse_u256_hex(&h)?,
            Err(_) => {
                let h: String = self.raw("eth_gasPrice", Vec::<()>::new()).await?;
                parse_u256_hex(&h)?.saturating_sub(base_fee)
            }
        };
        Ok((tip, base_fee * U256::from(2) + tip))
    }

    async fn estimate_gas(
        &self,
        from: Address,
        to: Address,
        data: &[u8],
    ) -> Result<u64, BatchError> {
        let hex_str: String = self
            .raw(
                "eth_estimateGas",
                [CallObj {
                    from: format!("0x{}", hex::encode(from)),
                    to: format!("0x{}", hex::encode(to)),
                    data: format!("0x{}", hex::encode(data)),
                }],
            )
            .await?;
        u64::from_str_radix(hex_str.trim_start_matches("0x"), 16)
            .map_err(|e| BatchError::Rpc(format!("gas parse: {e}")))
    }

    async fn send_signed(
        &self,
        signer: &PrivateKeySigner,
        chain_id: u64,
        to: Address,
        data: &[u8],
    ) -> Result<B256, BatchError> {
        let from = signer.address();
        let nonce = self.nonce(from).await?;
        let (max_priority_fee, max_fee) = self.fee_params().await?;
        // Bump gas estimate by 25% — `createBatch` calls into the
        // ordered-tree library which has variable cost depending on
        // tree depth. Unlike the fee ceiling, an overestimate here is
        // refunded, so this only sets how much gas the tx *may* burn.
        let gas = self.estimate_gas(from, to, data).await? * 125 / 100;
        let raw = sign_eip1559_tx(
            signer,
            chain_id,
            nonce,
            max_priority_fee,
            max_fee,
            gas,
            to,
            data,
        )?;
        let hex_str: String = self
            .raw(
                "eth_sendRawTransaction",
                [format!("0x{}", hex::encode(&raw))],
            )
            .await?;
        Ok(hex_str
            .parse()
            .map_err(|e| BatchError::Rpc(format!("tx hash parse: {e}")))?)
    }

    async fn wait_for_success(
        &self,
        tx_hash: B256,
        timeout: Duration,
    ) -> Result<ReceiptResp, BatchError> {
        let start = std::time::Instant::now();
        loop {
            let r: Option<ReceiptResp> = self
                .raw_opt(
                    "eth_getTransactionReceipt",
                    [format!("0x{}", hex::encode(tx_hash))],
                )
                .await?;
            if let Some(rcpt) = r {
                let ok =
                    u64::from_str_radix(rcpt.status.trim_start_matches("0x"), 16).unwrap_or(0) == 1;
                if !ok {
                    return Err(BatchError::Reverted);
                }
                return Ok(rcpt);
            }
            if start.elapsed() > timeout {
                return Err(BatchError::ReceiptTimeout);
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// EIP-1559 (type-2) transaction signing
// ──────────────────────────────────────────────────────────────────────

/// Build a signed EIP-1559 (type-2) transaction.
/// Returns `0x02 || rlp([...])`, ready for `eth_sendRawTransaction`.
fn sign_eip1559_tx(
    signer: &PrivateKeySigner,
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: U256,
    max_fee_per_gas: U256,
    gas_limit: u64,
    to: Address,
    data: &[u8],
) -> Result<Vec<u8>, BatchError> {
    // Sighash preimage: keccak256(0x02 || rlp([chainId, nonce,
    //   maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data,
    //   accessList]))
    let mut sighash_payload = vec![TX_TYPE_EIP1559];
    encode_1559_fields(
        &mut sighash_payload,
        chain_id,
        nonce,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        to,
        U256::ZERO,
        data,
        None,
    );
    let sighash = keccak256(&sighash_payload);

    let sig = signer
        .sign_hash_sync(&sighash)
        .map_err(|e| BatchError::Rpc(format!("sign: {e}")))?;

    // Type-2 carries a bare y-parity (0/1) — the EIP-155 `chain_id * 2 + 35`
    // encoding is legacy-only, since chainId is now an explicit field.
    let mut out = vec![TX_TYPE_EIP1559];
    encode_1559_fields(
        &mut out,
        chain_id,
        nonce,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        to,
        U256::ZERO,
        data,
        Some((sig.v() as u64, sig.r(), sig.s())),
    );
    Ok(out)
}

/// EIP-2718 envelope discriminator for EIP-1559 transactions.
const TX_TYPE_EIP1559: u8 = 0x02;

/// Encode a type-2 envelope's RLP list.
///
/// `sig = None` yields the 9-field sighash preimage; `Some` appends the
/// `(y_parity, r, s)` triple for the 12-field signed form. Both share this
/// encoder so the signed bytes can't drift from what was actually signed.
#[allow(clippy::too_many_arguments)]
fn encode_1559_fields(
    out: &mut Vec<u8>,
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: U256,
    max_fee_per_gas: U256,
    gas_limit: u64,
    to: Address,
    value: U256,
    data: &[u8],
    sig: Option<(u64, U256, U256)>,
) {
    let mut payload = Vec::new();
    chain_id.encode(&mut payload);
    nonce.encode(&mut payload);
    max_priority_fee_per_gas.encode(&mut payload);
    max_fee_per_gas.encode(&mut payload);
    gas_limit.encode(&mut payload);
    to.encode(&mut payload);
    value.encode(&mut payload);
    data.encode(&mut payload);
    // Empty access list.
    alloy_rlp::Header {
        list: true,
        payload_length: 0,
    }
    .encode(&mut payload);
    if let Some((y_parity, r, s)) = sig {
        y_parity.encode(&mut payload);
        r.encode(&mut payload);
        s.encode(&mut payload);
    }
    let header = alloy_rlp::Header {
        list: true,
        payload_length: payload.len(),
    };
    header.encode(out);
    out.extend_from_slice(&payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-for-byte cross-check of the hand-rolled type-2 envelope against
    /// an independent implementation.
    ///
    /// Recovering the sender from our own sighash preimage would be
    /// vacuous — it round-trips whatever we hashed, correct or not. The
    /// only thing that catches an encoding divergence from consensus is
    /// comparing against a signer we didn't write. Expected value produced
    /// by foundry:
    ///
    /// ```text
    /// cast mktx --private-key 0x2cfe…1569 --nonce 719 --gas-limit 100000 \
    ///   --gas-price 1432 --priority-gas-price 1 --chain 100 --value 0 \
    ///   0x45a1502382541Cd610CC9068e88727426b696293 0xdeadbeef
    /// ```
    #[test]
    fn eip1559_envelope_matches_foundry() {
        let signer: PrivateKeySigner =
            "0x2cfe73bcd53cc2708a35f6f2238e2aeeb0448b65339f43d398e736102a211569"
                .parse()
                .unwrap();
        let raw = sign_eip1559_tx(
            &signer,
            100,
            719,
            U256::from(1),
            U256::from(1432),
            100_000,
            "0x45a1502382541Cd610CC9068e88727426b696293"
                .parse()
                .unwrap(),
            &hex::decode("deadbeef").unwrap(),
        )
        .unwrap();
        assert_eq!(
            raw[0], TX_TYPE_EIP1559,
            "must be an EIP-2718 type-2 envelope"
        );
        assert_eq!(hex::encode(&raw), FOUNDRY_REFERENCE_TX);
    }

    const FOUNDRY_REFERENCE_TX: &str = "02f86b648202cf01820598830186a09445a1502382541cd610cc9068e88727426b6962938084deadbeefc001a0730b51de4f0ccabb418de873399fc265c7c7f8d6e397b334f15211d1da551d0fa07391d0301aaa4870a5832730aa05ed0177b4b09ecc4e079000838c109059cab9";

    #[test]
    fn parse_size_binary_units() {
        assert_eq!(parse_size("100MB").unwrap(), 100 * 1024 * 1024);
        assert_eq!(parse_size("2GB").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(
            parse_size("1.5TB").unwrap(),
            (1.5 * 1024.0 * 1024.0 * 1024.0 * 1024.0) as u64
        );
        assert_eq!(parse_size("44.70 kB").unwrap(), (44.70 * 1024.0) as u64);
        assert_eq!(parse_size("1gb").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("4K").unwrap(), 4 * 1024);
    }

    #[test]
    fn parse_size_rejects_garbage() {
        assert!(parse_size("100").is_err()); // no unit
        assert!(parse_size("MB").is_err()); // no number
        assert!(parse_size("100XB").is_err()); // bad unit
    }

    #[test]
    fn parse_duration_units() {
        assert_eq!(parse_duration("24h").unwrap(), 24 * 3600);
        assert_eq!(parse_duration("30d").unwrap(), 30 * 86400);
        assert_eq!(parse_duration("2w").unwrap(), 2 * 7 * 86400);
        assert_eq!(parse_duration("1y").unwrap(), 365 * 86400);
        assert_eq!(parse_duration("12 hours").unwrap(), 12 * 3600);
        assert_eq!(parse_duration("7 days").unwrap(), 7 * 86400);
    }

    #[test]
    fn depth_for_size_matches_calculator() {
        // 1 GB ≈ 0.93 GiB ≤ 2.60 GiB ⇒ depth 21
        assert_eq!(depth_for_size(1_000_000_000), Some(21));
        // 50 GB ≈ 46.57 GiB ≤ 47.06 GiB ⇒ depth 24
        assert_eq!(depth_for_size(50_000_000_000), Some(24));
        // 1 TB = 10^12 B ≈ 931.32 GiB ≤ 993.65 GiB ⇒ depth 28
        assert_eq!(depth_for_size(1_000_000_000_000), Some(28));
        assert_eq!(depth_for_size(1), Some(17));
    }

    #[test]
    fn amount_for_duration_24h() {
        // 24h = 86400s; blocks = 86400 / 5 = 17280; with last_price=1
        // amount = 17280 + 10 (buffer)
        assert_eq!(amount_for_duration(1, 86400), U256::from(17290u64));
    }
}

// ──────────────────────────────────────────────────────────────────────
// Chequebook reads (metered relay — docs/pusher-incentives.md Stage 1)
// ──────────────────────────────────────────────────────────────────────

sol! {
    // ERC20SimpleSwap / SimpleSwapFactory, from
    // github.com/ethersphere/swap-swear-and-swindle.
    function issuer() external view returns (address);
    function paidOut(address beneficiary) external view returns (uint256);
    function bounced() external view returns (bool);
    // NOT `balance()`. `liquidBalance() = balance() - totalHardDeposit`, and
    // `liquidBalanceFor(b) = liquidBalance() + hardDeposits[b].amount`, which
    // is what `_cashChequeInternal` actually pays against. Bee checks
    // `balance()`, counting *other* beneficiaries' hard deposits as our
    // coverage — unsound in general, invisible only because bee never places
    // any (incentives §11.2).
    function liquidBalanceFor(address beneficiary) external view returns (uint256);
    function deployedContracts(address who) external view returns (bool);
}

/// Canonical `SimpleSwapFactory` per chain (`bee/pkg/config/chain.go:66,89`).
/// **Hardcoded on purpose.** A factory address supplied by the client lets it
/// present a contract that returns a forged `issuer()` and
/// `liquidBalanceFor()` and implements `cashChequeBeneficiary` as a no-op —
/// total compromise for one `eth_call` saved (incentives §6).
pub const GNOSIS_SWAP_FACTORY: &str = "0xc2d5a532cf69aa9a1378737d8ccdef884b6e7420";
pub const SEPOLIA_SWAP_FACTORY: &str = "0x0fF044F6bB4F684a5A149B46D7eC03ea659F98A1";

/// The factory for a chain, or `None` if we have no vetted address for it —
/// in which case metered mode must not run, rather than fall back to
/// something the client names.
pub fn swap_factory_for_chain(chain_id: u64) -> Option<Address> {
    let s = match chain_id {
        100 => GNOSIS_SWAP_FACTORY,
        11155111 => SEPOLIA_SWAP_FACTORY,
        _ => return None,
    };
    s.parse().ok()
}

/// What the relay needs to know about a chequebook to accept a cheque
/// drawn on it.
#[derive(Debug, Clone, Copy)]
pub struct ChequebookState {
    pub issuer: Address,
    /// Everything this beneficiary could actually cash right now.
    pub liquid_for_us: U256,
    /// Already cashed by this beneficiary; the cheque's cumulative must
    /// exceed it or there is nothing left to draw.
    pub paid_out_to_us: U256,
    /// Set permanently, contract-wide, the first time any cheque could not
    /// be paid in full. Readable state rather than an event you had to have
    /// been watching for (incentives §11.2).
    pub bounced: bool,
}

/// Is this address a chequebook the canonical factory deployed?
///
/// Cache this forever per address on a `true`, and negative-cache a `false`
/// — it is the first chain read an unauthenticated `/v1/pay` can reach, so
/// an uncached miss is a one-RPC-per-request amplifier (incentives §11.6).
pub async fn is_deployed_chequebook(
    rpc_url: &str,
    factory: Address,
    chequebook: Address,
) -> Result<bool, BatchError> {
    EthRpc::new(rpc_url.to_string())
        .call_view(factory, deployedContractsCall { who: chequebook })
        .await
}

/// Read the four values that decide whether a cheque is worth anything —
/// in **one** JSON-RPC round trip.
///
/// They used to be four sequential `eth_call`s, which put four round trips
/// on the critical path of every `/v1/pay`. They are all reads against the
/// same block, so there is no reason for them to be sequential: batching
/// them makes the miss case one request, and the caller (`Metered`) caches
/// on top so the honest path is usually zero.
pub async fn read_chequebook_state(
    rpc_url: &str,
    chequebook: Address,
    beneficiary: Address,
) -> Result<ChequebookState, BatchError> {
    let rpc = EthRpc::new(rpc_url.to_string());
    let calls = [
        issuerCall {}.abi_encode(),
        liquidBalanceForCall { beneficiary }.abi_encode(),
        paidOutCall { beneficiary }.abi_encode(),
        bouncedCall {}.abi_encode(),
    ];
    let out = rpc.batch_call_view(chequebook, &calls).await?;
    let dec = |i: usize| -> Result<&Vec<u8>, BatchError> {
        out.get(i)
            .ok_or_else(|| BatchError::Rpc("short batch response".into()))
    };
    Ok(ChequebookState {
        issuer: issuerCall::abi_decode_returns(dec(0)?)
            .map_err(|e| BatchError::AbiDecode(e.to_string()))?,
        liquid_for_us: liquidBalanceForCall::abi_decode_returns(dec(1)?)
            .map_err(|e| BatchError::AbiDecode(e.to_string()))?,
        paid_out_to_us: paidOutCall::abi_decode_returns(dec(2)?)
            .map_err(|e| BatchError::AbiDecode(e.to_string()))?,
        bounced: bouncedCall::abi_decode_returns(dec(3)?)
            .map_err(|e| BatchError::AbiDecode(e.to_string()))?,
    })
}

impl EthRpc {
    /// Several `eth_call`s to one contract in a single JSON-RPC batch.
    ///
    /// Results come back keyed by request id rather than in order — the
    /// spec permits a server to reorder them, and some do — so they are
    /// re-sorted before being returned.
    async fn batch_call_view(
        &self,
        to: Address,
        calls: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, BatchError> {
        #[derive(Serialize)]
        struct BatchReq<'a> {
            jsonrpc: &'a str,
            id: usize,
            method: &'a str,
            params: (CallObj, &'a str),
        }
        let to_hex = format!("0x{}", hex::encode(to));
        let reqs: Vec<BatchReq> = calls
            .iter()
            .enumerate()
            .map(|(i, data)| BatchReq {
                jsonrpc: "2.0",
                id: i,
                method: "eth_call",
                params: (
                    CallObj {
                        from: format!("0x{}", hex::encode(Address::ZERO)),
                        to: to_hex.clone(),
                        data: format!("0x{}", hex::encode(data)),
                    },
                    "latest",
                ),
            })
            .collect();
        let resp: Vec<serde_json::Value> = self
            .http
            .post(&self.url)
            .json(&reqs)
            .send()
            .await?
            .json()
            .await?;
        if resp.len() != calls.len() {
            return Err(BatchError::Rpc(format!(
                "batch eth_call: sent {} requests, got {} responses",
                calls.len(),
                resp.len()
            )));
        }
        let mut out = vec![Vec::new(); calls.len()];
        for item in resp {
            if let Some(err) = item.get("error") {
                return Err(BatchError::Rpc(format!("batch eth_call: {err}")));
            }
            let id = item
                .get("id")
                .and_then(|i| i.as_u64())
                .ok_or_else(|| BatchError::Rpc("batch eth_call: missing id".into()))?
                as usize;
            let hex_str = item
                .get("result")
                .and_then(|r| r.as_str())
                .ok_or_else(|| BatchError::Rpc("batch eth_call: missing result".into()))?;
            let slot = out
                .get_mut(id)
                .ok_or_else(|| BatchError::Rpc(format!("batch eth_call: bad id {id}")))?;
            *slot = hex::decode(hex_str.trim_start_matches("0x"))?;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod chequebook_binding_tests {
    use super::*;

    /// Selectors are what the node dispatches on, so a wrong one silently
    /// reads a *different* function rather than failing. Pinned against
    /// `keccak256(signature)[..4]`.
    #[test]
    fn selectors_match_the_solidity_signatures() {
        use alloy_sol_types::SolCall;
        for (got, sig) in [
            (issuerCall::SELECTOR, "issuer()"),
            (paidOutCall::SELECTOR, "paidOut(address)"),
            (bouncedCall::SELECTOR, "bounced()"),
            (liquidBalanceForCall::SELECTOR, "liquidBalanceFor(address)"),
            (
                deployedContractsCall::SELECTOR,
                "deployedContracts(address)",
            ),
        ] {
            let want: [u8; 32] = <sha3::Keccak256 as sha3::Digest>::digest(sig.as_bytes()).into();
            assert_eq!(got, want[..4], "selector drift for {sig}");
        }
    }

    /// A relay must never accept a factory address from the wire, and must
    /// refuse to run metered on a chain it has no vetted factory for.
    #[test]
    fn only_known_chains_have_a_factory() {
        assert!(swap_factory_for_chain(100).is_some(), "gnosis");
        assert!(swap_factory_for_chain(11155111).is_some(), "sepolia");
        assert!(
            swap_factory_for_chain(1).is_none(),
            "mainnet: no vetted factory"
        );
        assert!(swap_factory_for_chain(31337).is_none(), "local devnet");
    }
}

// ──────────────────────────────────────────────────────────────────────
// Chequebook deployment (docs/pusher-incentives.md §14)
// ──────────────────────────────────────────────────────────────────────

sol! {
    // SimpleSwapFactory.deploySimpleSwap(issuer, defaultHardDepositTimeoutDuration, salt)
    function deploySimpleSwap(
        address issuer,
        uint256 defaultHardDepositTimeoutDuration,
        bytes32 salt
    ) external returns (address);

    event SimpleSwapDeployed(address contractAddress);

    function transfer(address to, uint256 amount) external returns (bool);
}

#[derive(Debug, Clone)]
pub struct DeployChequebookParams {
    pub rpc_url: String,
    pub chain_id: u64,
    pub factory: Address,
    /// Must be the **batch owner's** address (§6): a relay only accepts a
    /// cheque whose chequebook `issuer()` equals the account it billed.
    pub issuer: Address,
    pub receipt_timeout: std::time::Duration,
}

#[derive(Debug, Clone)]
pub struct DeployedChequebook {
    pub address: Address,
    pub tx: B256,
    /// True when the address already held code before we sent anything —
    /// the deploy is deterministic in `(issuer, timeout, salt)`, so a repeat
    /// with the same salt would revert rather than make a second one.
    pub already_deployed: bool,
}

/// Deploy a chequebook through bee's canonical factory.
///
/// **Deliberately its own command, never a side effect of an upload.**
/// Deploying a contract is irreversible and spends real funds; an upload
/// that did it silently because some lane quoted a price would fire on the
/// first metered lane a user ever met, before they had decided they wanted
/// to pay at all.
///
/// The hard-deposit timeout is **0**, matching what bee deploys
/// (`init.go:169`). That means deposits are not actually locked — see
/// §11.2 — but it keeps us byte-compatible with every bee chequebook, and
/// a non-zero timeout can be set later per beneficiary via
/// `setCustomHardDepositTimeout` if secured mode is ever wanted.
pub async fn deploy_chequebook(
    signer: &PrivateKeySigner,
    params: DeployChequebookParams,
) -> Result<DeployedChequebook, BatchError> {
    let rpc = EthRpc::new(params.rpc_url.clone());

    let mut salt_bytes = [0u8; 32];
    getrandom::fill(&mut salt_bytes).map_err(|e| BatchError::Rpc(format!("getrandom: {e}")))?;
    let salt = B256::from(salt_bytes);

    let call = deploySimpleSwapCall {
        issuer: params.issuer,
        defaultHardDepositTimeoutDuration: U256::ZERO,
        salt,
    };

    // Simulate first. The factory returns the address it *would* create, so
    // a revert (bad issuer, salt collision) surfaces here for free instead
    // of as a burnt transaction.
    let predicted: Address = rpc.call_view(params.factory, call.clone()).await?;
    let existing = rpc.code_len(predicted).await?;
    if existing > 0 {
        return Ok(DeployedChequebook {
            address: predicted,
            tx: B256::ZERO,
            already_deployed: true,
        });
    }

    let tx = rpc
        .send_signed(signer, params.chain_id, params.factory, &call.abi_encode())
        .await?;
    rpc.wait_for_success(tx, params.receipt_timeout).await?;

    // Trust the chain, not the simulation: read the address back out of the
    // receipt's `SimpleSwapDeployed` log.
    let deployed = rpc.find_deployed_chequebook(tx).await?.unwrap_or(predicted);

    // The relay checks this before accepting any cheque (§6), so checking it
    // here turns "your cheques are silently refused" into a deploy-time
    // error.
    let issuer: Address = rpc.call_view(deployed, issuerCall {}).await?;
    if issuer != params.issuer {
        return Err(BatchError::Rpc(format!(
            "deployed chequebook {deployed} has issuer {issuer}, expected {}",
            params.issuer
        )));
    }
    Ok(DeployedChequebook {
        address: deployed,
        tx,
        already_deployed: false,
    })
}

/// Move BZZ into a chequebook. Plain ERC-20 transfer — the contract holds
/// whatever balance the token says it does, and `liquidBalanceFor` is
/// derived from it.
pub async fn fund_chequebook(
    signer: &PrivateKeySigner,
    rpc_url: &str,
    chain_id: u64,
    bzz_token: Address,
    chequebook: Address,
    amount: U256,
    receipt_timeout: std::time::Duration,
) -> Result<B256, BatchError> {
    let rpc = EthRpc::new(rpc_url.to_string());
    let from = signer.address();
    let balance: U256 = rpc
        .call_view(bzz_token, balanceOfCall { account: from })
        .await?;
    if balance < amount {
        return Err(BatchError::InsufficientBalance {
            have: balance,
            need: amount,
        });
    }
    // Refuse to fund something that is not a chequebook: a mistyped address
    // sends BZZ somewhere unrecoverable.
    let issuer: Address = rpc
        .call_view(chequebook, issuerCall {})
        .await
        .map_err(|e| {
            BatchError::Rpc(format!(
                "{chequebook} does not answer issuer() — is it a chequebook? ({e})"
            ))
        })?;
    if issuer != from {
        return Err(BatchError::Rpc(format!(
            "chequebook {chequebook} is issued by {issuer}, not {from}: only the issuer \
             can ever withdraw, so funding it would strand the deposit"
        )));
    }
    let call = transferCall {
        to: chequebook,
        amount,
    }
    .abi_encode();
    let tx = rpc.send_signed(signer, chain_id, bzz_token, &call).await?;
    rpc.wait_for_success(tx, receipt_timeout).await?;
    Ok(tx)
}

impl EthRpc {
    /// `eth_getCode` length, for "is there already a contract here".
    async fn code_len(&self, addr: Address) -> Result<usize, BatchError> {
        let hex_str: String = self
            .raw(
                "eth_getCode",
                (format!("0x{}", hex::encode(addr)), "latest"),
            )
            .await?;
        Ok(hex_str.trim_start_matches("0x").len() / 2)
    }

    /// Pull the chequebook address out of a deploy receipt's logs.
    async fn find_deployed_chequebook(&self, tx: B256) -> Result<Option<Address>, BatchError> {
        let receipt: serde_json::Value = self
            .raw(
                "eth_getTransactionReceipt",
                (format!("0x{}", hex::encode(tx)),),
            )
            .await?;
        let topic = SimpleSwapDeployed::SIGNATURE_HASH;
        let Some(logs) = receipt.get("logs").and_then(|l| l.as_array()) else {
            return Ok(None);
        };
        for log in logs {
            let topics: Vec<String> = log
                .get("topics")
                .and_then(|t| t.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            if topics
                .first()
                .map(|t| t.trim_start_matches("0x").to_lowercase())
                != Some(hex::encode(topic))
            {
                continue;
            }
            // Non-indexed single address parameter: it is the data word.
            if let Some(data) = log.get("data").and_then(|d| d.as_str()) {
                let raw = hex::decode(data.trim_start_matches("0x"))
                    .map_err(|e| BatchError::Rpc(format!("log data hex: {e}")))?;
                if raw.len() >= 32 {
                    return Ok(Some(Address::from_slice(&raw[12..32])));
                }
            }
        }
        Ok(None)
    }
}

// ──────────────────────────────────────────────────────────────────────
// Cashing out (docs/pusher-incentives.md §14 Stage 2)
// ──────────────────────────────────────────────────────────────────────

sol! {
    function cashChequeBeneficiary(
        address recipient,
        uint256 cumulativePayout,
        bytes issuerSig
    ) external;
}

/// What a cheque is actually worth right now, before spending gas on it.
#[derive(Debug, Clone, Copy)]
pub struct CashoutQuote {
    /// `cumulative - paidOut(beneficiary)`: what is still unclaimed.
    pub requested_plur: U256,
    /// `min(requested, liquidBalanceFor(beneficiary))` — what the contract
    /// would actually transfer.
    pub payable_plur: U256,
    /// True when the chequebook cannot cover the whole claim. The cashout
    /// still succeeds and takes what is there — `_cashChequeInternal` does
    /// not revert — but it sets `bounced` permanently.
    pub would_bounce: bool,
    pub already_bounced: bool,
}

/// Price a cheque without sending anything.
///
/// Worth doing first because gas is spent whether or not the cheque is
/// worth cashing, and a cumulative at or below `paidOut` transfers nothing
/// at all.
pub async fn quote_cashout(
    rpc_url: &str,
    chequebook: Address,
    beneficiary: Address,
    cumulative_plur: U256,
) -> Result<CashoutQuote, BatchError> {
    let st = read_chequebook_state(rpc_url, chequebook, beneficiary).await?;
    let requested_plur = cumulative_plur.saturating_sub(st.paid_out_to_us);
    let payable_plur = requested_plur.min(st.liquid_for_us);
    Ok(CashoutQuote {
        requested_plur,
        payable_plur,
        would_bounce: payable_plur < requested_plur,
        already_bounced: st.bounced,
    })
}

/// Present a cheque on-chain.
///
/// **Must be sent by the beneficiary**: `cashChequeBeneficiary` passes
/// `msg.sender` as the beneficiary into `_cashChequeInternal`, so the
/// signing key here is the EOA the cheques were made out to — never the
/// relay's, which is why this is a separate command run somewhere else
/// (§6). `recipient` is where the BZZ lands and may differ.
pub async fn cash_cheque(
    beneficiary_signer: &PrivateKeySigner,
    rpc_url: &str,
    chain_id: u64,
    chequebook: Address,
    recipient: Address,
    cumulative_plur: U256,
    signature: &[u8; 65],
    receipt_timeout: std::time::Duration,
) -> Result<B256, BatchError> {
    // The contract verifies through OpenZeppelin's ECDSA, which rejects
    // high-s and v ∉ {27,28}. A non-canonical signature reverts and burns
    // the gas, so refuse it here where it costs nothing.
    crate::signer::check_canonical_signature(signature)
        .map_err(|e| BatchError::Rpc(format!("stored cheque is not cashable: {e}")))?;
    let rpc = EthRpc::new(rpc_url.to_string());
    let call = cashChequeBeneficiaryCall {
        recipient,
        cumulativePayout: cumulative_plur,
        issuerSig: signature.to_vec().into(),
    }
    .abi_encode();
    let tx = rpc
        .send_signed(beneficiary_signer, chain_id, chequebook, &call)
        .await?;
    rpc.wait_for_success(tx, receipt_timeout).await?;
    Ok(tx)
}

#[cfg(test)]
mod cashout_tests {
    use super::*;

    #[test]
    fn the_cashout_selector_matches_the_contract() {
        use alloy_sol_types::SolCall;
        let want: [u8; 32] = <sha3::Keccak256 as sha3::Digest>::digest(
            "cashChequeBeneficiary(address,uint256,bytes)".as_bytes(),
        )
        .into();
        assert_eq!(cashChequeBeneficiaryCall::SELECTOR, want[..4]);
    }
}
