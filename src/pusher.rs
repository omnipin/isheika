//! `hoverfly pusher` — HTTP chunk-push relay, stages A+B implemented
//! (docs/pusher-design.md §11).
//!
//! Routes:
//!
//! - `POST /v1/push` — the real relay endpoint (stage B): pre-signed
//!   frames in (docs/pusher-design.md §3), streamed NDJSON acks out.
//!   Open mode: a chunk is accepted iff its stamp signature recovers to
//!   the on-chain owner of a **live** batch (owner + `remainingBalance >
//!   0`, both cached — one RPC pair per batch). Keys stay strictly
//!   client-side; the pusher only ever sees pre-signed material.
//! - `GET /v1/status` — health/advertisement JSON. Doubles as the
//!   platform health check on Render/Lambda-style hosts.
//! - `POST /v1/probe?size=N&concurrency=M&max_retries=R` — flag-gated
//!   (`--probe`) self-push experiment endpoint: generates `size` bytes of
//!   random data, stamps it with an env-provided throwaway key/batch
//!   (`HOVERFLY_PROBE_KEY`, `HOVERFLY_PROBE_BATCH`), runs the standard
//!   one-shot push path, and streams NDJSON progress lines followed by a
//!   final metrics report (throughput, `transport::diag` counter deltas,
//!   dial reachability split, per-host dial-failure clustering). This was
//!   the instrument for the shared-cloud-egress-IP gate experiment
//!   (stage A, results in the design doc); it stays as a diagnostics
//!   endpoint.
//! - `POST /v1/tcpcheck?targets=…` — flag-gated raw TCP connect tester
//!   (network-layer vs application-layer throttling discriminator).
//!
//! Probe mode is the one sanctioned exception to "the pusher never
//! signs": it signs with its *own* env key against a dust batch, exists
//! only for self-testing, and is off by default.
//!
//! Still open from the design doc: stage C (weighted rendezvous is
//! client-side; `budget_remaining_gb` accounting here), and the deferred
//! `--push-quota` / `--push-challenge` / `--push-allow` hardening.
//!
//! Deliberately absent: IPC socket, retrieval-over-HTTP, any acceptance
//! of key material over the wire.

use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited, StreamBody, combinators::BoxBody};
use hyper::body::Frame;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use tracing::{info, warn};

use crate::client::{
    ProgressFn, SessionPool, StampedChunk, push_chunks_with_pool_ex, upload_bytes_ex,
};
use crate::peers::{DialResult, PeerStore, apply_log};
use crate::pushframe;
use crate::signer::SwarmSigner;
use crate::transport::{Transport, TransportConfig, diag};

/// Max frames per POST /v1/push (also bounds decode allocation).
const PUSH_BATCH_MAX: usize = 512;
/// Max /v1/push body: PUSH_BATCH_MAX × max frame + slack.
const PUSH_MAX_BODY: usize = PUSH_BATCH_MAX * pushframe::MAX_FRAME_LEN + 4096;
/// Default warm-pool target for the push path, overridable via
/// `HOVERFLY_PUSH_POOL`.
///
/// Was 32, on the theory that a shared cloud /32 starves at ~10–35 live
/// sessions (bee rate-limits inbound dials per /32 at 10/s, burst 40 —
/// docs/pusher-design.md §"Stage A results") so a bigger target would only
/// burn dial churn. **Measured 2026-07 on Render free, that is no longer
/// true**: the pool reaches a full 128/128 and the difference is not
/// marginal. Single-lane, 2 MiB, same platform, same hour:
///
/// | pool | throughput | shallow receipts per chunk | best available PO |
/// |------|------------|----------------------------|-------------------|
/// | 32   | 14.2 KiB/s | 8.1                        | 3.61              |
/// | 128  | 37.0 KiB/s | 0.44                       | 4.70              |
///
/// The mechanism is the shallow-receipt cascade: a small pool means the
/// closest session to a given chunk is far from it (best available PO ~3.6
/// vs ~4.7), so bee forwards instead of storing, the dispatcher gets a
/// shallow receipt and retries against another peer — 8 wasted pushes per
/// chunk at pool 32 against 0.44 at pool 128.
///
/// Raising the target is safe on a genuinely rate-limited host: `top_up` is
/// best-effort, so a pool that *can't* reach the target simply doesn't, and
/// `/v1/status` advertises `pool.live` so the client's scheduler weights the
/// lane by what it actually achieved rather than what it asked for.
const PUSH_POOL_TARGET_DEFAULT: usize = 128;
/// Clamp for the env override.
const PUSH_POOL_TARGET_MAX: usize = 512;
/// Per-chunk retry budget on the push path.
const PUSH_MAX_RETRIES: usize = 20;
/// Default cap on concurrent inbound connections
/// (`HOVERFLY_PUSH_MAX_CONNS`). A `/v1/push` in flight holds its collected
/// body plus decoded frames — a couple of MiB at `PUSH_BATCH_MAX` — so an
/// uncapped accept loop is an uncapped memory commitment.
const PUSH_MAX_CONNS_DEFAULT: usize = 256;
/// Ceiling on the accept-loop retry backoff.
const ACCEPT_BACKOFF_MAX_MS: u64 = 1000;
/// How long a connection may take to send its request headers. Only the
/// header read — response streaming is unbounded by design.
const HEADER_READ_TIMEOUT_SECS: u64 = 30;
/// How long `/v1/push` may take to receive its (already size-capped) body.
/// Generous for ~2 MiB on a slow mobile link, but finite: the read happens
/// before any work is spawned, so an unbounded one is free to hold.
const PUSH_BODY_READ_TIMEOUT_SECS: u64 = 120;
/// Bound on the `batch_id → owner` cache. Batch ids are enumerable
/// on-chain (`BatchCreated`), so an unbounded map is a remote memory sink.
const OWNER_CACHE_CAP: usize = 4096;
/// How long a successful batch resolution stays cached. Bounded so a batch
/// that expires while cached stops being served indefinitely.
const OWNER_OK_TTL_SECS: u64 = 1800;
/// How long a *definitive* rejection (absent on-chain, or expired) stays
/// cached. This is what stops a flood of bogus batch ids from turning one
/// unauthenticated POST into one RPC round trip per frame.
const OWNER_BAD_TTL_SECS: u64 = 300;
/// Distinct batch resolutions that may reach the chain in a single POST.
/// Honest clients push one or a few batches per request; this bounds the
/// RPC amplification of a request that names 512 different ones.
const PUSH_MAX_BATCH_LOOKUPS: usize = 8;
/// Recently-acked address cache: enough to cover several in-flight
/// batches across every lane a client might hedge between.
const RECENT_ACK_CAP: usize = 8192;
/// How long a cached ack answers duplicates. Long enough to absorb a
/// hedge (which fires on the order of one batch deadline) without
/// pretending a chunk pushed minutes ago is still fresh.
const RECENT_ACK_TTL_SECS: u64 = 120;

/// Hard cap on probe payload size — a probe is a measurement, not a
/// bulk upload, and free-tier egress is the budget being measured.
const PROBE_MAX_SIZE: usize = 128 * 1024 * 1024;
const PROBE_DEFAULT_SIZE: usize = 10 * 1024 * 1024;
/// Default matches the concurrency the VPS baseline numbers in
/// PERFORMANCE.md were measured at, so probe reports compare 1:1.
const PROBE_DEFAULT_CONCURRENCY: usize = 64;
/// Same default as `hoverfly upload --max-retries`.
const PROBE_DEFAULT_MAX_RETRIES: usize = 10;

pub struct PusherOpts {
    pub listen: SocketAddr,
    pub peerlist: PathBuf,
    pub probe_enabled: bool,
    /// Overlay nonce (same stable-identity story as the CLI's
    /// `--nonce-file`; see `signer::from_bytes_with_nonce`).
    pub nonce: [u8; 32],
    pub network_id: u64,
    /// Gnosis RPC for probe-mode batch depth/owner resolution.
    pub rpc_url: String,
    /// Optional node-identity secp256k1 key (hex), distinct from the
    /// stamp signer — drives the overlay + libp2p peer-id. From
    /// HOVERFLY_PUSHER_IDENTITY. `None` = reuse the stamp key.
    pub node_identity: Option<String>,
    pub transport: TransportConfig,
    /// Metered mode (`docs/pusher-incentives.md` Stage 1). `None` = `open`,
    /// today's unmetered behaviour, which the production lanes keep running.
    pub meter: Option<MeterOpts>,
}

/// Everything `--meter` needs. Validated at startup: a relay that cannot
/// state its own origin, or whose parameters violate §10.1's invariant,
/// refuses to boot rather than serving a broken meter.
#[derive(Debug, Clone)]
pub struct MeterOpts {
    /// `--origin`, one or more. **Required**, and never derived from a
    /// request header (§11.1).
    pub origins: Vec<String>,
    /// EOA that must appear as `Cheque.beneficiary`. The relay holds the
    /// address only — never the key (§6).
    pub beneficiary: [u8; 20],
    /// Settlement chain. Pins the EIP-712 domain and the factory.
    pub chain_id: u64,
    pub params: crate::meter::Params,
    /// Where the ledger and relay secret live. Required: metered mode
    /// without durable state is an unbounded free-service loop (§11.4).
    pub state_dir: PathBuf,
    /// Stage 2. False = soft mode: meter and report, never refuse.
    pub hard_mode: bool,
}

struct State {
    opts: PusherOpts,
    started: Instant,
    /// Serializes network ops (probe + push): concurrent runs would
    /// pollute each other's diag deltas and fight over the session pool.
    probe_lock: Arc<tokio::sync::Mutex<()>>,
    probe_seq: AtomicU64,
    peers_known: AtomicUsize,
    /// `batch_id → (depth, immutable)` from the on-chain read, so
    /// repeated probes cost one RPC total.
    batch_cache: std::sync::Mutex<HashMap<String, (u8, bool)>>,
    /// Push-path state, built once at startup: the node-identity
    /// transport, the peer cache, and a warm session pool reused across
    /// /v1/push requests (filled lazily on first push). `None` transport
    /// means the node key was unresolvable; /v1/push then 503s.
    push: Option<PushState>,
    /// `batch_id(hex) → resolution`, so repeated pushes for one batch cost a
    /// single RPC. Caches rejections too — see [`OwnerCache`].
    owner_cache: std::sync::Mutex<OwnerCache>,
    /// Stage 0 shadow metering (`src/meter.rs`, incentives §14): counts what
    /// a metered relay *would* have billed, bills nothing, and changes
    /// nothing on the wire. Merged once per request, never per frame.
    meter: std::sync::Mutex<crate::meter::Meter>,
    /// Stage 1 metered mode. `None` in `open` mode, which is every
    /// production lane today.
    metered: Option<crate::metered::Metered>,
}

/// Outcome of resolving a batch id on-chain.
#[derive(Clone)]
enum OwnerLookup {
    /// Batch exists, is funded, and is owned by this address. Carries the
    /// batch's total remaining value in PLUR (`remainingBalance × 2^depth`),
    /// which costs nothing extra — `resolve_owner` already reads both halves
    /// to check for expiry — and is what Stage 0 shadow metering prices a
    /// credit line from (`src/meter.rs`, incentives §10.3).
    Owner([u8; 20], u128),
    /// Batch is *definitively* unusable: absent on-chain, or out of
    /// balance. Carries the reason so the ack is unchanged.
    Rejected(String),
}

/// Bounded, TTL'd `batch_id → outcome` cache.
///
/// Caching only *successes* was a live amplification bug. `stamp::validate`
/// checks that a signature recovers to a non-zero address and nothing else,
/// so any random key over any attacker-chosen batch id reaches the chain
/// read. With no negative entry, every frame naming a bogus batch re-issued
/// the RPC, so one unauthenticated POST of `PUSH_BATCH_MAX` frames became
/// that many serial `eth_call`s. Rejections are cached for a shorter TTL
/// than successes, so a batch that is topped up recovers quickly.
///
/// Only definitive on-chain answers are cached. A transport error is *not*
/// cached — an RPC blip must not blacklist a live batch.
struct OwnerCache {
    map: HashMap<String, (OwnerLookup, Instant)>,
    order: std::collections::VecDeque<String>,
    cap: usize,
}

impl OwnerCache {
    fn new(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: std::collections::VecDeque::new(),
            cap,
        }
    }

    fn get(&self, batch_id_hex: &str) -> Option<OwnerLookup> {
        let (entry, when) = self.map.get(batch_id_hex)?;
        let ttl = match entry {
            OwnerLookup::Owner(..) => OWNER_OK_TTL_SECS,
            OwnerLookup::Rejected(_) => OWNER_BAD_TTL_SECS,
        };
        (when.elapsed() < std::time::Duration::from_secs(ttl)).then(|| entry.clone())
    }

    fn insert(&mut self, batch_id_hex: &str, entry: OwnerLookup) {
        if self
            .map
            .insert(batch_id_hex.to_string(), (entry, Instant::now()))
            .is_none()
        {
            self.order.push_back(batch_id_hex.to_string());
        }
        while self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
    }
}

struct PushState {
    transport: Arc<Transport>,
    peers: Arc<PeerStore>,
    /// Warm pool, filled on first push and reused. `tokio::Mutex` because
    /// fills/pushes await; the pool itself is internally sharded.
    pool: tokio::sync::Mutex<Option<Arc<SessionPool>>>,
    /// Target warm-pool size (from `HOVERFLY_PUSH_POOL`).
    pool_target: usize,
    /// Live session count, published in `/v1/status`. Refreshed by the
    /// maintenance loop so the (sync) status handler never has to touch
    /// the async pool mutex.
    pool_live: AtomicUsize,
    /// The node-identity key. Kept alongside the transport (which owns its
    /// own clone) so the metered quote can be signed without rebuilding it
    /// — it signs prices, never payments, and is not spendable (§6).
    signer: crate::signer::SwarmSigner,
    /// This node's Kademlia overlay (node eth address + nonce). Published
    /// in `/v1/status` so a multi-lane client can route each chunk to the
    /// relay whose overlay is nearest the chunk's destination neighborhood
    /// (proximity rendezvous, docs/pusher-design.md §7).
    overlay: [u8; 32],
    /// Egress budget in GB (`HOVERFLY_PUSH_BUDGET_GB`), and bytes pushed
    /// since boot. Free tiers meter bandwidth, so a lane that has burned
    /// its month should attract less traffic *before* it starts failing.
    /// The client turns `budget_remaining_gb` into a scheduling weight.
    budget_gb: Option<f64>,
    bytes_pushed: AtomicU64,
    /// (Address, batch) pairs acked recently, so a duplicate frame (client
    /// hedging a straggler across two lanes) is answered from cache
    /// instead of paying a second real push. Keyed by batch so a dedup
    /// hit can't substitute another uploader's stamp.
    /// docs/pusher-design.md §7 "ChunkCache".
    recent: std::sync::Mutex<RecentAcks>,
}

/// Bounded, TTL'd set of recently-acked (chunk address, batch).
///
/// Keyed on the batch too: a chunk address is content-derived, so it is
/// not unique across batch owners. Under a bare-address key a dedup hit
/// acks a frame `ok` while silently discarding the submitted stamp — one
/// uploader's dust batch could shadow another uploader's long-lived
/// batch for the TTL, and the victim's chunk is then garbage-collected
/// when the shadowing batch expires (docs/pusher-incentives.md §15). It
/// also fires spuriously between honest users uploading identical bytes.
///
/// Insert order doubles as eviction order (a chunk's ack time only moves
/// forward), so a `VecDeque` of `((addr, batch), when)` plus a `HashMap`
/// index is enough — no LRU bookkeeping, since re-acking an entry
/// doesn't need to extend its life.
struct RecentAcks {
    seen: HashMap<([u8; 32], [u8; 32]), Instant>,
    order: std::collections::VecDeque<([u8; 32], [u8; 32])>,
    cap: usize,
    ttl: std::time::Duration,
}

impl RecentAcks {
    fn new(cap: usize, ttl: std::time::Duration) -> Self {
        Self {
            seen: HashMap::new(),
            order: std::collections::VecDeque::new(),
            cap,
            ttl,
        }
    }

    fn contains(&self, addr: &[u8; 32], batch_id: [u8; 32]) -> bool {
        self.seen
            .get(&(*addr, batch_id))
            .is_some_and(|t| t.elapsed() < self.ttl)
    }

    fn insert(&mut self, addr: [u8; 32], batch_id: [u8; 32]) {
        let key = (addr, batch_id);
        if self.seen.insert(key, Instant::now()).is_none() {
            self.order.push_back(key);
        }
        while self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                // Only drop the index entry if it wasn't re-inserted
                // (re-insert keeps a single order slot, so this is just
                // belt-and-braces against a stale key lingering).
                self.seen.remove(&old);
            }
        }
    }
}

type RespBody = BoxBody<Bytes, Infallible>;

pub async fn run(opts: PusherOpts) -> Result<(), Box<dyn std::error::Error>> {
    let peers_known = PeerStore::load_or_create(&opts.peerlist).len();
    if peers_known == 0 {
        warn!(
            "peerlist {} is empty — probes will fail until it is seeded",
            opts.peerlist.display()
        );
    }
    // Build the push-path node transport once, under the node identity
    // (HOVERFLY_PUSHER_IDENTITY, else a random ephemeral key — which gives
    // an unstable overlay and thus oversaturation drops, so a stable
    // premined identity is strongly recommended for real deployments).
    let push = build_push_state(&opts);
    if push.is_none() {
        warn!("push node identity unresolvable; /v1/push will 503 (probe/status still work)");
    }

    // Metered mode is validated *before* the listener binds. Every failure
    // here is one that would otherwise be discovered by a paying client:
    // a parameter set that bricks accounts (§10.1), an origin the relay
    // cannot state (§11.1), a chain with no vetted factory (§6), or state
    // it cannot persist (§11.4). Refuse to boot instead.
    let metered = match build_metered(&opts) {
        Ok(m) => m,
        Err(e) => return Err(format!("--meter: {e}").into()),
    };

    let listener = tokio::net::TcpListener::bind(opts.listen).await?;
    info!(
        "pusher listening on http://{} (probe {}; push {}; mode {}; {} known peers from {})",
        opts.listen,
        if opts.probe_enabled { "ON" } else { "off" },
        if push.is_some() { "ON" } else { "off" },
        if metered.is_some() { "metered" } else { "open" },
        peers_known,
        opts.peerlist.display(),
    );
    let state = Arc::new(State {
        opts,
        started: Instant::now(),
        probe_lock: Arc::new(tokio::sync::Mutex::new(())),
        probe_seq: AtomicU64::new(0),
        peers_known: AtomicUsize::new(peers_known),
        batch_cache: std::sync::Mutex::new(HashMap::new()),
        push,
        owner_cache: std::sync::Mutex::new(OwnerCache::new(OWNER_CACHE_CAP)),
        meter: std::sync::Mutex::new(crate::meter::Meter::default()),
        metered,
    });

    // Background warm-pool maintenance: fill on startup and keep the pool
    // topped up so /v1/push requests find live sessions ready and never
    // dial-burst inline. Gentle cadence stays under bee's per-/32 rate limit.
    if state.push.is_some() {
        let s = state.clone();
        tokio::spawn(async move { push_maintenance(s).await });
    }

    // Bound concurrent connections. The permit is held for the connection's
    // lifetime, so once `max_conns` are in flight the loop stops accepting and
    // the OS backlog supplies the backpressure. Without this the accept loop
    // spawned per connection with no cap at all, and (see the timer below)
    // held those connections open forever.
    let max_conns = std::env::var("HOVERFLY_PUSH_MAX_CONNS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .map(|n| n.clamp(8, 4096))
        .unwrap_or(PUSH_MAX_CONNS_DEFAULT);
    info!("pusher connection cap = {max_conns} (HOVERFLY_PUSH_MAX_CONNS to override)");
    let conns = Arc::new(tokio::sync::Semaphore::new(max_conns));
    let mut accept_backoff_ms = 0u64;

    loop {
        let Ok(permit) = conns.clone().acquire_owned().await else {
            break Ok(()); // semaphore closed — shutting down
        };
        let (stream, remote) = match listener.accept().await {
            Ok(v) => {
                accept_backoff_ms = 0;
                v
            }
            Err(e) => {
                // Per-connection accept errors (EMFILE, ENFILE, ECONNABORTED)
                // are exactly what a connection burst produces against a
                // process that also holds a warm libp2p pool. Propagating
                // them with `?` killed the whole relay; back off instead.
                let wait = accept_backoff_ms.max(10);
                warn!("accept error: {e} — retrying in {wait}ms");
                tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
                accept_backoff_ms = (wait * 2).min(ACCEPT_BACKOFF_MAX_MS);
                continue;
            }
        };
        let io = hyper_util::rt::TokioIo::new(stream);
        let state = state.clone();
        // The peer address from the accept loop, never a client-supplied
        // header: `/v1/challenge` rate-limits per IP, and a limiter keyed on
        // anything the caller controls limits nothing.
        let peer_ip = remote.ip().to_string();
        tokio::spawn(async move {
            // Held until the connection finishes, so the cap above is real.
            let _permit = permit;
            let svc = service_fn(move |req| {
                let state = state.clone();
                let peer_ip = peer_ip.clone();
                async move { Ok::<_, Infallible>(handle(state, req, &peer_ip).await) }
            });
            // A timer MUST be installed or hyper's `header_read_timeout`
            // default is silently inert: with `Time::Empty` the check logs
            // "timeout has default, but no timer set" and returns `None`, so
            // the previous builder had no header timeout whatsoever and a
            // client could hold a connection open indefinitely by dribbling
            // request headers. This bounds only the *request header* read —
            // streamed probe and push responses are unaffected.
            let _ = hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(std::time::Duration::from_secs(HEADER_READ_TIMEOUT_SECS))
                .serve_connection(io, svc)
                .await;
        });
    }
}

async fn handle(
    state: Arc<State>,
    req: Request<hyper::body::Incoming>,
    peer: &str,
) -> Response<RespBody> {
    // Browsers push cross-origin (a dApp on some origin → this relay), with a
    // custom content-type that triggers a CORS preflight. Answer OPTIONS and
    // tag every response with permissive CORS headers — the relay serves no
    // credentialed/secret data, auth is per-frame stamp signatures, so `*` is
    // correct. Without this the browser blocks /v1/push entirely.
    if req.method() == Method::OPTIONS {
        return cors_preflight();
    }
    let mut resp = match (req.method(), req.uri().path()) {
        (&Method::GET, "/v1/status") => status_response(&state),
        (&Method::GET, "/v1/meter") => meter_response(&state, req.headers()),
        (&Method::GET, "/v1/account") => account_response(&state, req.headers()),
        (&Method::GET, "/v1/challenge") => {
            // Per-IP, because no account exists yet. `peer` comes from the
            // accept loop, never from a client-supplied header.
            challenge_response(state, req.uri().query(), peer).await
        }
        (&Method::POST, "/v1/pay") => pay_response(state, req).await,
        (&Method::POST, "/v1/probe") => probe_response(state, req.uri().query()),
        (&Method::POST, "/v1/tcpcheck") => tcpcheck_response(state, req.uri().query()),
        (&Method::POST, "/v1/push") => push_response(state, req).await,
        (_, "/v1/probe")
        | (_, "/v1/status")
        | (_, "/v1/tcpcheck")
        | (_, "/v1/push")
        | (_, "/v1/meter")
        | (_, "/v1/challenge")
        | (_, "/v1/pay")
        | (_, "/v1/account") => {
            json_line_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
        }
        _ => json_line_response(StatusCode::NOT_FOUND, "not found"),
    };
    add_cors(resp.headers_mut());
    resp
}

/// What admission decided, carried into the push task so completion can
/// convert the reservation into debt. `None` in open mode.
///
/// **This is an RAII guard, and it has to be.** A reservation is placed
/// before the body is read, but half a dozen things between there and the
/// push can fail — an oversize body, a read timeout, a frame-decode error,
/// an empty batch. Every one of those returns without ever reaching
/// `run_push`, which is the only place `commit` runs, and `commit` is the
/// only thing besides `release` that lowers `reserved_plur`. Paying a
/// cheque does not help: `Ledger::credit` reduces `owed`, never `reserved`.
///
/// So a leaked reservation is permanent until restart, and it ratchets:
/// under hard mode the account eventually sits above its cap with **no
/// cheque able to clear it** — precisely the no-exit failure §10.1's
/// invariant exists to prevent — and under soft mode the leaks accumulate
/// against `MAX_LIVE_RESERVATIONS` until the relay sheds real clients.
///
/// Releasing on drop makes every exit path correct by construction,
/// including ones added later, which is the whole reason it is a guard
/// rather than four hand-written `release` calls.
pub struct Admitted {
    state: Arc<State>,
    account: [u8; 20],
    batch: [u8; 32],
    reserved_plur: u128,
    settled: bool,
}

impl Admitted {
    /// Convert the reservation into debt for the bytes actually admitted,
    /// releasing the remainder. Consumes the guard, so the `Drop` path
    /// cannot double-release.
    fn commit(mut self, billable_bytes: u64) {
        let Some(m) = self.state.metered.as_ref() else {
            return;
        };
        let billed = m.cfg.params.price_bytes(billable_bytes);
        let mut l = m.ledger.lock().expect("ledger poisoned");
        l.commit(self.account, self.reserved_plur, billed);
        if let Err(e) = l.persist() {
            // `owed` is written at batch completion, so a failed persist
            // forfeits at most this batch — the safe direction (§10.2).
            tracing::error!("ledger persist after commit failed: {e}");
        }
        self.settled = true;
    }
}

impl Drop for Admitted {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        if let Some(m) = self.state.metered.as_ref() {
            m.ledger
                .lock()
                .expect("ledger poisoned")
                .release(self.account, self.reserved_plur);
        }
    }
}

/// Metered admission for `/v1/push` (§7.2).
///
/// Runs before the body is read, and reads **no chain state** — the
/// challenge already carries the credit line, resolved once when it was
/// issued. That is what keeps up to 512 ecrecovers and an RPC round trip
/// off the front of every request.
fn admit_metered(
    state: &Arc<State>,
    req: &Request<hyper::body::Incoming>,
) -> Result<Option<Admitted>, Box<Response<RespBody>>> {
    let Some(m) = state.metered.as_ref() else {
        return Ok(None);
    };
    let raw = req
        .headers()
        .get(crate::challenge::CHALLENGE_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    // **Soft mode never refuses** (§7.1). A request with no challenge is an
    // unmetered request, served exactly as `open` mode serves it, with
    // Stage 0 still shadow-counting it. That is the whole point of shipping
    // soft first: a relay can be flipped to `--meter` while the existing
    // fleet keeps working, because clients that predate the protocol simply
    // do not send the header.
    //
    // Requiring it unconditionally would 401 every current client on the
    // lane the moment metering was enabled — the opposite of a staged
    // rollout. Hard mode does require it, because by then there is a 402 to
    // enforce and a client that cannot present a capability cannot be
    // billed.
    //
    // A header that is *present but invalid* is refused in both modes:
    // claiming a capability you do not hold is not the same as not claiming
    // one, and letting it through would make the check bypassable by
    // corrupting a byte.
    if raw.is_empty() {
        if m.cfg.hard_mode {
            return Err(Box::new(json_line_response(
                StatusCode::UNAUTHORIZED,
                "metered relay: a challenge is required (GET /v1/challenge)",
            )));
        }
        return Ok(None);
    }
    let verified = m
        .verify_header(raw, crate::challenge::now_unix())
        .map_err(|e| Box::new(json_line_response(StatusCode::UNAUTHORIZED, &e)))?;
    if !m.allow_account(&verified.account) {
        return Err(Box::new(json_line_response(
            StatusCode::TOO_MANY_REQUESTS,
            "slow down",
        )));
    }
    // The reservation ledger is attacker-influenced (one entry per batch in
    // standing), so shed rather than grow without bound (§7.2).
    if m.shed_reservations() {
        return Err(Box::new(json_line_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "too many accounts with live reservations",
        )));
    }
    // Bound the reservation by the *declared* body. Same quantity, same
    // arithmetic as the eventual bill (§8), so there is no estimate to be
    // wrong about — and a one-frame POST reserves one frame's worth rather
    // than a flat PUSH_BATCH_MAX, which is what keeps small batches usable.
    let declared = req
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    let Some(declared) = declared else {
        return Err(Box::new(json_line_response(
            StatusCode::LENGTH_REQUIRED,
            "metered mode requires Content-Length so the reservation can be bounded",
        )));
    };
    if declared > PUSH_MAX_BODY as u64 {
        return Err(Box::new(json_line_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body exceeds limit",
        )));
    }
    let adm = m.reserve_for_body(verified.account, declared, verified.cap_plur);
    if adm.over_cap {
        if m.cfg.hard_mode {
            // Hard mode: give the reservation back, then refuse. Keeping it
            // would leak credit on every refusal.
            m.ledger
                .lock()
                .expect("ledger poisoned")
                .release(verified.account, adm.reserved_plur);
            return Err(Box::new(json_response(
                StatusCode::PAYMENT_REQUIRED,
                &serde_json::json!({
                    "error": "payment required",
                    "outstanding_plur": adm.outstanding_plur.to_string(),
                    "max_outstanding_plur": adm.cap_plur.to_string(),
                    "settle_every_plur": m.cfg.params.settle_every_plur.to_string(),
                }),
            )));
        }
        // Soft mode: record and serve anyway. This is the instrument Stage 0
        // could not provide — how often a real client *would* have been
        // 402'd, measured against live traffic before anyone is refused.
        tracing::info!(
            account = %hex::encode(verified.account),
            outstanding_plur = %adm.outstanding_plur,
            cap_plur = %adm.cap_plur,
            "soft-mode overshoot: this request would 402 under hard mode"
        );
    }
    Ok(Some(Admitted {
        state: state.clone(),
        account: verified.account,
        batch: verified.batch,
        reserved_plur: adm.reserved_plur,
        settled: false,
    }))
}

/// Validate `--meter` and build the metered state, or `None` for `open`.
///
/// Every check here is one a paying client would otherwise discover the
/// hard way, so all of them are fatal rather than warnings.
fn build_metered(opts: &PusherOpts) -> Result<Option<crate::metered::Metered>, String> {
    let Some(m) = &opts.meter else {
        return Ok(None);
    };
    m.params.validate()?;
    if m.origins.is_empty() || m.origins.iter().any(|o| o.trim().is_empty()) {
        return Err(
            "--origin is required and must be non-empty: the relay compares a challenge's \
             origin against configuration, never against the Host header, and a relay that \
             cannot state its own hostname cannot close the cross-relay replay (§11.1)"
                .into(),
        );
    }
    let factory = crate::batch::swap_factory_for_chain(m.chain_id).ok_or_else(|| {
        format!(
            "no vetted SimpleSwapFactory for chain {}: a factory address must never come \
             from the wire, so metered mode cannot run here (§6)",
            m.chain_id
        )
    })?;
    if m.beneficiary == [0u8; 20] {
        return Err("--beneficiary must be set: it is the EOA cheques are made out to".into());
    }
    std::fs::create_dir_all(&m.state_dir)
        .map_err(|e| format!("--state-dir {}: {e}", m.state_dir.display()))?;
    let ledger =
        crate::ledger::Ledger::load_or_create(m.state_dir.join("ledger.json")).map_err(|e| {
            format!(
                "ledger at {}: {e} — metered mode requires durable state, because losing \
                 last_cumulative turns one signature into unlimited free service (§11.4)",
                m.state_dir.display()
            )
        })?;
    info!(
        "metered mode: origin(s) {} beneficiary 0x{} chain {} price {} PLUR/KiB ({} mode)",
        m.origins.join(","),
        hex::encode(m.beneficiary),
        m.chain_id,
        m.params.price_plur_per_kib,
        if m.hard_mode { "hard" } else { "soft" },
    );
    Ok(Some(crate::metered::Metered::new(
        crate::metered::MeterConfig {
            origins: m.origins.clone(),
            beneficiary: m.beneficiary,
            chain_id: m.chain_id,
            factory,
            params: m.params,
            hard_mode: m.hard_mode,
        },
        ledger,
    )))
}

/// `GET /v1/challenge?account=&batch=` — issue a capability (§7.2).
///
/// This is where the chain reads happen: standing is resolved once, priced
/// into a credit line, and baked into the nonce, so `/v1/push` admission
/// touches no chain state at all. Amplification is bounded by *distinct
/// batch ids* rather than request count, because the owner cache answers
/// repeats — plus a per-IP limit on top.
async fn challenge_response(
    state: Arc<State>,
    query: Option<&str>,
    peer_ip: &str,
) -> Response<RespBody> {
    let Some(m) = state.metered.as_ref() else {
        return json_line_response(StatusCode::NOT_FOUND, "relay is not metered");
    };
    if !m.allow_challenge(peer_ip) {
        return json_line_response(StatusCode::TOO_MANY_REQUESTS, "slow down");
    }
    let q = parse_query(query);
    let (Some(account_hex), Some(batch_hex)) = (q.get("account"), q.get("batch")) else {
        return json_line_response(StatusCode::BAD_REQUEST, "need account= and batch=");
    };
    let account = match parse_hex_array::<20>(account_hex) {
        Ok(a) => a,
        Err(e) => return json_line_response(StatusCode::BAD_REQUEST, &format!("account: {e}")),
    };
    let batch = match parse_hex_array::<32>(batch_hex) {
        Ok(b) => b,
        Err(e) => return json_line_response(StatusCode::BAD_REQUEST, &format!("batch: {e}")),
    };
    let batch_id_hex = hex::encode(batch);
    let mut budget = 1usize;
    let (owner, remaining_value) = match resolve_owner(&state, &batch_id_hex, &mut budget).await {
        Ok(v) => v,
        Err(e) => return json_line_response(StatusCode::BAD_REQUEST, &e),
    };
    // No nonce for a batch this account does not own. Without this,
    // admission would grant a reservation to any EOA that can sign, and
    // free identities could occupy ledger entries without owning anything.
    if owner != account {
        return json_line_response(
            StatusCode::FORBIDDEN,
            "account is not the on-chain owner of that batch",
        );
    }
    let origin = m.cfg.origins.first().cloned().unwrap_or_default();
    match m.issue(
        account,
        batch,
        remaining_value,
        &origin,
        crate::challenge::now_unix(),
    ) {
        Ok(issued) => json_response(StatusCode::OK, &issued.to_json()),
        Err(e) => json_line_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `POST /v1/pay` — accept a cheque (§11.6).
///
/// Ordered cheapest-first, but the *bound* comes from the two free refusals
/// at the top: a challenge is required, and an account with no debt cannot
/// spend a single `eth_call`. Without those, every "free" check passes for
/// a cheque an attacker synthesizes at zero cost and each garbage POST buys
/// one `deployedContracts` call.
async fn pay_response(
    state: Arc<State>,
    req: Request<hyper::body::Incoming>,
) -> Response<RespBody> {
    let Some(m) = state.metered.as_ref() else {
        return json_line_response(StatusCode::NOT_FOUND, "relay is not metered");
    };
    let header = req
        .headers()
        .get(crate::challenge::CHALLENGE_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let verified = match m.verify_header(&header, crate::challenge::now_unix()) {
        Ok(v) => v,
        Err(e) => return json_line_response(StatusCode::UNAUTHORIZED, &e),
    };
    if !m.allow_account(&verified.account) {
        return json_line_response(StatusCode::TOO_MANY_REQUESTS, "slow down");
    }
    // No debt, no cheque — before parsing anything. Postpaid means an honest
    // client always has debt by the time it settles, so this costs nothing
    // legitimate and makes the endpoint useless to anyone who has not first
    // done billable work.
    let owed = m
        .ledger
        .lock()
        .expect("ledger poisoned")
        .owed(&verified.account);
    if owed == 0 {
        return json_line_response(StatusCode::BAD_REQUEST, "nothing owed on this account");
    }

    let body = match read_body_limited(req, crate::protocols::swap::MAX_CHEQUE_JSON).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let cheque = match crate::protocols::swap::decode_signed_cheque_json(&body) {
        Ok(c) => c,
        Err(e) => return json_line_response(StatusCode::BAD_REQUEST, &e.to_string()),
    };
    if cheque.beneficiary != m.cfg.beneficiary {
        return json_line_response(StatusCode::BAD_REQUEST, "cheque is not made out to us");
    }
    let cumulative: u128 = match u128::try_from(cheque.cumulative_payout) {
        Ok(v) if v <= crate::ledger::MAX_CUMULATIVE_PLUR => v,
        _ => {
            return json_line_response(StatusCode::BAD_REQUEST, "cumulative payout is implausible");
        }
    };
    let have = m
        .ledger
        .lock()
        .expect("ledger poisoned")
        .last_cumulative(&verified.account, &cheque.chequebook);
    if cumulative <= have {
        return json_line_response(
            StatusCode::BAD_REQUEST,
            &format!("cheque cumulative {cumulative} does not exceed the {have} already accepted"),
        );
    }
    // Against the floor this account can actually reach, not the configured
    // one: a batch whose credit line is below `min_cheque_plur` would
    // otherwise be refused for a cheque it is structurally incapable of
    // writing (§10.1, `Params::effective`).
    let floor = m.cfg.params.effective(verified.cap_plur).min_cheque_plur;
    if cumulative - have < floor {
        return json_line_response(
            StatusCode::BAD_REQUEST,
            &format!(
                "cheque credits {} but the dust floor is {floor}",
                cumulative - have,
            ),
        );
    }
    // Every free check has passed; only now does this cost RPC.
    match m.is_deployed(&state.opts.rpc_url, cheque.chequebook).await {
        Ok(true) => {}
        Ok(false) => {
            return json_line_response(
                StatusCode::BAD_REQUEST,
                "chequebook was not deployed by the canonical factory",
            );
        }
        Err(e) => return json_line_response(StatusCode::BAD_GATEWAY, &e),
    }
    let issuer_ok = crate::signer::recover_cheque_issuer(
        &cheque.chequebook,
        &cheque.beneficiary,
        cheque.cumulative_payout,
        m.cfg.chain_id,
        &cheque.signature,
    );
    let recovered = match issuer_ok {
        Ok(a) => a,
        Err(e) => return json_line_response(StatusCode::BAD_REQUEST, &e.to_string()),
    };
    let cb_state = match m
        .chequebook_state(&state.opts.rpc_url, cheque.chequebook)
        .await
    {
        Ok(s) => s,
        Err(e) => return json_line_response(StatusCode::BAD_GATEWAY, &e),
    };
    if cb_state.bounced {
        return json_line_response(
            StatusCode::BAD_REQUEST,
            "chequebook has bounced a cheque before and is refused",
        );
    }
    if cb_state.issuer.into_array() != recovered {
        return json_line_response(
            StatusCode::BAD_REQUEST,
            "cheque was not signed by the issuer",
        );
    }
    if cb_state.issuer.into_array() != verified.account {
        return json_line_response(
            StatusCode::BAD_REQUEST,
            "chequebook issuer is not the account that owns this batch",
        );
    }
    // The funding check, against `liquidBalanceFor(us)` rather than
    // `balance()` — the latter counts other beneficiaries' hard deposits as
    // our coverage, which is unsound (§11.2).
    let paid_out = u128::try_from(cb_state.paid_out_to_us).unwrap_or(u128::MAX);
    let liquid = u128::try_from(cb_state.liquid_for_us).unwrap_or(u128::MAX);
    if liquid < cumulative.saturating_sub(paid_out) {
        return json_line_response(
            StatusCode::BAD_REQUEST,
            "chequebook cannot cover this cheque",
        );
    }
    match m.credit(
        verified.account,
        cheque.chequebook,
        cumulative,
        cheque.signature,
    ) {
        Ok(accepted) => {
            // We just consumed part of what that balance covered; the next
            // cheque should not be judged against the pre-credit reading.
            m.invalidate_chequebook(&cheque.chequebook);
            let l = m.ledger.lock().expect("ledger poisoned");
            json_response(
                StatusCode::OK,
                &serde_json::json!({
                    "accepted_plur": accepted.to_string(),
                    "cumulative": cumulative.to_string(),
                    "owed_plur": l.owed(&verified.account).to_string(),
                    "outstanding_plur": l.outstanding(&verified.account).to_string(),
                }),
            )
        }
        Err(crate::ledger::LedgerError::Store(e)) => {
            tracing::error!("ledger persist after credit failed: {e}");
            json_line_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "ledger write failed; re-present the same cheque",
            )
        }
        Err(e) => json_line_response(StatusCode::BAD_REQUEST, &e.to_string()),
    }
}

/// `GET /v1/account` — the client's own ledger row (§7).
///
/// Authenticated with the challenge header: unauthenticated it is a
/// per-identity volume oracle over on-chain-enumerable batch owners, and a
/// targeting oracle for tipping a victim into 402 at a chosen moment.
fn account_response(state: &State, headers: &hyper::HeaderMap) -> Response<RespBody> {
    let Some(m) = state.metered.as_ref() else {
        return json_line_response(StatusCode::NOT_FOUND, "relay is not metered");
    };
    let raw = headers
        .get(crate::challenge::CHALLENGE_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let verified = match m.verify_header(raw, crate::challenge::now_unix()) {
        Ok(v) => v,
        Err(e) => return json_line_response(StatusCode::UNAUTHORIZED, &e),
    };
    let l = m.ledger.lock().expect("ledger poisoned");
    // Report the *effective* thresholds for this account's line, not the
    // configured ones: `/v1/pay` enforces `effective(cap)`, and a client
    // following the configured numbers would wait for a settlement it can
    // never reach on a small batch (the case `Params::effective` exists for).
    let eff = m.cfg.params.effective(verified.cap_plur);
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "account": format!("0x{}", hex::encode(verified.account)),
            "owed_plur": l.owed(&verified.account).to_string(),
            "reserved_plur": l.reserved(&verified.account).to_string(),
            "outstanding_plur": l.outstanding(&verified.account).to_string(),
            "max_outstanding_plur": verified.cap_plur.to_string(),
            "settle_every_plur": eff.settle_every_plur.to_string(),
            "min_cheque_plur": eff.min_cheque_plur.to_string(),
        }),
    )
}

/// Read a request body with a hard cap, so an oversized one costs nothing.
async fn read_body_limited(
    req: Request<hyper::body::Incoming>,
    max: usize,
) -> Result<Bytes, Response<RespBody>> {
    use http_body_util::BodyExt;
    use hyper::body::Body as _;
    use std::time::Duration;
    // Cheap rejection when the client declares an oversize body up front.
    // This is an optimisation, NOT the bound: `size_hint().upper()` is
    // `None` for a chunked body (and for HTTP/2, where length is unknown
    // until END_STREAM), so a client that omits `Content-Length` skips it
    // entirely.
    if let Some(len) = req.body().size_hint().upper()
        && len > max as u64
    {
        return Err(json_line_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body too large",
        ));
    }
    // The real bound. `Limited` enforces the cap *inside* `poll_frame`, so
    // memory is held to `max` plus one frame. A bare `.collect()` would
    // accumulate whatever the client streams until the timeout fires —
    // ~30 s of link bandwidth per connection, times the connection cap —
    // and only notice afterwards, which is no bound at all.
    match tokio::time::timeout(
        Duration::from_secs(HEADER_READ_TIMEOUT_SECS),
        Limited::new(req.into_body(), max).collect(),
    )
    .await
    {
        Ok(Ok(c)) => {
            let b = c.to_bytes();
            if b.len() > max {
                return Err(json_line_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "body too large",
                ));
            }
            Ok(b)
        }
        Ok(Err(_)) => Err(json_line_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body exceeds limit or read error",
        )),
        Err(_) => Err(json_line_response(
            StatusCode::REQUEST_TIMEOUT,
            "body read timed out",
        )),
    }
}

fn parse_hex_array<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let raw = hex::decode(s.trim_start_matches("0x")).map_err(|e| e.to_string())?;
    if raw.len() != N {
        return Err(format!("must be {N} bytes, got {}", raw.len()));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Body of a maximal POST, for the credit-line comparison in `src/meter.rs`:
/// a batch whose line is under this has to split its uploads across smaller
/// requests (incentives §7.2).
fn full_post_kib() -> u64 {
    (PUSH_BATCH_MAX * pushframe::MAX_FRAME_LEN).div_ceil(1024) as u64
}

/// Completed per-stream push outcomes since boot.
///
/// Incentives §9.1 reads this over frames admitted as an egress multiplier,
/// and **it undercounts**: the counters are bumped after the await inside
/// the racing future (`src/client.rs:5818-5870`), and the dispatcher
/// cancels the losing racers as soon as it takes a receipt
/// (`src/client.rs:4806-4809`). A cancelled racer has already put its
/// Delivery on the wire — the relay pays that egress — but never reaches
/// the increment. Shallow retries and errors are counted; concurrent
/// losers are not, so the ratio floors near 1.0 whenever the race is won
/// promptly. Counting at dispatch, beside `inflight_pushes`, would fix it.
fn stream_attempts() -> u64 {
    use crate::transport::diag;
    use std::sync::atomic::Ordering;
    diag::PUSH_OUTCOME_OK.load(Ordering::Relaxed)
        + diag::PUSH_OUTCOME_SHALLOW.load(Ordering::Relaxed)
        + diag::PUSH_OUTCOME_OVERDRAFT.load(Ordering::Relaxed)
        + diag::PUSH_OUTCOME_ERROR.load(Ordering::Relaxed)
}

/// `GET /v1/meter` — Stage 0 shadow-metering detail (incentives §14).
///
/// **Open by default; set `HOVERFLY_PUSH_METER_TOKEN` to require a bearer
/// token.** Stage 0's rows are derived from state that is already public:
/// batch owners and their balances are on-chain and enumerable from
/// `BatchCreated`, and the stamp on every relayed chunk names its batch,
/// which retrieval hands back (incentives §2). All this endpoint adds is
/// relay attribution and timing, so gating it by default buys little and
/// costs a lot — an instrument nobody reads answers no questions, and
/// deciding whether to meter at all is the only reason Stage 0 exists.
///
/// That flips at **Stage 1**, and the reason is worth recording because it
/// is not the obvious one. Once 402s are live, `/v1/account` exposes an
/// account's *outstanding* balance, which lets a reader time a stamp replay
/// (§11.1) to tip a victim over its cap mid-upload. That is an active
/// attack enabler rather than a privacy leak, and it is the real reason
/// incentives §7 authenticates that endpoint.
fn meter_response(state: &State, headers: &hyper::HeaderMap) -> Response<RespBody> {
    if let Ok(want) = std::env::var("HOVERFLY_PUSH_METER_TOKEN") {
        let got = headers
            .get(hyper::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or_default();
        // Compare the *contents* in constant time — a byte-wise early exit
        // would let the token be ground out one character at a time. Length
        // is compared directly and so is observable, which is fine: it is a
        // static property of the operator's config, not something an
        // attacker can narrow down to a value.
        let ok = got.len() == want.len()
            && got
                .bytes()
                .zip(want.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0;
        if !ok {
            return json_line_response(StatusCode::UNAUTHORIZED, "unauthorized");
        }
    }
    let body =
        state
            .meter
            .lock()
            .expect("meter poisoned")
            .detail(full_post_kib(), stream_attempts(), 100);
    json_response(StatusCode::OK, &body)
}

/// Add permissive CORS headers to a response.
fn add_cors(h: &mut hyper::HeaderMap) {
    use hyper::header::HeaderValue;
    h.insert("access-control-allow-origin", HeaderValue::from_static("*"));
    h.insert(
        "access-control-expose-headers",
        HeaderValue::from_static("*"),
    );
}

/// 204 response for a CORS preflight (`OPTIONS`).
fn cors_preflight() -> Response<RespBody> {
    use hyper::header::HeaderValue;
    let mut resp = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Full::new(Bytes::new()).boxed())
        .expect("static response parts");
    let h = resp.headers_mut();
    add_cors(h);
    h.insert(
        "access-control-allow-methods",
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    h.insert(
        "access-control-allow-headers",
        HeaderValue::from_static("content-type, x-hoverfly-challenge"),
    );
    h.insert("access-control-max-age", HeaderValue::from_static("86400"));
    resp
}

fn status_response(state: &State) -> Response<RespBody> {
    let body = serde_json::json!({
        "version": crate::VERSION,
        "profile": "persistent",
        "probe": state.opts.probe_enabled,
        "push": state.push.is_some(),
        "peers_known": state.peers_known.load(Ordering::Relaxed),
        "uptime_secs": state.started.elapsed().as_secs(),
        "batch_max": if state.push.is_some() { serde_json::json!(PUSH_BATCH_MAX) } else { serde_json::Value::Null },
        // The node's Kademlia overlay, so a multi-lane client can route
        // each chunk to the nearest relay (proximity rendezvous, §7).
        "overlay": state.push.as_ref().map(|p| format!("0x{}", hex::encode(p.overlay))),
        // Egress budget headroom. `null` = unmetered (no cap configured);
        // the client treats that as "no budget penalty" rather than "no
        // budget left". Feeds the lane weight in the client scheduler (§7).
        "budget_remaining_gb": state.push.as_ref().and_then(|p| {
            let gb = p.budget_gb?;
            let used = p.bytes_pushed.load(Ordering::Relaxed) as f64 / 1e9;
            Some(((gb - used).max(0.0) * 1000.0).round() / 1000.0)
        }),
        // Warm-pool occupancy. A lane whose pool is starved (shared cloud
        // /32 vs dedicated IP) can sustain far less throughput, and the
        // client shouldn't have to discover that only by timing out.
        "pool": state.push.as_ref().map(|p| serde_json::json!({
            "live": p.pool_live.load(Ordering::Relaxed),
            "target": p.pool_target,
        })),
        // Suggested concurrent POSTs per lane. Derived from pool
        // occupancy: a starved pool can't absorb more parallel batches.
        "inflight_max": state.push.as_ref().map(|p| {
            let live = p.pool_live.load(Ordering::Relaxed);
            (live / 16).clamp(1, 8)
        }),
        // Cumulative push diagnostics since boot (push RTT buckets, session
        // retirement causes, pool proximity). Queryable rather than
        // log-only, so a deployed relay can be inspected without shell
        // access to it.
        "diag": diag::summary(),
        // Stage 0 shadow metering (incentives §14): what a metered relay
        // *would* have billed. Nothing is charged and no client behaviour
        // changes. Aggregates only — per-account detail is behind
        // /v1/meter, since it names identities (see `meter_response`).
        // Metered-mode quote (§7.3), signed with the node-identity key so a
        // price is not repudiable in either direction. Absent in open mode.
        "payment": payment_quote(state),
        "meter": state.push.as_ref().map(|_| {
            state
                .meter
                .lock()
                .expect("meter poisoned")
                .summary(full_post_kib(), stream_attempts())
        }),
    });
    json_response(StatusCode::OK, &body)
}

fn probe_response(state: Arc<State>, query: Option<&str>) -> Response<RespBody> {
    if !state.opts.probe_enabled {
        return json_line_response(StatusCode::NOT_FOUND, "probe endpoint disabled (--probe)");
    }
    let params = parse_query(query);
    let size = match param_usize(&params, "size", PROBE_DEFAULT_SIZE) {
        Ok(v) if (1..=PROBE_MAX_SIZE).contains(&v) => v,
        Ok(v) => {
            return json_line_response(
                StatusCode::BAD_REQUEST,
                &format!("size {v} out of range (1..={PROBE_MAX_SIZE})"),
            );
        }
        Err(e) => return json_line_response(StatusCode::BAD_REQUEST, &e),
    };
    let concurrency = match param_usize(&params, "concurrency", PROBE_DEFAULT_CONCURRENCY) {
        Ok(v) if (1..=1024).contains(&v) => v,
        Ok(v) => {
            return json_line_response(
                StatusCode::BAD_REQUEST,
                &format!("concurrency {v} out of range (1..=1024)"),
            );
        }
        Err(e) => return json_line_response(StatusCode::BAD_REQUEST, &e),
    };
    let max_retries = match param_usize(&params, "max_retries", PROBE_DEFAULT_MAX_RETRIES) {
        Ok(v) if (1..=100).contains(&v) => v,
        Ok(v) => {
            return json_line_response(
                StatusCode::BAD_REQUEST,
                &format!("max_retries {v} out of range (1..=100)"),
            );
        }
        Err(e) => return json_line_response(StatusCode::BAD_REQUEST, &e),
    };

    let Ok(guard) = state.probe_lock.clone().try_lock_owned() else {
        return json_line_response(StatusCode::CONFLICT, "a probe is already running");
    };

    let (tx, rx) = futures::channel::mpsc::unbounded::<Result<Frame<Bytes>, Infallible>>();
    tokio::spawn(async move {
        let _guard = guard;
        run_probe(state, size, concurrency, max_retries, tx).await;
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/x-ndjson")
        .header("cache-control", "no-store")
        // Tell buffering reverse proxies (nginx-style) to pass NDJSON
        // lines through as they are flushed.
        .header("x-accel-buffering", "no")
        .body(BoxBody::new(StreamBody::new(rx)))
        .expect("static response parts")
}

/// `POST /v1/tcpcheck?targets=host:port,…&n=20&timeout_ms=3000` — raw
/// TCP connect tester, the discriminator between "our egress path is
/// broken" and "peers throttle this source IP". No libp2p, no
/// handshake: just `TcpStream::connect` × `n` per target with error-kind
/// classification (refused = RST reached us, so packets flow; timeout =
/// dropped somewhere; unreachable = routing/NAT). Targets run in
/// parallel, attempts per target sequentially with a small gap so one
/// target never sees a SYN flood. One NDJSON line per target as it
/// finishes. Gated behind `--probe` like the push probe.
fn tcpcheck_response(state: Arc<State>, query: Option<&str>) -> Response<RespBody> {
    if !state.opts.probe_enabled {
        return json_line_response(StatusCode::NOT_FOUND, "probe endpoint disabled (--probe)");
    }
    let params = parse_query(query);
    let targets: Vec<String> = params
        .get("targets")
        .map(|t| {
            t.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    if targets.is_empty() || targets.len() > 16 {
        return json_line_response(StatusCode::BAD_REQUEST, "need 1..=16 targets=host:port,…");
    }
    let n = match param_usize(&params, "n", 20) {
        Ok(v) if (1..=100).contains(&v) => v,
        Ok(v) => {
            return json_line_response(
                StatusCode::BAD_REQUEST,
                &format!("n {v} out of range (1..=100)"),
            );
        }
        Err(e) => return json_line_response(StatusCode::BAD_REQUEST, &e),
    };
    let timeout_ms = match param_usize(&params, "timeout_ms", 3000) {
        Ok(v) if (100..=10_000).contains(&v) => v as u64,
        Ok(v) => {
            return json_line_response(
                StatusCode::BAD_REQUEST,
                &format!("timeout_ms {v} out of range (100..=10000)"),
            );
        }
        Err(e) => return json_line_response(StatusCode::BAD_REQUEST, &e),
    };

    let (tx, rx) = futures::channel::mpsc::unbounded::<Result<Frame<Bytes>, Infallible>>();
    tokio::spawn(async move {
        let mut handles = Vec::with_capacity(targets.len());
        for target in targets {
            let tx = tx.clone();
            handles.push(tokio::spawn(async move {
                let line = tcpcheck_target(&target, n, timeout_ms).await;
                let mut s = serde_json::json!({"tcpcheck": line}).to_string();
                s.push('\n');
                let _ = tx.unbounded_send(Ok(Frame::data(Bytes::from(s))));
            }));
        }
        for h in handles {
            let _ = h.await;
        }
        let _ = tx.unbounded_send(Ok(Frame::data(Bytes::from(
            serde_json::json!({"done": true}).to_string() + "\n",
        ))));
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/x-ndjson")
        .header("cache-control", "no-store")
        .header("x-accel-buffering", "no")
        .body(BoxBody::new(StreamBody::new(rx)))
        .expect("static response parts")
}

async fn tcpcheck_target(target: &str, n: usize, timeout_ms: u64) -> serde_json::Value {
    use std::io::ErrorKind;
    let mut ok = 0usize;
    let mut connect_ms: Vec<u64> = Vec::new();
    let mut errors: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut sample_error: Option<String> = None;
    for i in 0..n {
        if i > 0 {
            // Pace attempts so a single target never sees a SYN burst —
            // we are measuring policy, not provoking it.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let started = Instant::now();
        match tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms),
            tokio::net::TcpStream::connect(target),
        )
        .await
        {
            Ok(Ok(_stream)) => {
                ok += 1;
                connect_ms.push(started.elapsed().as_millis() as u64);
            }
            Ok(Err(e)) => {
                let class = match e.kind() {
                    ErrorKind::ConnectionRefused => "refused",
                    ErrorKind::ConnectionReset => "reset",
                    ErrorKind::TimedOut => "timeout",
                    ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable => "unreachable",
                    _ => "other",
                };
                *errors.entry(class).or_insert(0) += 1;
                sample_error.get_or_insert_with(|| e.to_string());
            }
            Err(_) => {
                *errors.entry("timeout").or_insert(0) += 1;
            }
        }
    }
    connect_ms.sort_unstable();
    let med = connect_ms.get(connect_ms.len() / 2).copied();
    let mut v = serde_json::json!({
        "target": target,
        "n": n,
        "ok": ok,
        "connect_ms": {
            "min": connect_ms.first().copied(),
            "median": med,
            "max": connect_ms.last().copied(),
        },
        "errors": errors,
    });
    if let Some(s) = sample_error {
        v["sample_error"] = serde_json::Value::String(s);
    }
    v
}

/// Build the push-path transport + peer cache from the node identity.
/// Returns `None` if the node key can't be resolved.
fn build_push_state(opts: &PusherOpts) -> Option<PushState> {
    let nonce_hex = format!("0x{}", hex::encode(opts.nonce));
    let node_signer = match opts.node_identity.as_deref() {
        Some(k) => SwarmSigner::from_hex_with_nonce(k, &nonce_hex, opts.network_id).ok()?,
        None => {
            let mut kb = [0u8; 32];
            getrandom::fill(&mut kb).ok()?;
            SwarmSigner::from_hex_with_nonce(
                &format!("0x{}", hex::encode(kb)),
                &nonce_hex,
                opts.network_id,
            )
            .ok()?
        }
    };
    let keypair = crate::inbound::libp2p_keypair_from_identity(&node_signer);
    let overlay = *node_signer.overlay();
    let quote_signer = node_signer.clone();
    let snapshot = crate::protocols::status::StatusSnapshot::default();
    let transport = Transport::new_with_keypair(node_signer, opts.transport.clone(), keypair)
        .with_status_snapshot(snapshot);
    info!("push node overlay = 0x{}", hex::encode(overlay));
    let peers = PeerStore::load_or_create(&opts.peerlist);
    let pool_target = std::env::var("HOVERFLY_PUSH_POOL")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .map(|n| n.clamp(1, PUSH_POOL_TARGET_MAX))
        .unwrap_or(PUSH_POOL_TARGET_DEFAULT);
    info!("push warm-pool target = {pool_target} (HOVERFLY_PUSH_POOL to override)");
    let budget_gb = std::env::var("HOVERFLY_PUSH_BUDGET_GB")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|v| *v > 0.0);
    match budget_gb {
        Some(gb) => info!("push egress budget = {gb} GB (HOVERFLY_PUSH_BUDGET_GB)"),
        None => {
            info!("push egress budget = unmetered (set HOVERFLY_PUSH_BUDGET_GB to advertise one)")
        }
    }
    Some(PushState {
        transport: Arc::new(transport),
        peers: Arc::new(peers),
        pool: tokio::sync::Mutex::new(None),
        pool_target,
        pool_live: AtomicUsize::new(0),
        signer: quote_signer,
        overlay,
        budget_gb,
        bytes_pushed: AtomicU64::new(0),
        recent: std::sync::Mutex::new(RecentAcks::new(
            RECENT_ACK_CAP,
            std::time::Duration::from_secs(RECENT_ACK_TTL_SECS),
        )),
    })
}

/// `POST /v1/push` — the real relay endpoint. Body = frames
/// (`docs/pusher-design.md` §3); response = streamed NDJSON acks. Open
/// mode: a chunk is accepted iff its stamp signature recovers to the
/// on-chain owner of the stamp's batch AND the batch is alive
/// (`remainingBalance > 0`) — that pair *is* the auth (§5). No keys ever
/// cross the wire — the client stamps locally and ships only pre-signed
/// frames.
async fn push_response(
    state: Arc<State>,
    req: Request<hyper::body::Incoming>,
) -> Response<RespBody> {
    if state.push.is_none() {
        return json_line_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "push disabled (no node identity resolvable)",
        );
    }
    // Metered admission, entirely before the body is read (§7.2). Nothing
    // here touches the chain: the challenge already carries the credit line,
    // which is the point of issuing it.
    let admitted = match admit_metered(&state, &req) {
        Ok(a) => a,
        Err(resp) => return *resp,
    };
    // Bounded body read — a whole batch, not a stream. Bounded in *time* as
    // well as size: the size limit alone let a client dribble a body forever
    // and hold the connection (and, under metering, its admission
    // reservation) for free.
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(PUSH_BODY_READ_TIMEOUT_SECS),
        Limited::new(req.into_body(), PUSH_MAX_BODY).collect(),
    )
    .await;
    let bytes = match read {
        Ok(Ok(c)) => c.to_bytes(),
        Ok(Err(_)) => {
            return json_line_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "body exceeds limit or read error",
            );
        }
        Err(_) => {
            return json_line_response(StatusCode::REQUEST_TIMEOUT, "body read timed out");
        }
    };
    let chunks = match pushframe::decode_batch(&bytes, PUSH_BATCH_MAX) {
        Ok(c) => c,
        Err(e) => {
            return json_line_response(StatusCode::BAD_REQUEST, &format!("frame decode: {e}"));
        }
    };
    if chunks.is_empty() {
        return json_line_response(StatusCode::BAD_REQUEST, "empty batch");
    }

    // Pushes run CONCURRENTLY over the shared warm pool — clients pipeline
    // several batches at once, so serializing them (the old 409-on-contention
    // behavior) forced needless failover churn. The pool is Arc/RwLock-shared
    // and kept filled by the background maintenance loop; each push only reads
    // sessions from it (maintain=false), so no per-push dial burst.
    let (tx, rx) = futures::channel::mpsc::unbounded::<Result<Frame<Bytes>, Infallible>>();
    tokio::spawn(async move {
        run_push(state, chunks, tx, admitted).await;
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/x-ndjson")
        .header("cache-control", "no-store")
        .header("x-accel-buffering", "no")
        .body(BoxBody::new(StreamBody::new(rx)))
        .expect("static response parts")
}

async fn run_push(
    state: Arc<State>,
    chunks: Vec<StampedChunk>,
    tx: futures::channel::mpsc::UnboundedSender<Result<Frame<Bytes>, Infallible>>,
    admitted: Option<Admitted>,
) {
    let push = state.push.as_ref().expect("push state present");
    let mut dedup_hits = 0usize;
    let send_line = |v: &serde_json::Value| {
        let mut s = v.to_string();
        s.push('\n');
        let _ = tx.unbounded_send(Ok(Frame::data(Bytes::from(s))));
    };
    let ack = |addr: &[u8; 32], status: &str, err: Option<&str>| {
        let mut v = serde_json::json!({"a": hex::encode(addr), "s": status});
        if let Some(e) = err {
            v["e"] = serde_json::Value::String(e.to_string());
        }
        send_line(&v);
    };
    let ack_dedup = |addr: &[u8; 32]| {
        // A dedup hit did no push work and is billed at zero (§8.2). Say so
        // explicitly: without a marker it is indistinguishable from a real
        // push, so a paying client counts bytes the relay never charged
        // for, and its next cheque is refused as an overpayment. The claim
        // only ever *lowers* what is owed, so it is safe for the client to
        // take at face value.
        send_line(&serde_json::json!({
            "a": hex::encode(addr), "s": "ok", "po": 0, "ms": 0, "dedup": true
        }));
    };

    // The stamp's batch_id must match the on-chain owner the signature
    // recovers to. All chunks in one upload share a batch; verify the
    // batch once, then check each chunk's recovered signer against it.
    let mut accepted: Vec<StampedChunk> = Vec::with_capacity(chunks.len());
    let mut batch_owner: Option<([u8; 20], u128)> = None;
    let mut batch_hex: Option<String> = None;
    // Stage 0 shadow metering, accumulated on this task's stack and merged
    // once below. Per-frame locking would serialize concurrent POSTs on a
    // counter nobody is billed from.
    let mut tally = crate::meter::PostTally::default();
    // Body bytes that will actually be billed: admitted minus dedup hits,
    // which did no push work and so cost nothing (§8.2).
    let mut billable_bytes: u64 = 0;
    // addr -> owning batch, for the recent-ack cache: dedup must be
    // scoped per (addr, batch) so one uploader's frame can't be acked
    // "ok" under another uploader's stamp (§15).
    let mut batch_of: HashMap<[u8; 32], [u8; 32]> = HashMap::with_capacity(chunks.len());
    // Distinct on-chain batch resolutions this request may perform.
    let mut rpc_budget = PUSH_MAX_BATCH_LOOKUPS;

    for chunk in chunks {
        let vs = match crate::stamp::validate(&chunk.addr, &chunk.stamp) {
            Ok(v) => v,
            Err(e) => {
                ack(&chunk.addr, "err", Some(&format!("bad stamp: {e}")));
                continue;
            }
        };
        let bid = hex::encode(vs.batch_id);
        // Resolve the owner for this batch (cached, one RPC per batch).
        let owner = if batch_hex.as_deref() == Some(bid.as_str()) {
            batch_owner
        } else {
            match resolve_owner(&state, &bid, &mut rpc_budget).await {
                Ok(o) => {
                    batch_hex = Some(bid.clone());
                    batch_owner = Some(o);
                    Some(o)
                }
                Err(e) => {
                    ack(&chunk.addr, "err", Some(&e));
                    continue;
                }
            }
        };
        match owner {
            Some((o, batch_value)) if o == vs.signer => {
                // Duplicate suppression: a client hedging a straggler
                // sends the same frame to two lanes on purpose. Answering
                // from the recent-ack cache makes the loser of that race
                // free instead of a second real push through the pool.
                // Scoped per (addr, batch) — a bare address would let the
                // hit discard the submitted stamp (§15).
                let mut batch_id = [0u8; 32];
                batch_id.copy_from_slice(vs.batch_id);
                // One batch per request under metering (§6). Standing, the
                // credit line and the reservation are all properties of a
                // *batch*, so a POST that mixes them lets one good-standing
                // frame carry 511 others from an account that is over its
                // cap (§11.8). Rejected rather than billed to whoever it
                // names.
                if let Some(adm) = &admitted
                    && batch_id != adm.batch
                {
                    ack(
                        &chunk.addr,
                        "err",
                        Some("frame batch does not match the challenge (one batch per request)"),
                    );
                    continue;
                }
                // Body bytes this frame occupied — header plus wire — which
                // is the unit incentives §8 bills. Recorded for every
                // admitted frame, dedup hits included, because the relay
                // received those bytes either way.
                let key = crate::meter::AccountBatch {
                    owner: o,
                    batch: batch_id,
                };
                let frame_bytes = (pushframe::HEADER_LEN + chunk.wire.len()) as u64;
                tally.admit(key, batch_value, frame_bytes);
                billable_bytes += frame_bytes;
                let dup = push
                    .recent
                    .lock()
                    .expect("recent-ack cache poisoned")
                    .contains(&chunk.addr, batch_id);
                if dup {
                    dedup_hits += 1;
                    tally.dedup(key, batch_value, frame_bytes);
                    billable_bytes = billable_bytes.saturating_sub(frame_bytes);
                    ack_dedup(&chunk.addr);
                } else {
                    batch_of.insert(chunk.addr, batch_id);
                    accepted.push(chunk);
                }
            }
            Some((o, _)) => ack(
                &chunk.addr,
                "err",
                Some(&format!(
                    "stamp signer 0x{} is not the on-chain batch owner 0x{}",
                    hex::encode(vs.signer),
                    hex::encode(o)
                )),
            ),
            None => ack(&chunk.addr, "err", Some("batch owner unresolved")),
        }
    }

    // Turn the reservation into debt for what was actually admitted, and
    // release the rest (§10.2). Runs before the early return below, so a
    // POST that admitted nothing still gives its reservation back — leaking
    // it would ratchet the account toward a 402 it can never clear.
    if let Some(adm) = admitted {
        adm.commit(billable_bytes);
    }

    // One lock for the whole request. Runs before the early return below so
    // an all-dedup POST is still measured — those are exactly the requests
    // §8.2 bills at zero, and their share is a number Stage 0 wants.
    if !tally.is_empty() {
        state
            .meter
            .lock()
            .expect("meter poisoned")
            .merge(std::mem::take(&mut tally));
    }

    if accepted.is_empty() {
        send_line(&serde_json::json!({
            "done": {"pushed": 0, "rejected": dedup_hits == 0, "dedup": dedup_hits}
        }));
        return;
    }

    // Grab the warm pool (kept filled by the maintenance loop) and push.
    let pool = match get_pool(push).await {
        Ok(p) => p,
        Err(e) => {
            for c in &accepted {
                ack(&c.addr, "err", Some(&format!("pool: {e}")));
            }
            return;
        }
    };

    let addrs: Vec<[u8; 32]> = accepted.iter().map(|c| c.addr).collect();
    let total = accepted.len();
    let bytes: u64 = accepted.iter().map(|c| c.wire.len() as u64).sum();

    // Per-chunk acks, streamed as each chunk resolves. Chunks are
    // independent for pushsync, so one failure inside a 256-frame batch
    // says nothing about the other 255 — reporting a single verdict for
    // the whole batch (the old behaviour) forced the client to re-push
    // everything over one loss, and made the dApp's "streaming" progress
    // bar jump in 256-chunk steps.
    //
    // The channel send is what carries the ack out, so the callback has to
    // own a clone of the sender rather than borrow `send_line`.
    let acked: Arc<std::sync::Mutex<HashMap<[u8; 32], bool>>> =
        Arc::new(std::sync::Mutex::new(HashMap::with_capacity(total)));
    let on_chunk: crate::client::ChunkDoneFn = {
        let tx = tx.clone();
        let acked = acked.clone();
        Arc::new(move |addr: &[u8; 32], res| {
            let v = match &res {
                Ok(info) => {
                    // `po` is the proximity order of the peer whose receipt
                    // we took — how deep into the chunk's own neighborhood
                    // it actually landed. This is the measurement that
                    // decides whether client-side proximity routing to a
                    // relay's overlay is worth anything at all
                    // (docs/pusher-design.md §7); without it that question
                    // can only be guessed at.
                    let mut v = serde_json::json!({
                        "a": hex::encode(addr), "s": "ok", "po": info.po, "ms": info.ms,
                        // Best proximity the dispatcher could reach for this
                        // chunk; `po` vs `bpo` attributes far landings to the
                        // pool's coverage or to the eligibility filters.
                        "bpo": info.best_po,
                    });
                    if info.shallow {
                        v["shallow"] = serde_json::Value::Bool(true);
                    }
                    v
                }
                Err(e) => serde_json::json!({"a": hex::encode(addr), "s": "err", "e": e}),
            };
            acked
                .lock()
                .expect("ack map poisoned")
                .insert(*addr, res.is_ok());
            let mut s = v.to_string();
            s.push('\n');
            let _ = tx.unbounded_send(Ok(Frame::data(Bytes::from(s))));
        })
    };

    let result = push_chunks_with_pool_ex(
        &push.transport,
        &pool,
        &push.peers,
        accepted,
        PUSH_MAX_RETRIES,
        false, // the background maintenance loop owns pool upkeep — no per-push
        // top-up (concurrent pushes would otherwise each dial-burst and trip
        // bee's per-/32 rate limiter).
        None,
        Some(&on_chunk),
    )
    .await;

    // A fatal error aborts the dispatcher with chunks still queued; those
    // never reached the callback, so name them here. Without this the
    // client would wait out its own deadline for acks that can't come.
    let seen = acked.lock().expect("ack map poisoned").clone();
    let mut pushed = 0usize;
    let mut pushed_bytes = 0u64;
    for (a, ok) in &seen {
        if *ok {
            pushed += 1;
            // A successful chunk belongs to exactly the batch it was
            // admitted under; cache it under (addr, batch) so dedup stays
            // scoped. `batch_of` is only missing a key if the chunk was
            // admitted on a path that never mapped it — none currently.
            let bid = batch_of.get(a).copied().unwrap_or([0u8; 32]);
            push.recent
                .lock()
                .expect("recent-ack cache poisoned")
                .insert(*a, bid);
        }
    }
    if total > 0 {
        pushed_bytes = bytes * pushed as u64 / total as u64;
    }
    push.bytes_pushed.fetch_add(pushed_bytes, Ordering::Relaxed);
    let err_msg = result.err().map(|e| e.to_string());
    let unresolved = addrs.iter().filter(|a| !seen.contains_key(*a)).count();
    if unresolved > 0 {
        let msg = err_msg
            .clone()
            .unwrap_or_else(|| "dispatcher exited before this chunk resolved".into());
        for a in &addrs {
            if !seen.contains_key(a) {
                ack(a, "err", Some(&msg));
            }
        }
    }
    let mut done = serde_json::json!({"pushed": pushed, "total": total});
    if dedup_hits > 0 {
        done["dedup"] = serde_json::json!(dedup_hits);
        info!(target: "hoverfly::pusher",
            "batch: {pushed}/{total} pushed, {dedup_hits} served from the recent-ack cache");
    }
    if let Some(e) = err_msg {
        done["error"] = serde_json::Value::String(e);
    }
    send_line(&serde_json::json!({ "done": done }));
}

/// On-chain batch owner for `batch_id_hex`, cached. Errors (string) on
/// RPC failure, unknown batch, or an **expired** batch: open-mode auth
/// is "the batch is alive" (docs/pusher-design.md §5), so a batch whose
/// `remainingBalance` has drained to zero is rejected — bee nodes would
/// refuse its stamps anyway, and pushing them just burns relay egress.
/// The aliveness read happens once per batch and is cached for
/// `OWNER_OK_TTL_SECS`; a batch that dies *while cached* only wastes its
/// own push attempts — bees reject the stamps downstream.
/// `rpc_budget` bounds how many *distinct* batch ids one request may push
/// through to the chain. A cache hit never spends it; only a genuine miss
/// does. Without it, negative caching alone still leaves a single POST
/// naming `PUSH_BATCH_MAX` different bogus batch ids able to issue that
/// many serial `eth_call`s, since every one of them is a first miss.
async fn resolve_owner(
    state: &State,
    batch_id_hex: &str,
    rpc_budget: &mut usize,
) -> Result<([u8; 20], u128), String> {
    if let Some(hit) = state
        .owner_cache
        .lock()
        .expect("owner cache poisoned")
        .get(batch_id_hex)
    {
        return match hit {
            OwnerLookup::Owner(o, value) => Ok((o, value)),
            OwnerLookup::Rejected(why) => Err(why),
        };
    }
    if *rpc_budget == 0 {
        return Err(format!(
            "batch {batch_id_hex}: too many distinct batches in one request \
             (limit {PUSH_MAX_BATCH_LOOKUPS}); split them across requests"
        ));
    }
    *rpc_budget -= 1;

    // Only *definitive* on-chain answers are cached. A transport error must
    // not blacklist a live batch for OWNER_BAD_TTL_SECS, so those propagate
    // uncached.
    let stamp_addr: alloy_primitives::Address = crate::batch::MAINNET_POSTAGE_STAMP
        .parse()
        .expect("hardcoded valid");
    let info = crate::batch::read_batch(&state.opts.rpc_url, stamp_addr, batch_id_hex)
        .await
        .map_err(|e| format!("batch owner RPC: {e}"))?;
    let reject = |state: &State, why: String| -> String {
        state
            .owner_cache
            .lock()
            .expect("owner cache poisoned")
            .insert(batch_id_hex, OwnerLookup::Rejected(why.clone()));
        why
    };
    if info.not_found {
        return Err(reject(
            state,
            format!("batch {batch_id_hex} not found on-chain"),
        ));
    }
    let remaining =
        crate::batch::read_remaining_balance(&state.opts.rpc_url, stamp_addr, batch_id_hex)
            .await
            .map_err(|e| format!("batch balance RPC: {e}"))?;
    if remaining.is_zero() {
        return Err(reject(
            state,
            format!(
                "batch {batch_id_hex} has expired (zero remaining balance) — bees would reject every stamp"
            ),
        ));
    }
    // Total value still funded on this batch: `remainingBalance` is PLUR per
    // chunk, and a batch of depth `d` covers 2^d chunks (incentives §6).
    // Saturating rather than wrapping — a nonsense depth from a malformed
    // read must not produce a small number that looks like a real answer.
    let depth_factor = 1u128
        .checked_shl(u32::from(info.depth))
        .unwrap_or(u128::MAX);
    let remaining_value_plur = u128::try_from(remaining)
        .unwrap_or(u128::MAX)
        .saturating_mul(depth_factor);
    let owner = info.owner.into_array();
    state
        .owner_cache
        .lock()
        .expect("owner cache poisoned")
        .insert(
            batch_id_hex,
            OwnerLookup::Owner(owner, remaining_value_plur),
        );
    Ok((owner, remaining_value_plur))
}

/// Return the warm pool, filling/topping it up to `push.pool_target`.
async fn ensure_pool(push: &PushState) -> Result<Arc<SessionPool>, String> {
    // Get-or-install the pool handle under a brief lock, then top up WITHOUT
    // holding it — dialing takes seconds and must not block concurrent pushes
    // reading the pool.
    let pool = {
        let mut guard = push.pool.lock().await;
        match guard.as_ref() {
            Some(p) => p.clone(),
            None => {
                let p = Arc::new(SessionPool::new());
                *guard = Some(p.clone());
                p
            }
        }
    };
    pool.top_up(&push.transport, &push.peers, push.pool_target)
        .await;
    push.pool_live.store(pool.len(), Ordering::Relaxed);
    if pool.len() == 0 {
        return Err("could not open any sessions from the peer cache".into());
    }
    Ok(pool)
}

/// The warm pool for a push: the background loop keeps it filled, so this is
/// normally a lock-free read. Only on a cold first request (before the
/// maintenance loop has filled it) does it fall back to building/dialing.
async fn get_pool(push: &PushState) -> Result<Arc<SessionPool>, String> {
    {
        let guard = push.pool.lock().await;
        if let Some(p) = guard.as_ref() {
            if p.len() > 0 {
                return Ok(p.clone());
            }
        }
    }
    ensure_pool(push).await
}

/// Background loop: fill the warm pool on startup and keep it topped up to
/// target on a gentle cadence, so /v1/push never dials inline.
async fn push_maintenance(state: Arc<State>) {
    let Some(push) = state.push.as_ref() else {
        return;
    };
    loop {
        match ensure_pool(push).await {
            Ok(p) => info!(target: "hoverfly::pusher", "warm pool: {} session(s)", p.len()),
            Err(e) => warn!(target: "hoverfly::pusher", "warm pool maintenance: {e}"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}

/// The probe itself. Every early exit sends a terminal `report` line
/// with `ok:false` — an errored probe still carries measurement data,
/// which is the whole point of the gate experiment.
async fn run_probe(
    state: Arc<State>,
    size: usize,
    concurrency: usize,
    max_retries: usize,
    tx: futures::channel::mpsc::UnboundedSender<Result<Frame<Bytes>, Infallible>>,
) {
    let send_line = |v: &serde_json::Value| {
        let mut s = v.to_string();
        s.push('\n');
        // A closed channel means the client hung up; the push keeps
        // running to completion so the probe still lands in the log.
        let _ = tx.unbounded_send(Ok(Frame::data(Bytes::from(s))));
    };

    let key = match std::env::var("HOVERFLY_PROBE_KEY") {
        Ok(k) if !k.trim().is_empty() => k,
        _ => {
            send_line(&serde_json::json!({
                "report": {"ok": false, "error": "HOVERFLY_PROBE_KEY not set in the pusher's environment"}
            }));
            return;
        }
    };
    let batch = match std::env::var("HOVERFLY_PROBE_BATCH") {
        Ok(b) if !b.trim().is_empty() => b,
        _ => {
            send_line(&serde_json::json!({
                "report": {"ok": false, "error": "HOVERFLY_PROBE_BATCH not set in the pusher's environment"}
            }));
            return;
        }
    };

    let signer = match SwarmSigner::from_hex_with_nonce(
        &key,
        &format!("0x{}", hex::encode(state.opts.nonce)),
        state.opts.network_id,
    ) {
        Ok(s) => s,
        Err(e) => {
            send_line(&serde_json::json!({
                "report": {"ok": false, "error": format!("HOVERFLY_PROBE_KEY: {e}")}
            }));
            return;
        }
    };

    // Depth + mutability: env override, else the cached on-chain read
    // (which also owner-checks the env key — the classic misconfig that
    // otherwise burns the whole probe on "could not push chunk").
    let (depth, immutable) = match resolve_batch(&state, &signer, &batch).await {
        Ok(v) => v,
        Err(e) => {
            send_line(&serde_json::json!({"report": {"ok": false, "error": e}}));
            return;
        }
    };

    let mut peers = PeerStore::load_or_create(&state.opts.peerlist);
    if peers.is_empty() {
        send_line(&serde_json::json!({
            "report": {"ok": false, "error": format!("peerlist {} is empty", state.opts.peerlist.display())}
        }));
        return;
    }

    let seq = state.probe_seq.fetch_add(1, Ordering::Relaxed);
    let data = random_data(size, seq);
    send_line(&serde_json::json!({
        "probe": {
            "seq": seq, "size": size, "concurrency": concurrency,
            "max_retries": max_retries, "depth": depth, "immutable": immutable,
            "peers_known": peers.len(),
        }
    }));

    // Node identity is separate from the stamp signer. The stamp key
    // (`signer`) only signs postage; the *network* identity — overlay +
    // libp2p peer-id — comes from HOVERFLY_PUSHER_IDENTITY when set, so
    // multiple pushers sharing one batch owner key still present as
    // distinct bee citizens (required to run them concurrently without a
    // peer-id collision). Falls back to the stamp key when unset. This is
    // the coordinator-stamps / workers-push split from
    // `prepare_upload_bytes`'s docs.
    let node_signer = match state.opts.node_identity.as_deref() {
        Some(nk) => match SwarmSigner::from_hex_with_nonce(
            nk,
            &format!("0x{}", hex::encode(state.opts.nonce)),
            state.opts.network_id,
        ) {
            Ok(s) => s,
            Err(e) => {
                send_line(&serde_json::json!({
                    "report": {"ok": false, "error": format!("HOVERFLY_PUSHER_IDENTITY: {e}")}
                }));
                return;
            }
        },
        None => signer.clone(),
    };

    let snapshot = crate::protocols::status::StatusSnapshot::default();
    // Stable, premined libp2p identity derived deterministically from the
    // node key — not a fresh random keypair per boot. A stable peer-id lets
    // bees recognize reconnections as one peer instead of a flood of
    // strangers; the overlay (node eth address + nonce) governs bin
    // placement / oversaturation.
    let keypair = crate::inbound::libp2p_keypair_from_identity(&node_signer);
    let transport = Transport::new_with_keypair(node_signer, state.opts.transport.clone(), keypair)
        .with_status_snapshot(snapshot);

    let before = diag_snapshot();
    let started = Instant::now();

    // Throttled progress stream: at most ~1 line/s keeps the response
    // flowing (and proxies un-idle) without drowning small probes.
    let progress_tx = tx.clone();
    let progress_started = started;
    let last_sent = std::sync::Mutex::new(Instant::now() - std::time::Duration::from_secs(2));
    let progress: ProgressFn = Arc::new(move |done, total| {
        let mut last = last_sent.lock().expect("progress throttle poisoned");
        if last.elapsed() < std::time::Duration::from_secs(1) && done != total {
            return;
        }
        *last = Instant::now();
        let mut s = serde_json::json!({
            "progress": {
                "done": done, "total": total,
                "elapsed_ms": progress_started.elapsed().as_millis() as u64,
            }
        })
        .to_string();
        s.push('\n');
        let _ = progress_tx.unbounded_send(Ok(Frame::data(Bytes::from(s))));
    });

    let result = upload_bytes_ex(
        &transport,
        &peers,
        &signer,
        &batch,
        depth,
        immutable,
        &data,
        // The probe measures push throughput for a known chunk count, so it
        // deliberately uploads *without* redundancy: parity chunks would add
        // an implicit ~8% to the workload the caller asked to measure.
        crate::erasure::Level::None,
        max_retries,
        concurrency,
        Some(&progress),
    )
    .await;

    let elapsed = started.elapsed();
    let after = diag_snapshot();
    let diag_delta: BTreeMap<&'static str, u64> = after
        .iter()
        .filter_map(|(k, v)| {
            let d = v - before.get(k).copied().unwrap_or(0);
            (d > 0).then_some((*k, d))
        })
        .collect();

    // Dial reachability: overall split plus per-host failure clustering —
    // the per-/32 signature is the primary read-out of the cloud-egress
    // gate experiment (a farm refusing cloud IPs shows up as its hosts
    // dominating this map while the VPS baseline dials them fine).
    let log = transport.reachability_log();
    let (dial_ok, dial_fail, failed_hosts) = {
        let by_overlay: HashMap<String, &crate::peers::Peer> = peers
            .iter()
            .map(|p| (p.overlay.to_lowercase(), p))
            .collect();
        let entries = log.lock().expect("reachability log poisoned");
        let mut ok = 0u64;
        let mut fail = 0u64;
        let mut hosts: BTreeMap<String, u64> = BTreeMap::new();
        for (overlay, res) in entries.iter() {
            match res {
                DialResult::Success { .. } => ok += 1,
                DialResult::Failure => {
                    fail += 1;
                    let host = by_overlay
                        .get(overlay.as_str())
                        .and_then(|p| p.underlays.first())
                        .and_then(|u| multiaddr_host(u))
                        .unwrap_or_else(|| "unknown".into());
                    *hosts.entry(host).or_insert(0) += 1;
                }
            }
        }
        (ok, fail, hosts)
    };

    // Feed the observations back into the peerlist (same citizenship as
    // the one-shot CLI) so consecutive probes start from a warmer cache.
    apply_log(&mut peers, &log);
    if let Err(e) = peers.save(&state.opts.peerlist) {
        warn!("could not save peerlist: {e}");
    }
    state.peers_known.store(peers.len(), Ordering::Relaxed);

    let mib_s = (size as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64().max(1e-9);
    let mut report = serde_json::json!({
        "ok": result.is_ok(),
        "seq": seq,
        "size": size,
        "elapsed_ms": elapsed.as_millis() as u64,
        "mib_per_sec": (mib_s * 1000.0).round() / 1000.0,
        "dials": {"ok": dial_ok, "failed": dial_fail, "failed_hosts": failed_hosts},
        "diag": diag_delta,
    });
    match result {
        Ok(root) => {
            report["root"] = serde_json::Value::String(hex::encode(root.as_bytes()));
        }
        Err(e) => {
            report["error"] = serde_json::Value::String(e.to_string());
        }
    }
    send_line(&serde_json::json!({"report": report}));
}

/// Depth/immutability for the probe batch: `HOVERFLY_PROBE_DEPTH` (with
/// optional `HOVERFLY_PROBE_IMMUTABLE=1`) skips the chain entirely,
/// otherwise one cached on-chain read that also owner-checks the key.
async fn resolve_batch(
    state: &State,
    signer: &SwarmSigner,
    batch: &str,
) -> Result<(u8, bool), String> {
    if let Ok(d) = std::env::var("HOVERFLY_PROBE_DEPTH") {
        let depth: u8 = d
            .trim()
            .parse()
            .map_err(|e| format!("HOVERFLY_PROBE_DEPTH: {e}"))?;
        let immutable = std::env::var("HOVERFLY_PROBE_IMMUTABLE").is_ok_and(|v| v == "1");
        return Ok((depth, immutable));
    }
    if let Some(hit) = state
        .batch_cache
        .lock()
        .expect("batch cache poisoned")
        .get(batch)
    {
        return Ok(*hit);
    }
    let stamp_addr: alloy_primitives::Address = crate::batch::MAINNET_POSTAGE_STAMP
        .parse()
        .expect("hardcoded valid");
    let info = crate::batch::read_batch(&state.opts.rpc_url, stamp_addr, batch)
        .await
        .map_err(|e| {
            format!("could not read batch on-chain (set HOVERFLY_PROBE_DEPTH to skip): {e}")
        })?;
    if info.not_found {
        return Err(format!("batch {batch} not found on-chain"));
    }
    let signer_addr = alloy_primitives::Address::from(*signer.eth_address());
    if signer_addr != info.owner {
        return Err(format!(
            "batch owner mismatch: on-chain owner {} vs HOVERFLY_PROBE_KEY address {} — \
             bee would reject every stamp",
            info.owner, signer_addr
        ));
    }
    state
        .batch_cache
        .lock()
        .expect("batch cache poisoned")
        .insert(batch.to_string(), (info.depth, info.immutable));
    Ok((info.depth, info.immutable))
}

/// Deterministic-per-seed pseudo-random payload (xorshift64). Seeded
/// with wall-clock + probe sequence so consecutive probes never re-push
/// identical chunk addresses (which bees would dedupe, and which would
/// double-spend stamp bucket slots on immutable batches).
fn random_data(size: usize, seq: u64) -> Vec<u8> {
    let mut x: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x243F_6A88_85A3_08D3)
        ^ (seq.wrapping_add(1).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let mut data = vec![0u8; size];
    for chunk in data.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        for (i, b) in chunk.iter_mut().enumerate() {
            *b = (x >> (8 * i)) as u8;
        }
    }
    data
}

/// Snapshot every `transport::diag` counter relevant to a push run.
fn diag_snapshot() -> BTreeMap<&'static str, u64> {
    let m: &[(&'static str, &AtomicU64)] = &[
        ("push_ok", &diag::PUSH_OUTCOME_OK),
        ("push_shallow", &diag::PUSH_OUTCOME_SHALLOW),
        ("push_overdraft", &diag::PUSH_OUTCOME_OVERDRAFT),
        ("push_error", &diag::PUSH_OUTCOME_ERROR),
        ("push_lat_lt_100ms", &diag::PUSH_LATENCY_LT_100MS),
        ("push_lat_100_500ms", &diag::PUSH_LATENCY_100_500MS),
        ("push_lat_500ms_2s", &diag::PUSH_LATENCY_500MS_2S),
        ("push_lat_2_5s", &diag::PUSH_LATENCY_2_5S),
        ("push_lat_5_10s", &diag::PUSH_LATENCY_5_10S),
        ("push_lat_gt_10s", &diag::PUSH_LATENCY_GT_10S),
        ("chunk_lat_lt_500ms", &diag::CHUNK_LATENCY_LT_500MS),
        ("chunk_lat_500ms_2s", &diag::CHUNK_LATENCY_500MS_2S),
        ("chunk_lat_2_5s", &diag::CHUNK_LATENCY_2_5S),
        ("chunk_lat_5_15s", &diag::CHUNK_LATENCY_5_15S),
        ("chunk_lat_gt_15s", &diag::CHUNK_LATENCY_GT_15S),
        ("open_stream_lt_10ms", &diag::OPEN_STREAM_LT_10MS),
        ("open_stream_10_100ms", &diag::OPEN_STREAM_10_100MS),
        ("open_stream_100_500ms", &diag::OPEN_STREAM_100_500MS),
        ("open_stream_gt_500ms", &diag::OPEN_STREAM_GT_500MS),
        ("conn_closed_io", &diag::CONN_CLOSED_IO),
        ("conn_closed_keepalive", &diag::CONN_CLOSED_KEEPALIVE),
        ("conn_closed_clean", &diag::CONN_CLOSED_CLEAN),
        ("retire_dead_low_ghost", &diag::DEAD_RETIRE_LOW_GHOST),
        (
            "retire_dead_prewarm_ghost",
            &diag::DEAD_RETIRE_PREWARM_GHOST,
        ),
        ("retire_dead_high_ghost", &diag::DEAD_RETIRE_HIGH_GHOST),
        ("retire_ghost", &diag::GHOST_RETIRE),
        ("retire_max_pushes", &diag::MAX_PUSHES_RETIRE),
        ("prewarm_on_dead", &diag::PREWARM_ON_DEAD),
        ("prewarm_on_ghost", &diag::PREWARM_ON_GHOST),
        ("hive_announce_ok", &diag::HIVE_ANNOUNCE_OK),
        ("hive_announce_fail", &diag::HIVE_ANNOUNCE_FAIL),
    ];
    m.iter()
        .map(|(k, v)| (*k, v.load(Ordering::Relaxed)))
        .collect()
}

/// Host component of a text multiaddr (`/ip4/1.2.3.4/tcp/…`,
/// `/dns4/host/…`). Good enough for failure clustering; not a parser.
fn multiaddr_host(underlay: &str) -> Option<String> {
    let mut parts = underlay.split('/').filter(|s| !s.is_empty());
    while let Some(proto) = parts.next() {
        match proto {
            "ip4" | "ip6" | "dns" | "dns4" | "dns6" => return parts.next().map(str::to_string),
            _ => {
                // Every multiaddr protocol we expect here carries one
                // value component; skip it.
                parts.next();
            }
        }
    }
    None
}

fn parse_query(query: Option<&str>) -> HashMap<String, String> {
    query
        .unwrap_or("")
        .split('&')
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            Some((k.to_string(), v.to_string()))
        })
        .collect()
}

fn param_usize(
    params: &HashMap<String, String>,
    key: &str,
    default: usize,
) -> Result<usize, String> {
    match params.get(key) {
        None => Ok(default),
        Some(v) => v.parse().map_err(|e| format!("{key}: {e}")),
    }
}

fn json_response(status: StatusCode, body: &serde_json::Value) -> Response<RespBody> {
    let mut s = body.to_string();
    s.push('\n');
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(s)).boxed())
        .expect("static response parts")
}

fn json_line_response(status: StatusCode, message: &str) -> Response<RespBody> {
    json_response(status, &serde_json::json!({"error": message}))
}

/// The signed `payment` block for `/v1/status` (incentives §7.3).
///
/// An unsigned price is repudiable in both directions: the relay can serve
/// `P` and bill `10P`, the client can claim it saw `P/10`, and
/// reconciliation can detect the mismatch but never attribute it.
///
/// It carries `node_eth_address` and `overlay_nonce` because
/// "pin `(url, overlay)`" is not implementable — an overlay is
/// `keccak(eth_addr ‖ network_id_LE8 ‖ nonce)`, so verifying a signature
/// yields the *eth address* while the nonce is neither transmitted nor
/// derivable. With both present a client can recompute the overlay and
/// check it against what the relay advertises, and pin the triple
/// `(url, node_eth_address, beneficiary)`.
fn payment_quote(state: &State) -> Option<serde_json::Value> {
    let m = state.metered.as_ref()?;
    let push = state.push.as_ref()?;
    let p = &m.cfg.params;
    // `origin` advertises the first configured hostname: issuance binds
    // only that one (`origins.first()`), while verification accepts any
    // configured origin. Extra `--origin` values are accept-list entries
    // for multi-host relays, not separately advertised lines.
    // `quote_valid_secs` is how long the client may treat this quote as
    // current without re-reading `/v1/status` (§7.2/§11.9): 24 h, which
    // exceeds one settlement period (§10.1 sizes ~32 MiB per window).
    let mut body = serde_json::json!({
        "mode": "metered",
        "enforcement": if m.cfg.hard_mode { "hard" } else { "soft" },
        "beneficiary": format!("0x{}", hex::encode(m.cfg.beneficiary)),
        "node_eth_address": format!("0x{}", hex::encode(push.signer.eth_address())),
        "overlay_nonce": format!("0x{}", hex::encode(state.opts.nonce)),
        "origin": m.cfg.origins.first().cloned().unwrap_or_default(),
        "chain_id": m.cfg.chain_id,
        "factory": format!("0x{}", hex::encode(m.cfg.factory)),
        "price_plur_per_kib": p.price_plur_per_kib.to_string(),
        "min_cheque_plur": p.min_cheque_plur.to_string(),
        "settle_every_plur": p.settle_every_plur.to_string(),
        "max_outstanding_plur": p.max_outstanding_plur.to_string(),
        "credit_ratio": p.credit_ratio,
        "challenge_ttl_secs": crate::challenge::CHALLENGE_TTL_SECS,
        "quote_valid_secs": 86_400,
    });
    // Sign the canonical serialization of the block itself, so what the
    // client verifies is exactly what it read.
    let payload = body.to_string();
    match push.signer.sign_eip191(payload.as_bytes()) {
        Ok(sig) => {
            body["sig"] = serde_json::Value::String(format!("0x{}", hex::encode(sig)));
            Some(body)
        }
        Err(e) => {
            tracing::error!("cannot sign payment quote: {e}");
            None
        }
    }
}

#[cfg(test)]
mod owner_cache_tests {
    use super::*;

    fn owner_of(c: &OwnerCache, k: &str) -> Option<[u8; 20]> {
        match c.get(k) {
            Some(OwnerLookup::Owner(o, _)) => Some(o),
            _ => None,
        }
    }

    fn value_of(c: &OwnerCache, k: &str) -> Option<u128> {
        match c.get(k) {
            Some(OwnerLookup::Owner(_, v)) => Some(v),
            _ => None,
        }
    }

    #[test]
    fn rejections_are_cached_so_a_bogus_batch_is_not_re_resolved() {
        let mut c = OwnerCache::new(16);
        assert!(c.get("deadbeef").is_none(), "cold cache must miss");
        c.insert("deadbeef", OwnerLookup::Rejected("not found".into()));
        // The point of the fix: a second frame naming the same bogus batch
        // finds a cached rejection instead of issuing another eth_call.
        assert!(
            matches!(c.get("deadbeef"), Some(OwnerLookup::Rejected(w)) if w == "not found"),
            "rejection must be cached"
        );
    }

    /// The batch's remaining value rides along on the cached success so
    /// Stage 0 can price a credit line without a second `eth_call`
    /// (`src/meter.rs`). A cache that dropped it would silently make every
    /// batch look unpriced.
    #[test]
    fn the_cached_success_carries_the_batch_value() {
        let mut c = OwnerCache::new(16);
        c.insert("b0", OwnerLookup::Owner([7u8; 20], 100_000_000_000_000));
        assert_eq!(owner_of(&c, "b0"), Some([7u8; 20]));
        assert_eq!(value_of(&c, "b0"), Some(100_000_000_000_000));
    }

    #[test]
    fn eviction_is_bounded_by_cap() {
        let mut c = OwnerCache::new(4);
        for i in 0..64 {
            c.insert(&format!("batch{i}"), OwnerLookup::Owner([i as u8; 20], 0));
        }
        assert_eq!(c.map.len(), 4, "map must stay at cap");
        assert_eq!(c.order.len(), 4, "order must stay at cap");
        assert!(owner_of(&c, "batch0").is_none(), "oldest evicted");
        assert_eq!(owner_of(&c, "batch63"), Some([63u8; 20]), "newest retained");
    }

    #[test]
    fn reinserting_a_key_does_not_grow_the_order_queue() {
        let mut c = OwnerCache::new(8);
        for _ in 0..32 {
            c.insert("same", OwnerLookup::Owner([1u8; 20], 0));
        }
        assert_eq!(c.order.len(), 1, "one order slot per distinct key");
        assert_eq!(owner_of(&c, "same"), Some([1u8; 20]));
    }

    #[test]
    fn entries_expire() {
        // Zero-length TTLs are not reachable through the constants, so drive
        // expiry by backdating the insert instant directly.
        let mut c = OwnerCache::new(8);
        c.insert("stale", OwnerLookup::Owner([2u8; 20], 0));
        let aged = Instant::now()
            .checked_sub(std::time::Duration::from_secs(OWNER_OK_TTL_SECS + 1))
            .expect("clock supports backdating");
        c.map.get_mut("stale").expect("present").1 = aged;
        assert!(c.get("stale").is_none(), "expired entry must not be served");
    }
}
