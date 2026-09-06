//! hoverfly CLI — `discover` / `fetch` / `upload` against the Swarm network
//! over libp2p WebSocket only, with DoH-only DNS resolution.

use std::path::PathBuf;
use std::time::Duration;

use std::sync::Arc;

use clap::{Parser, Subcommand};
use hoverfly::client::{
    DEFAULT_DISCOVER_CONCURRENCY, DEFAULT_FETCH_CONCURRENCY, DEFAULT_UPLOAD_CONCURRENCY,
    ProgressFn, fetch_bytes_progress, fetch_manifest_path_progress, list_manifest_ex,
    upload_bytes_ex, upload_collection, upload_file_with_manifest_ex,
};
use indicatif::{ProgressBar, ProgressStyle};

use hoverfly::{
    DEFAULT_DOH_URL, Doh, MAINNET_BOOTNODE, PeerStore, SwarmSigner, Transport, TransportConfig,
    UploadFile,
};
use libp2p::Multiaddr;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(
    name = "hoverfly",
    version,
    about = "Swarm micro-client (TCP + WebSocket on native, WebSocket on WASM)"
)]
struct Cli {
    /// Verbose output (info-level logging)
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Debug output (debug-level logging)
    #[arg(short, long, global = true)]
    debug: bool,

    /// Trace output (trace-level logging; very noisy, intended for
    /// profile/diagnostic targets like `hoverfly::profile`).
    #[arg(long, global = true)]
    trace: bool,

    /// DoH endpoint to use for DNS resolution
    #[arg(long, global = true, default_value = DEFAULT_DOH_URL, value_name = "URL")]
    doh_url: String,

    /// Network ID (1 = mainnet, 10 = testnet)
    #[arg(long, global = true, default_value_t = 1, value_name = "ID")]
    network_id: u64,

    /// Per-operation timeout in seconds (one pushsync or retrieval
    /// round-trip on an already-open session).
    #[arg(long, global = true, default_value_t = 10, value_name = "SECS")]
    timeout: u64,

    /// Wall-clock budget for opening a session to a peer (libp2p dial +
    /// identify + handshake + pricing). Set low (1-3 s) so dead/NAT'd
    /// peers fail fast; live peers usually answer in well under a
    /// second. Independent of `--timeout`.
    #[arg(long, global = true, default_value_t = 3, value_name = "SECS")]
    dial_timeout: u64,

    /// Per-connection cap on concurrent outbound substream upgrades.
    /// Higher means more substream opens negotiate in parallel
    /// (~lower open latency); lower means less yamux flow-control
    /// contention per-stream (~lower push latency). Sweet spot is
    /// workload-dependent; see `PERFORMANCE.md`. Default 64.
    #[arg(long, global = true,
          default_value_t = hoverfly::protocols::stream_pool::DEFAULT_MAX_CONCURRENT_OUTBOUND_UPGRADES,
          value_name = "N")]
    substream_upgrade_cap: usize,

    /// Multiplier applied to the dispatcher's in-flight chunk
    /// buffer. The buffer's base cap is `128 × mult`, floored at
    /// pool size. At `mult=1` the buffer matches the original 128
    /// cap; default `2` (= 256 in-flight chunks) consistently
    /// outperforms `1` in CI/VPS bench A/Bs with no measurable
    /// memory or contention downside at the sizes we run. Increase
    /// together with `--concurrency`: per-session in-flight stays
    /// ~constant while total grows. Sweet spot empirically
    /// `--concurrency 512 --buffer-multiplier 4` on a 3000+ peer
    /// pool (≈ 1 MB/s on a VPS); larger overshoots into yamux
    /// contention and regresses. See PERFORMANCE.md "Pool + buffer
    /// scaling" for the sweep.
    #[arg(long, global = true, default_value_t = 2, value_name = "N")]
    buffer_multiplier: usize,

    /// SWAP chequebook contract address (20 bytes hex, 0x-optional).
    /// When set, every session emits signed cheques after pseudosettle
    /// to cover remaining debt — see the SWAP section in
    /// `PERFORMANCE.md` for the hypothesis (Swarm infra team reports
    /// 3× upload speedup when paying).
    ///
    /// PREREQUISITES (we don't verify them — bee will reject the
    /// cheque otherwise):
    /// 1. The chequebook contract must already be deployed by bee's
    ///    official factory (mainnet:
    ///    `0xc2d5a532cf69aa9a1378737d8ccdef884b6e7420`).
    /// 2. Its `issuer()` must equal `--key`'s derived Ethereum
    ///    address (we sign cheques with `--key`).
    /// 3. It must have deposited BZZ ≥ what we'll cumulatively pay
    ///    any single peer (see `--chequebook-per-peer-cap-bzz`).
    #[arg(long, global = true, value_name = "ADDR")]
    chequebook: Option<String>,

    /// Max cumulative payout per peer (in BZZ-wei) we'll issue
    /// before falling back to pseudosettle-only with that peer.
    /// Bee's `chequestore.go:176` bounces cheques whose
    /// `cumulative - paidOut` exceeds the chequebook balance; this
    /// cap is the operator's per-peer ceiling regardless of how
    /// much is left in the chequebook. Defaults to 10^16 BZZ-wei
    /// (= 1 BZZ), which is generous for most workloads — bee will
    /// only ever ask us for a fraction of this in any single upload.
    #[arg(
        long,
        global = true,
        default_value = "10000000000000000",
        value_name = "WEI"
    )]
    chequebook_per_peer_cap_bzz: String,

    /// Path to the cheque-issuance sidecar (`cheques.json`).
    /// Persists per-peer cumulative-payout state across runs. Bee
    /// rejects any cheque whose CumulativePayout is not strictly
    /// greater than the last one it accepted from us
    /// (`ErrChequeNotIncreasing`, chequestore.go:30), so this file
    /// **must** survive between runs that target the same peer set.
    #[arg(
        long,
        global = true,
        default_value = "cheques.json",
        value_name = "FILE"
    )]
    cheques_file: PathBuf,

    /// EVM chain id used in the EIP-712 domain of cheque signatures.
    /// Defaults to 100 (Gnosis chain — Swarm mainnet). Use 11155111
    /// for Sepolia testnet. The chain id is part of the domain
    /// separator that bee's chequestore verifies against, so a
    /// mismatch silently invalidates every cheque we send.
    /// Metered lanes are also checked against this: a quote naming a
    /// different chain is refused rather than signed for.
    #[arg(long, global = true, default_value_t = 100, value_name = "ID")]
    chequebook_chain_id: u64,

    /// Pin a metered lane's identity: `URL,NODE,BENEFICIARY` (0x-hex).
    /// Repeatable. Without a pin the first-seen quote is trusted for the
    /// run (TOFU) with a warning — any host answering the URL could mint
    /// its own quote and be paid. Stable fleets should pin.
    #[arg(long, global = true, value_name = "URL,NODE,BENEFICIARY")]
    lane_pin: Vec<String>,

    /// Path to the 32-byte overlay nonce file. The Swarm overlay is
    /// derived as `keccak256(eth_addr || network_id || nonce)`, so a
    /// stable nonce gives a stable overlay across daemon restarts.
    /// This is essential for bee-citizenship: bee gossips peer
    /// overlays via the hive protocol and learned overlays only
    /// match across restarts if our overlay stays the same. With a
    /// fresh nonce each run, every restart looks like a new peer to
    /// bee and we never accumulate kademlia membership over time.
    ///
    /// Behaviour:
    /// - File exists: load the 32-byte nonce from it (hex format,
    ///   `0x` optional). If the file is malformed, fail loudly.
    /// - File missing: generate a random nonce, write it to the file
    ///   before doing any network I/O, then use it.
    ///
    /// Default: `overlay-nonce` in the current working directory.
    /// Daemon operators should treat this file like an identity
    /// secret — losing it means losing the overlay (and therefore
    /// any kademlia memberships built up over time).
    #[arg(
        long,
        global = true,
        default_value = "overlay-nonce",
        value_name = "FILE"
    )]
    nonce_file: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Discover peers from a bootstrap multiaddr or /dnsaddr/.
    Discover {
        /// Bootstrap peer (defaults to mainnet bootnode dnsaddr)
        #[arg(value_name = "PEER", default_value = MAINNET_BOOTNODE)]
        peer: String,

        /// Output peers.json path
        #[arg(short, long, default_value = "peers.json", value_name = "FILE")]
        output: PathBuf,

        /// Hard deadline (seconds) for the per-peer hive listen
        /// window. We accept multiple `peers` envelopes from each
        /// queried peer (bee splits gossip into 30-peer batches over
        /// separate streams) and short-circuit out 750 ms after the
        /// last batch lands. Bee finishes its `Announce` burst in
        /// well under 1 s on a healthy mainnet path, so this is a
        /// timeout for stragglers and bad links, not the expected
        /// per-peer cost.
        #[arg(long, default_value_t = 5)]
        wait: u64,

        /// Append to existing peers.json instead of overwriting
        #[arg(long)]
        append: bool,

        /// Number of recursive discovery hops. 1 = bootnode only. 2-3 is
        /// recommended for upload workloads — chunk pushes need a peer
        /// near each chunk's address, so a broader peerlist matters.
        #[arg(long, default_value_t = 1)]
        rounds: usize,

        /// Peers to dial in parallel per round. Each dial holds the
        /// hive stream open until bee finishes its gossip burst
        /// (typically ~1 s; capped at `--wait`), so a higher value
        /// finishes a 70-peer round in roughly `ceil(70/N) × ~1 s`
        /// instead of `70 × ~1 s`.
        #[arg(long, default_value_t = DEFAULT_DISCOVER_CONCURRENCY)]
        discover_concurrency: usize,

        /// After discovery, probe each peer's underlay to verify
        /// reachability. The results are written into peers.json's
        /// reachability cache so future operations skip known-dead
        /// peers up-front (saving ~timeout seconds per dead peer).
        #[arg(long)]
        healthcheck: bool,

        /// Concurrency for the healthcheck probe phase.
        #[arg(long, default_value_t = 64)]
        healthcheck_concurrency: usize,

        /// Export a browser-ready seed: keep only peers that advertise a
        /// `/ws` or `/wss` (WebSocket) underlay, and strip each peer's
        /// non-ws underlays. Browser builds can't open raw TCP, so this
        /// produces a peers.json the in-browser gateway daemon can use
        /// directly (e.g. `apps/gateway/public/__gw__/peers.ws.json`).
        #[arg(long)]
        ws_only: bool,
    },

    /// Fetch content addressed by a 32-byte hex root hash.
    Fetch {
        /// Swarm root hash (hex)
        #[arg(value_name = "HASH")]
        hash: String,

        /// Output file (required unless --list)
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Treat the root as a mantaray manifest and resolve this path.
        #[arg(long, value_name = "PATH")]
        path: Option<String>,

        /// List all entries in the manifest at the root and exit.
        #[arg(long, conflicts_with = "path")]
        list: bool,

        /// peers.json path
        #[arg(long, default_value = "peers.json", value_name = "FILE")]
        peerlist: PathBuf,

        /// Cap on peers tried per chunk before giving up. `0` means no
        /// cap — march through every peer in the peerlist (proximity-
        /// ordered) until one yields the chunk. Useful when the chunk
        /// neighborhood isn't densely represented in your peerlist:
        /// non-neighbor Bee nodes will forward the request through their
        /// own kademlia table.
        #[arg(long, default_value_t = 0)]
        max_retries: usize,

        /// Number of peers to race in parallel per chunk request.
        /// Slow/dead peers no longer block faster ones — whoever responds
        /// first with a valid chunk wins. Set to 1 for strict closest-first
        /// sequential behavior.
        #[arg(long, default_value_t = DEFAULT_FETCH_CONCURRENCY)]
        concurrency: usize,

        /// Connect to a running daemon instead of executing the fetch
        /// in this process. See `hoverfly daemon`.
        #[cfg(unix)]
        #[arg(long, value_name = "SOCKET")]
        daemon: Option<PathBuf>,
    },

    /// Upload a file using an existing postage batch. Wraps the file in a
    /// single-entry mantaray manifest with the file's basename as path. The
    /// returned root resolves to the file via `fetch <root> --path <name>`.
    Upload {
        /// Input file
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Postage batch ID (hex, 32 bytes)
        #[arg(long, value_name = "BATCH_ID")]
        batch: String,

        /// Batch depth (typically 17-24). When omitted, the depth is read
        /// from the batch's on-chain struct via `--rpc-url` (and the
        /// batch owner is verified against `--key`'s address). Passing an
        /// explicit `--depth` skips the on-chain read entirely.
        ///
        /// Defaulting blindly to a fixed depth silently corrupts uploads
        /// when the real batch depth differs (wrong per-bucket index
        /// math), so there is intentionally no default — supply `--depth`
        /// or a working `--rpc-url`.
        #[arg(long)]
        depth: Option<u8>,

        /// Gnosis JSON-RPC endpoint used to read the batch's on-chain
        /// depth + owner when `--depth` is omitted. Ignored when `--depth`
        /// is supplied. Defaults to a public Gnosis RPC.
        #[arg(
            long,
            value_name = "URL",
            default_value = "https://rpc.gnosischain.com"
        )]
        rpc_url: String,

        /// Skip the on-chain owner check that runs when `--depth` is
        /// omitted. The depth is still read from chain; only the
        /// owner==key assertion is bypassed (e.g. when stamping on behalf
        /// of a batch you don't own but are authorised to sign for).
        #[arg(long)]
        no_owner_check: bool,

        /// Treat the batch as immutable (fill-only stamping). When `--depth`
        /// is omitted the batch's mutability is read from chain and this flag
        /// is ignored; it only takes effect when `--depth` is supplied (which
        /// skips the on-chain read). Mutable batches use overwrite-aware ring
        /// stamping; immutable batches use fill-only stamping.
        #[arg(long)]
        immutable: bool,

        /// Private key (hex, 32 bytes — batch owner's signer)
        #[arg(long, value_name = "KEY")]
        key: String,

        /// peers.json path
        #[arg(long, default_value = "peers.json", value_name = "FILE")]
        peerlist: PathBuf,

        /// Push through a relay (`hoverfly pusher`) over HTTP instead of
        /// dialing bees directly. The signing key never leaves this
        /// process — only pre-signed chunk frames go over the wire. Stage
        /// B: single lane (repeatable, but only the first URL is used for
        /// now). Bypasses `--peerlist`/`--concurrency` (the pusher owns
        /// the session pool). See docs/pusher-design.md.
        #[arg(long, value_name = "URL")]
        pusher: Vec<String>,

        /// Number of peers to try per chunk before giving up
        #[arg(long, default_value_t = 10)]
        max_retries: usize,

        /// Upload raw chunks only, skip manifest creation.
        #[arg(long)]
        raw: bool,

        /// Override the manifest path (default: file basename).
        #[arg(long, value_name = "PATH")]
        manifest_path: Option<String>,

        /// Override the Content-Type metadata (default: auto-detected from extension).
        #[arg(long, value_name = "MIME")]
        content_type: Option<String>,

        /// Number of peer sessions to keep open in parallel during upload.
        /// Each session reuses a single libp2p connection for many chunks,
        /// so a small pool (4-16) is usually plenty.
        #[arg(long, default_value_t = DEFAULT_UPLOAD_CONCURRENCY)]
        concurrency: usize,

        /// Treat the input as a tar archive (bee's `application/x-tar`
        /// collection upload): unpack and upload each regular file as its
        /// own entry in a multi-entry mantaray, addressable individually.
        /// Auto-enabled for `*.tar`. Pass to force collection mode on
        /// inputs without a `.tar` extension.
        #[arg(long)]
        collection: bool,

        /// (Collection mode) Filename served when the root manifest is
        /// fetched without a sub-path. Equivalent to bee's
        /// `Swarm-Index-Document` header. Defaults to `index.html` when
        /// running in collection mode; pass `--index-document ""` to
        /// disable. Ignored for non-collection uploads.
        #[arg(long, value_name = "FILE")]
        index_document: Option<String>,

        /// (Collection mode) Filename served on lookups that miss.
        /// Equivalent to bee's `Swarm-Error-Document` header. Ignored
        /// for non-collection uploads.
        #[arg(long, value_name = "FILE")]
        error_document: Option<String>,

        /// Reed–Solomon redundancy level for the upload:
        /// `none`|`medium`|`strong`|`insane`|`paranoid` (or 0-4, bee's
        /// `Swarm-Redundancy-Level` values). Defaults to `medium`, which is
        /// what a bee gateway applies to `POST /bytes` and `POST /bzz`.
        ///
        /// Erasure coding adds parity chunks so the object stays readable
        /// when some of its data chunks are unretrievable — the normal state
        /// of a freshly uploaded object for a forwarding-dependent client
        /// (ethersphere/bee#5541). It costs postage: ~+8% chunks on large
        /// files at `medium`, but proportionally much more on small ones (a
        /// two-chunk file gets three parity chunks). `--redundancy none`
        /// reproduces the pre-erasure behaviour — and a different reference,
        /// since the level is encoded in the root chunk's span.
        #[arg(long, value_name = "LEVEL", default_value_t = hoverfly::erasure::DEFAULT_UPLOAD_LEVEL)]
        redundancy: hoverfly::erasure::Level,

        /// Connect to a running daemon instead of executing the upload
        /// in this process. The daemon must own a warm session pool —
        /// see `hoverfly daemon`. Mutually exclusive with the in-process
        /// peerlist; the daemon's own peerlist is used.
        #[cfg(unix)]
        #[arg(long, value_name = "SOCKET")]
        daemon: Option<PathBuf>,
    },

    /// Compute the Swarm BMT (content) root of a file without uploading.
    ///
    /// No network, no postage batch, no key — pure local hashing. The
    /// output mirrors exactly what `upload` would produce for the same
    /// input and flags:
    ///
    /// - Single file (default): prints the bare file BMT root (what
    ///   `upload --raw` produces) and the single-entry mantaray manifest
    ///   root (what the default `upload` produces, addressable via
    ///   `fetch <root> --path <name>`).
    /// - Collection (`*.tar`, or `--collection`): prints the multi-entry
    ///   manifest root (what `upload <file>.tar` produces), matching
    ///   bee's `application/x-tar` collection semantics.
    Bmt {
        /// Input file
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Override the manifest path used to derive the single-entry
        /// manifest root (default: file basename). Must match the
        /// `--manifest-path` you intend to pass to `upload` for the
        /// manifest roots to agree. Ignored in collection mode.
        #[arg(long, value_name = "PATH")]
        manifest_path: Option<String>,

        /// Override the Content-Type baked into the manifest entry
        /// (default: auto-detected from extension). Must match what
        /// `upload` will use for the manifest roots to agree. Ignored in
        /// collection mode (per-entry types are auto-detected there).
        #[arg(long, value_name = "MIME")]
        content_type: Option<String>,

        /// Treat the input as a tar archive (bee's collection upload):
        /// compute the multi-entry manifest root instead of a single
        /// file root. Auto-enabled for `*.tar`. Pass to force collection
        /// mode on inputs without a `.tar` extension.
        #[arg(long)]
        collection: bool,

        /// (Collection mode) Filename served when the root manifest is
        /// fetched without a sub-path. Defaults to `index.html`, matching
        /// `upload`'s collection default; pass `--index-document ""` to
        /// disable. Must match what `upload` will use for the roots to agree.
        #[arg(long, value_name = "FILE")]
        index_document: Option<String>,

        /// (Collection mode) Filename served on lookups that miss. Must
        /// match what `upload` will use for the roots to agree.
        #[arg(long, value_name = "FILE")]
        error_document: Option<String>,

        /// Redundancy level to hash at — must match the `--redundancy` you
        /// will pass to `upload` for the roots to agree, since the level is
        /// encoded in the root chunk's span. Defaults to `medium`, the same
        /// default `upload` uses.
        #[arg(long, value_name = "LEVEL", default_value_t = hoverfly::erasure::DEFAULT_UPLOAD_LEVEL)]
        redundancy: hoverfly::erasure::Level,
    },

    /// Run an HTTP chunk-push relay (stage A: /v1/status + the
    /// flag-gated /v1/probe self-push experiment endpoint). See
    /// docs/pusher-design.md. No IPC socket, no retrieval over HTTP,
    /// no key material accepted over the wire; probe mode signs with
    /// HOVERFLY_PROBE_KEY / HOVERFLY_PROBE_BATCH from the environment.
    #[cfg(feature = "pusher")]
    Pusher {
        /// TCP address the pusher's HTTP endpoint listens on. On
        /// container platforms bind 0.0.0.0:$PORT.
        #[arg(long, default_value = "127.0.0.1:8550", value_name = "ADDR")]
        listen: std::net::SocketAddr,

        /// peers.json path — the warm peer cache probe/push session
        /// pools fill from (and save reachability observations back to).
        #[arg(long, default_value = "peers.seed.json", value_name = "FILE")]
        peerlist: PathBuf,

        /// Enable POST /v1/probe: generate + stamp + push a random blob
        /// with the env-provided throwaway key/batch and stream back a
        /// metrics report. The instrument for the cloud-egress-IP gate
        /// experiment; off by default because it makes the pusher sign.
        #[arg(long)]
        probe: bool,

        /// Gnosis RPC used by probe mode to resolve batch depth and
        /// owner-check the probe key (skipped when HOVERFLY_PROBE_DEPTH
        /// is set).
        #[arg(
            long,
            default_value = "https://rpc.gnosischain.com",
            value_name = "URL"
        )]
        rpc_url: String,

        // ── Metered mode (docs/pusher-incentives.md Stage 1) ──────────
        /// Bill clients for relayed bytes with off-chain SWAP cheques.
        /// Off by default: `open` is today's unmetered behaviour and is
        /// what the production lanes run.
        #[arg(long)]
        meter: bool,

        /// Hostname(s) this relay is reached at. **Required with
        /// `--meter`.** The admission challenge binds the origin a client
        /// dialled, and the relay compares it against *this* value — never
        /// against the `Host` header, which the same client supplies and
        /// which would make the check a no-op that silently reopens
        /// cross-relay replay.
        #[arg(long, value_name = "HOST")]
        origin: Vec<String>,

        /// EOA that cheques are made out to. The relay holds this address
        /// only, never the key: cashing out happens elsewhere.
        #[arg(long, value_name = "0xADDR")]
        beneficiary: Option<String>,

        /// Settlement chain. Pins the EIP-712 domain and selects the
        /// hardcoded SimpleSwapFactory; a chain with no vetted factory
        /// cannot run metered.
        #[arg(long, default_value_t = 100, value_name = "ID")]
        chequebook_chain: u64,

        /// Directory for the ledger and relay secret. **Required with
        /// `--meter`**: without durable state a client re-presents its
        /// last cheque after every restart and is credited the full
        /// cumulative again, which is unlimited free service from one
        /// signature.
        #[arg(long, value_name = "DIR")]
        state_dir: Option<std::path::PathBuf>,

        /// PLUR per KiB of body admitted.
        #[arg(long, value_name = "PLUR")]
        price_plur_per_kib: Option<u128>,

        /// Smallest cheque accepted, to bound RPC cost per unit of value.
        #[arg(long, value_name = "PLUR")]
        min_cheque_plur: Option<u128>,

        /// Debt at which a client is expected to settle.
        #[arg(long, value_name = "PLUR")]
        settle_every_plur: Option<u128>,

        /// Global ceiling on a credit line. The actual cap is per batch:
        /// `min(batch_remaining_value / credit_ratio, this)`.
        #[arg(long, value_name = "PLUR")]
        max_outstanding_plur: Option<u128>,

        /// Credit line = batch remaining on-chain value ÷ this. The Sybil
        /// margin is this ratio by construction, independent of batch size.
        #[arg(long, value_name = "N")]
        credit_ratio: Option<u128>,

        /// Enforce 402 when an account is over its cap. Default is soft
        /// mode: meter, report, and serve anyway — which is what Stage 1
        /// ships, so the overshoot rate can be measured against live
        /// traffic before anyone is refused.
        #[arg(long)]
        meter_hard: bool,
    },

    /// Run a long-lived daemon that holds a warm session pool across
    /// upload/fetch requests. Listens on a unix socket; the same CLI
    /// (`upload --daemon <socket>` / `fetch --daemon <socket>`)
    /// connects in client mode. Reduces per-request session pool
    /// fill from ~3-10 s to ~0 s.
    #[cfg(unix)]
    Daemon {
        /// Unix socket path the daemon listens on. Removed on graceful
        /// shutdown; stale sockets from crashed daemons are unlinked
        /// at startup.
        #[arg(long, value_name = "PATH")]
        socket: PathBuf,

        /// peers.json path (loaded at startup, saved on shutdown).
        #[arg(long, default_value = "peers.json", value_name = "FILE")]
        peerlist: PathBuf,

        /// Target size of the warm session pool. The daemon eagerly dials
        /// this many sessions on startup and a fast maintenance loop keeps
        /// the pool topped up for all subsequent requests.
        ///
        /// Default 256 = the documented throughput operating point (pool
        /// 128 ≈ 665 KiB/s, 256 ≈ 1055 on a VPS; see PERFORMANCE.md). The
        /// maintenance loop now holds a big pool near target, so a large
        /// default is worthwhile rather than the old minimal 16 that churned
        /// down to a handful of live sessions. Lower it (e.g. 64) on a
        /// resource-constrained box: 256 outbound connections ≈ 256 fds plus
        /// a steady ~target/8 dials/sec of maintenance traffic.
        #[arg(long, default_value_t = 256)]
        pool_size: usize,

        /// (Experimental) libp2p multiaddr to bind an inbound
        /// bee-protocol listener on. When set together with
        /// `--identity` and `--advertise`, the daemon serves
        /// retrieval requests from its local upload cache. Marginal
        /// help in practice — bee peers route retrieval by proximity
        /// to the chunk address, so a single-overlay daemon is
        /// rarely the closest peer. Default behaviour (no flag) is
        /// outbound-only.
        #[arg(long, value_name = "MULTIADDR")]
        listen: Option<String>,

        /// Daemon identity (hex secp256k1 private key, 32 bytes).
        /// Required only when `--listen` is set.
        #[arg(long, value_name = "HEX")]
        identity: Option<String>,

        /// Publicly-routable multiaddr to advertise. Only used with
        /// `--listen`. Without it the listener accepts dial-backs
        /// from bee but bee never adds us to its routing tables.
        #[arg(long, value_name = "MULTIADDR")]
        advertise: Option<String>,

        /// Number of recursive discovery hops the daemon's eager
        /// pool fill performs against the bootnode before opening
        /// sessions. Default 1 (bootnode only) — enough when
        /// `peers.json` is already populated. Set to 3-5 on a cold
        /// peerlist (no prior `discover` run) so the eager pool
        /// fill has thousands of candidates to dial. The discover
        /// happens under the daemon's stable identity (when
        /// `--listen` + `--identity` are set), so bees don't
        /// reject it via kademlia saturation — unlike the ephemeral
        /// `hoverfly discover` subcommand which can be RST'd by
        /// every bootnode on a fresh runner.
        #[arg(long, default_value_t = 1, value_name = "N")]
        discover_rounds: usize,

        /// Bootstrap peer multiaddr for the daemon's eager pool fill
        /// discover. Pass `--bootnode` multiple times to supply
        /// fallbacks: discover tries each in order until one returns
        /// a non-empty peer set. Defaults to a single entry,
        /// `/dnsaddr/mainnet.ethswarm.org`, which resolves to the
        /// Swarm Foundation bootnodes.
        ///
        /// Multiple bootnodes are useful because bee performs
        /// kademlia bin-saturation gating at the handshake substream:
        /// our overlay can be silently rejected by one peer (the
        /// `/swarm/handshake/14.0.0/handshake` substream returns
        /// `UnsupportedProtocol` even though identify completed),
        /// while a peer in a different bin accepts us. Listing a
        /// handful of stable peers across different ASes / regions
        /// makes cold-start robust against this random rejection.
        ///
        /// May 2026: GitHub Actions runners, CircleCI runners, and at
        /// least one Hetzner VPS saw the official mainnet bootnodes
        /// reject the handshake substream while regular peers still
        /// accepted it.
        #[arg(
            long,
            value_name = "MULTIADDR",
            action = clap::ArgAction::Append,
            default_values_t = [MAINNET_BOOTNODE.to_string()],
        )]
        bootnode: Vec<String>,
    },

    /// Send a SavePeers request to a running daemon, forcing it to
    /// write its in-memory peerlist (plus accumulated reachability
    /// observations) to the daemon's `--peerlist` file. Useful to
    /// harvest the live peer set of a long-running daemon without
    /// interrupting it. Equivalent to what graceful shutdown does
    /// (via SIGINT), minus the actual shutdown.
    #[cfg(unix)]
    SavePeers {
        /// Unix socket path of the running daemon.
        #[arg(long, value_name = "PATH")]
        socket: PathBuf,
    },

    /// Query a running daemon's pool + peerlist stats: how many peer
    /// sessions are live right now vs the configured `--pool-size`
    /// target, and how many dial candidates the peerlist holds. Use
    /// this to see whether the pool is filling toward target or capped.
    #[cfg(unix)]
    Status {
        /// Unix socket path of the running daemon.
        #[arg(long, value_name = "PATH")]
        socket: PathBuf,
    },

    /// Search for a vanity overlay nonce that targets bee mainnet's
    /// kademlia bin structure.
    ///
    /// Bee mainnet bins are saturated at the default
    /// `defaultOverSaturationPeers = 18` per kademlia bin
    /// (`pkg/topology/kademlia/kademlia.go:55`). When we dial a bee
    /// peer with a random overlay, our PO to that peer is typically
    /// 0-2 — meaning we drop into their bin 0/1/2, which is the
    /// most-saturated. Bee rejects us with `topology.ErrOversaturated`
    /// before any upload happens.
    ///
    /// Two operating modes:
    ///
    /// **Single-target mode** (`--target-overlay`): find a nonce
    /// that maximizes PO to ONE specific peer. Useful for anchoring
    /// near a known stable peer (bootnode, Swarm Foundation
    /// infrastructure). Expected cost: ~2^k tries for PO=k.
    ///
    /// **Coverage mode** (default, uses `peers.json`): find a nonce
    /// that maximizes PO to MANY peers at once. Realistic targets
    /// here are PO=3 against ~15-20% of the pool — beyond that the
    /// search hits the bound `expected_matches = N × 2^-PO` and you
    /// can't significantly outperform the uniform distribution.
    ///
    /// The search is keccak256-bound: ~1 µs per candidate on a
    /// modern x86 core, so brute-forcing PO≥10 against ONE peer
    /// (~1024 tries) is instant; PO≥4 with 15% coverage against
    /// 3000 peers takes a few minutes.
    ///
    /// Writes the winning nonce to `--output` (default
    /// `overlay-nonce`) so the daemon's `--nonce-file` flag picks it
    /// up on next start.
    VanityOverlay {
        /// Private key (hex secp256k1, 32 bytes) — same key used for
        /// the daemon's `--identity`. We need it because the overlay
        /// is `keccak256(eth_address || network_id || nonce)`, so the
        /// key determines half the input. Different keys → different
        /// vanity nonces.
        #[arg(long, value_name = "HEX")]
        key: String,

        /// Target overlay(s) for anchored mode (hex, 32 bytes each;
        /// pass multiple times). When set, the search maximizes
        /// PO against this set of overlays instead of the peers.json
        /// pool.
        ///
        /// Single target: search maximizes PO against that one
        /// overlay. Anchors us near a specific known stable peer
        /// (e.g. a bootnode).
        ///
        /// Multiple targets: search maximizes the *minimum* PO
        /// across the set. The result anchors us close enough to
        /// EVERY peer in the list that we land in their deep bins,
        /// trading per-target PO for redundancy. Best with 3-10
        /// peers that are themselves close in overlay space (e.g.
        /// the top-K most-used peers from a previous upload trace).
        #[arg(long, value_name = "HEX")]
        target_overlay: Vec<String>,

        /// `peers.json` path. Used as the target set in coverage
        /// mode (when `--target-overlay` is not set).
        #[arg(long, default_value = "peers.json", value_name = "FILE")]
        peerlist: PathBuf,

        /// Target proximity-order. The search succeeds when the
        /// candidate overlay's PO to the target is ≥ this value
        /// (single-target mode) or when `--min-coverage` peers
        /// reach this PO (coverage mode).
        #[arg(long, default_value_t = 10)]
        target_po: u8,

        /// Coverage mode only: stop once this fraction of peers in
        /// `peerlist` reach PO ≥ `target_po`. Beware: the natural
        /// uniform expectation is `2^-target_po`, so meaningful
        /// targets are `2-3×` that (e.g. coverage=0.15 with
        /// target_po=3, since 2^-3 = 0.125).
        #[arg(long, default_value_t = 0.15)]
        min_coverage: f64,

        /// Output file for the chosen nonce. Pass this same path as
        /// `--nonce-file` when starting the daemon.
        #[arg(short, long, default_value = "overlay-nonce", value_name = "FILE")]
        output: PathBuf,

        /// Hard ceiling on search attempts. Default 10M; with a
        /// ~1 µs/keccak rate that's ~10 s budget on a single core.
        /// Raise for higher `--target-po`.
        #[arg(long, default_value_t = 10_000_000u64)]
        max_attempts: u64,

        /// Network ID (1 = mainnet, 10 = testnet). Must match the
        /// daemon's `--network-id`.
        #[arg(long, default_value_t = 1)]
        network_id: u64,
    },

    /// Manage on-chain postage stamp batches.
    ///
    /// Unlike every other subcommand, `batch` makes real on-chain RPC
    /// calls (Gnosis chain by default). Requires an `--rpc-url` and a
    /// `--key` whose Ethereum address holds enough BZZ to fund the
    /// batch (depth=20 with the current price typically costs <1 BZZ
    /// per day of validity).
    #[cfg(unix)]
    Batch {
        #[command(subcommand)]
        action: BatchAction,
    },

    /// Cash cheques a metered relay has accepted.
    ///
    /// Reads the relay's ledger, prices each held cheque on-chain, and
    /// presents the ones worth collecting. **Run this somewhere other than
    /// the relay**: `cashChequeBeneficiary` must be sent *by* the
    /// beneficiary, so it needs the beneficiary's private key — which is
    /// exactly the key a relay box is designed never to hold. Copy the
    /// relay's state directory (it contains `ledger.json`), or point
    /// `--state-dir` at a snapshot copy of that directory, and run this
    /// from a machine that does.
    ///
    /// A cheque is cumulative, so only the newest one per chequebook is
    /// ever presented; gas is paid once per chequebook, not once per
    /// cheque received.
    ///
    /// Behind the `pusher` feature because it reads the *relay's* ledger:
    /// without a relay there are no cheques to cash. (Ideally this would
    /// be `#[cfg(unix)]` with only `ledger` ungated — a cashout box needs
    /// no hyper server — but `ledger` currently shares the `pusher` gate,
    /// so cashing requires it for now.)
    #[cfg(all(unix, feature = "pusher"))]
    Cashout {
        #[arg(
            long,
            default_value = "https://rpc.gnosischain.com",
            value_name = "URL"
        )]
        rpc_url: String,
        /// The **beneficiary's** private key — the EOA cheques were made
        /// out to, and the only address the contract will pay.
        #[arg(long, value_name = "KEY")]
        key: String,
        /// Relay state directory containing `ledger.json`.
        #[arg(long, value_name = "DIR")]
        state_dir: std::path::PathBuf,
        /// Where the BZZ should land. Defaults to the beneficiary.
        #[arg(long, value_name = "ADDR")]
        recipient: Option<String>,
        /// Skip cheques worth less than this in BZZ. Measured cashouts use
        /// ~75-110k gas at ~1e-10 xDAI, so any non-zero cheque repays its
        /// gas; this threshold is a batching convenience — how much value
        /// to let accumulate before spending an RPC round trip and a
        /// pending transaction — not a break-even (§9.3).
        #[arg(long, default_value = "0.25", value_name = "BZZ")]
        min_amount: String,
        /// Only one chequebook, rather than everything in the ledger.
        #[arg(long, value_name = "ADDR")]
        chequebook: Option<String>,
        /// Price everything and print it, sending nothing.
        #[arg(long)]
        dry_run: bool,
        #[arg(long, default_value_t = 100, value_name = "ID")]
        chain_id: u64,
        #[arg(long, default_value_t = 300, value_name = "SECS")]
        timeout: u64,
    },

    /// Manage a SWAP chequebook — the contract that pays metered pusher
    /// relays (`docs/pusher-incentives.md`).
    ///
    /// Deliberately its own command rather than something an upload does
    /// for you: deploying a contract is irreversible and spends real funds,
    /// and an upload that deployed one silently because a lane quoted a
    /// price would fire before you had decided you wanted to pay at all.
    #[cfg(unix)]
    Chequebook {
        #[command(subcommand)]
        action: ChequebookAction,
    },

    /// Bridge funds from another chain to xDAI + BZZ on Gnosis via Relay.
    ///
    /// Solves the setup chicken-and-egg: `batch create` needs the signer's
    /// address to already hold a little xDAI (gas) and some BZZ on Gnosis.
    /// This command funds it from a token you hold on Ethereum, Base,
    /// Optimism, or Arbitrum, using the permissionless Relay API
    /// (<https://docs.relay.link>) — no API key required.
    ///
    /// `--to both` (default) checks the recipient's xDAI balance on Gnosis
    /// and only tops up gas if it's below the threshold, then swaps the
    /// rest to BZZ. NOTE: Relay needs a little native gas on the *origin*
    /// chain to broadcast the deposit transaction (it covers destination
    /// gas, not origin).
    ///
    /// Like `batch`, this is the rare subcommand that makes on-chain RPC
    /// calls. It's an optional compile-time feature (`bridge`, on by
    /// default); build with `--no-default-features --features cli` to omit
    /// it entirely.
    #[cfg(feature = "bridge")]
    Bridge {
        /// Origin chain: ethereum | base | optimism | arbitrum (or a
        /// numeric EVM chain id for any other Relay-supported chain).
        #[arg(long, value_name = "CHAIN")]
        from_chain: String,

        /// Origin token to spend. Either:
        ///   - a token **symbol** (e.g. `USDC`), resolved to the canonical
        ///     address AND decimals on `--from-chain` via Relay's token
        ///     list — no need to know the address or `--from-decimals`; or
        ///   - a raw **0x address** (used verbatim, with `--from-decimals`).
        /// Omit entirely to spend the chain's native gas token (ETH).
        #[arg(long, value_name = "SYMBOL|ADDR")]
        from_token: Option<String>,

        /// Amount of the origin token to spend, in whole units (e.g.
        /// `2.5`). Combined with the token's decimals to compute the
        /// on-wire amount.
        #[arg(long, value_name = "AMOUNT")]
        amount: String,

        /// Decimals to assume when `--from-token` is a raw 0x address.
        /// Ignored when `--from-token` is a symbol or omitted (decimals
        /// are resolved automatically then). USDC/USDT = 6; most ERC-20s
        /// = 18. Defaults to 6 (the common stablecoin case).
        #[arg(long, default_value_t = 6, value_name = "N")]
        from_decimals: u8,

        /// What to acquire on Gnosis: bzz | xdai | both.
        #[arg(long, default_value = "both", value_name = "TARGET")]
        to: String,

        /// Origin chain JSON-RPC endpoint. Required — used to broadcast
        /// the deposit transaction Relay returns and to read the origin
        /// native-gas balance.
        #[arg(long = "rpc-url", value_name = "URL")]
        origin_rpc_url: String,

        /// Gnosis JSON-RPC endpoint, used for the `--to both` xDAI
        /// balance check. Ignored for `--to bzz` / `--to xdai`.
        #[arg(
            long,
            value_name = "URL",
            default_value = "https://rpc.gnosischain.com"
        )]
        gnosis_rpc_url: String,

        /// Signer private key (hex, 32 bytes). Pays origin gas and signs
        /// the deposit. Its derived address is the default `--recipient`.
        #[arg(long, value_name = "HEX")]
        key: String,

        /// Recipient on Gnosis. Defaults to the signer's address (the
        /// usual case: fund your own upload key).
        #[arg(long, value_name = "ADDR")]
        recipient: Option<String>,

        /// Optional Relay API key. Not required (Relay is permissionless);
        /// only raises the rate limit.
        #[arg(long, value_name = "KEY")]
        api_key: Option<String>,

        /// `--to both`: top up xDAI only when the recipient's balance is
        /// below this many whole xDAI. Default 1.0.
        #[arg(long, default_value_t = 1.0, value_name = "XDAI")]
        xdai_topup_threshold: f64,

        /// `--to both`: how much xDAI (whole units) to acquire when
        /// topping up. Default 1.0.
        #[arg(long, default_value_t = 1.0, value_name = "XDAI")]
        xdai_topup_amount: f64,

        /// Overall timeout (seconds) for each leg's origin-receipt wait
        /// and Relay fill poll. Default 180.
        #[arg(long, default_value_t = 180, value_name = "SECS")]
        bridge_timeout: u64,
    },
}

#[cfg(unix)]
#[derive(Subcommand)]
enum ChequebookAction {
    /// Deploy a chequebook through bee's canonical SimpleSwapFactory.
    ///
    /// The issuer is `--key`'s address, and it must be the **batch owner**:
    /// a metered relay only accepts a cheque whose chequebook `issuer()`
    /// equals the account it billed. The issuer is also the only address
    /// that can ever `withdraw()`, so never deploy with a key you do not
    /// exclusively control.
    ///
    /// Deploys with a hard-deposit timeout of 0, matching every bee
    /// chequebook. Deposits are therefore not locked; see §11.2.
    Deploy {
        #[arg(
            long,
            default_value = "https://rpc.gnosischain.com",
            value_name = "URL"
        )]
        rpc_url: String,
        /// Private key (hex, 32 bytes). Its address becomes the issuer.
        #[arg(long, value_name = "KEY")]
        key: String,
        #[arg(long, default_value_t = 100, value_name = "ID")]
        chain_id: u64,
        /// Seconds to wait for the deploy receipt.
        #[arg(long, default_value_t = 300, value_name = "SECS")]
        timeout: u64,
    },
    /// Deposit BZZ into an existing chequebook.
    ///
    /// Separate from `deploy` so topping up later does not mean pretending
    /// to redeploy. Refuses to send to an address that does not answer
    /// `issuer()`, or whose issuer is not `--key` — only the issuer can
    /// withdraw, so funding someone else's chequebook strands the deposit.
    Fund {
        #[arg(
            long,
            default_value = "https://rpc.gnosischain.com",
            value_name = "URL"
        )]
        rpc_url: String,
        #[arg(long, value_name = "KEY")]
        key: String,
        #[arg(long, value_name = "ADDR")]
        chequebook: String,
        /// BZZ to deposit (decimal, e.g. `0.05`). BZZ has 16 decimals.
        #[arg(long, value_name = "BZZ")]
        amount: String,
        #[arg(long, default_value_t = 100, value_name = "ID")]
        chain_id: u64,
        #[arg(long, default_value_t = 300, value_name = "SECS")]
        timeout: u64,
    },
    /// Print a chequebook's on-chain state: issuer, balance liquid to a
    /// given beneficiary, what it has already paid out, and whether it has
    /// ever bounced.
    Status {
        #[arg(
            long,
            default_value = "https://rpc.gnosischain.com",
            value_name = "URL"
        )]
        rpc_url: String,
        #[arg(long, value_name = "ADDR")]
        chequebook: String,
        /// Beneficiary to report liquidity for. Defaults to the zero
        /// address, which reports the plain liquid balance.
        #[arg(long, value_name = "ADDR")]
        beneficiary: Option<String>,
    },
}

#[derive(Subcommand)]
enum BatchAction {
    /// Create a new postage stamp batch on-chain.
    ///
    /// Flow (matches bee's `postagecontract.CreateBatch`):
    /// 1. Read `lastPrice` and `minimumValidityBlocks` from the
    ///    PostageStamp contract to compute the min initial balance.
    /// 2. Verify the signer has enough BZZ to cover
    ///    `initial_balance_per_chunk * 2^depth`.
    /// 3. Approve the PostageStamp contract to spend the BZZ.
    /// 4. Call `createBatch(owner, balancePerChunk, depth, 16,
    ///    randomNonce, immutable)`.
    /// 5. Parse the `BatchCreated` event from the receipt and emit
    ///    the resulting batch ID.
    Create {
        /// JSON-RPC endpoint for the chain. For Swarm mainnet this is
        /// any Gnosis chain RPC (e.g. `https://rpc.gnosischain.com`).
        #[arg(long, value_name = "URL")]
        rpc_url: String,

        /// Signer private key (hex, 32 bytes). Pays gas, owns the
        /// resulting batch unless `--owner` is set.
        #[arg(long, value_name = "HEX")]
        key: String,

        /// Approximate storage volume the batch should cover. Combined
        /// with `--duration`, derives `--depth` and `--amount-per-chunk`
        /// via the same formulas as the official postage-stamp
        /// calculator at <https://docs.ethswarm.org/docs/develop/tools-and-features/buy-a-stamp-batch/#calculators>.
        ///
        /// Accepts a number with a unit suffix (binary): `kB`, `MB`,
        /// `GB`, `TB`, `PB`. Examples: `100MB`, `2GB`, `1.5TB`.
        /// Picks the smallest depth whose effective volume (unencrypted,
        /// no erasure coding, 0.1% failure quantile) covers the value.
        ///
        /// Mutually exclusive with `--depth`.
        #[arg(
            long,
            value_name = "SIZE",
            conflicts_with_all = ["depth", "amount_per_chunk"],
            requires = "duration"
        )]
        size: Option<String>,

        /// How long the batch should stay valid. Combined with `--size`,
        /// derives `--amount-per-chunk` as `ceil(duration/5s) × lastPrice`
        /// + a small buffer, matching bee-docs.
        ///
        /// Accepts a number with a unit suffix: `h` (hours), `d`
        /// (days), `w` (weeks), `y` (years). Examples: `24h`, `30d`,
        /// `2w`, `1y`. Minimum is 24h (the on-chain
        /// `minimumValidityBlocks` floor).
        ///
        /// Mutually exclusive with `--amount-per-chunk`.
        #[arg(
            long,
            value_name = "DURATION",
            conflicts_with_all = ["depth", "amount_per_chunk"],
            requires = "size"
        )]
        duration: Option<String>,

        /// Per-chunk initial balance in BZZ-PLUR (1 BZZ = 10^16 PLUR).
        /// Low-level alternative to `--duration`. Must exceed
        /// `lastPrice * minimumValidityBlocks` (~24h of storage on
        /// Swarm mainnet); the contract reverts otherwise. Total BZZ
        /// pulled from `--key` is this value × 2^depth.
        #[arg(long, value_name = "PLUR", requires = "depth")]
        amount_per_chunk: Option<String>,

        /// Batch depth. Stamp count = 2^depth. Must be > 16 (bucket
        /// depth); typical values 20-24. Low-level alternative to
        /// `--size`. Higher depth = more chunks = proportionally
        /// more BZZ.
        #[arg(long, requires = "amount_per_chunk")]
        depth: Option<u8>,

        /// Immutable batch flag. Mutable (default) can be topped up
        /// and diluted; immutable can't.
        #[arg(long)]
        immutable: bool,

        /// Override the batch owner. Defaults to the signer's address.
        /// The contract reverts on zero address.
        #[arg(long, value_name = "ADDR")]
        owner: Option<String>,

        /// PostageStamp contract address. Defaults to the Swarm
        /// mainnet deployment on Gnosis chain.
        #[arg(long, value_name = "ADDR")]
        postage_stamp: Option<String>,

        /// BZZ ERC-20 token address. Defaults to Swarm mainnet BZZ.
        #[arg(long, value_name = "ADDR")]
        bzz_token: Option<String>,

        /// EIP-155 chain id. Defaults to 100 (Gnosis).
        #[arg(long, default_value_t = 100)]
        chain_id: u64,
    },
}

/// Parse a tar archive into a flat list of `UploadFile`s (regular files
/// only), matching bee's `pkg/api/dirs.go::tarReader::Next` semantics.
fn read_tar_files(bytes: &[u8]) -> Result<Vec<UploadFile>, Box<dyn std::error::Error>> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(bytes));
    let mut out = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let header = entry.header().clone();
        if !header.entry_type().is_file() {
            continue;
        }
        let path = entry.path()?.to_string_lossy().into_owned();
        let path = path.trim_start_matches("./").to_string();
        if path.is_empty() || path == "." {
            continue;
        }
        let mut data = Vec::with_capacity(header.size().unwrap_or(0) as usize);
        std::io::Read::read_to_end(&mut entry, &mut data)?;
        let content_type = guess_content_type(&path);
        out.push(UploadFile {
            path,
            content_type,
            data,
        });
    }
    Ok(out)
}

/// Build a CLI-side `indicatif` progress bar wrapped in a [`ProgressFn`]
/// callback the library can call after each successful chunk push.
///
/// Returns `None` when stdout isn't a TTY (piping / redirecting to file)
/// so we don't pollute log captures with terminal escape codes; the
/// library then falls back to the existing tracing `pushed N/M chunks`
/// lines, which work fine in log files.
///
/// The bar's length starts at 0 because the library only knows the
/// final chunk count after stamping. The first callback invocation
/// resizes via `set_length`. The bar finalises itself the moment
/// `done == total`, then the closure's `ProgressBar` clone is dropped
/// when the caller releases the `ProgressFn` Arc.
fn make_progress_bar() -> Option<ProgressFn> {
    let pb = ProgressBar::new(0);
    if pb.is_hidden() {
        return None;
    }
    pb.set_style(
        ProgressStyle::with_template(
            "  pushing {bar:40.cyan/blue} {pos}/{len} chunks  ({percent}%, eta {eta}) {msg}",
        )
        .ok()?
        .progress_chars("##-"),
    );
    pb.enable_steady_tick(Duration::from_millis(250));
    let start = std::time::Instant::now();
    let cb: ProgressFn = Arc::new(move |done: usize, total: usize| {
        if pb.length() != Some(total as u64) {
            pb.set_length(total as u64);
        }
        pb.set_position(done as u64);
        // Throughput: each chunk holds ~4 KiB of data (Swarm leaf chunk).
        let elapsed = start.elapsed().as_secs_f64();
        if elapsed > 0.5 && done > 0 {
            let bytes = done as f64 * 4096.0;
            let bps = bytes / elapsed;
            let (rate, unit) = if bps >= 1024.0 * 1024.0 {
                (bps / (1024.0 * 1024.0), "MB/s")
            } else {
                (bps / 1024.0, "KB/s")
            };
            pb.set_message(format!("{rate:.1} {unit}"));
        }
        if done >= total {
            pb.finish_and_clear();
        }
    });
    Some(cb)
}

/// Build a CLI-side byte-based progress bar wrapped in a [`ProgressFn`] for the
/// **fetch** path. The callback receives `(done_bytes, total_bytes)`; the total
/// is the file's size (known from the root span), so the length is set on the
/// first call. Like [`make_progress_bar`], returns `None` when stdout isn't a
/// TTY so log captures stay clean.
fn make_byte_progress_bar() -> Option<ProgressFn> {
    let pb = ProgressBar::new(0);
    if pb.is_hidden() {
        return None;
    }
    pb.set_style(
        ProgressStyle::with_template(
            "  fetching {bar:40.cyan/blue} {bytes}/{total_bytes}  ({percent}%, {bytes_per_sec}, eta {eta})",
        )
        .ok()?
        .progress_chars("##-"),
    );
    pb.enable_steady_tick(Duration::from_millis(250));
    let cb: ProgressFn = Arc::new(move |done: usize, total: usize| {
        if pb.length() != Some(total as u64) {
            pb.set_length(total as u64);
        }
        pb.set_position(done as u64);
        if total > 0 && done >= total {
            pb.finish_and_clear();
        }
    });
    Some(cb)
}

/// Convert a 64-char hex Swarm reference to a multibase-encoded CIDv1
/// (`b...` lowercase base32). Returns `None` on malformed input.
fn root_hex_to_cid(root_hex: &str) -> Option<String> {
    let bytes = hex::decode(root_hex).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(hoverfly::cid::reference_to_cid(&arr))
}

fn guess_content_type(path: &str) -> Option<String> {
    hoverfly::mime::guess_from_path(path)
}

/// Print the session-retirement-cause counters to stderr at upload end.
/// See `hoverfly::transport::diag` for what each counter means.
/// Format `bytes / elapsed` as a human-readable throughput line.
/// Uses binary units (KiB/MiB) to match every other "throughput"
/// number in `PERFORMANCE.md`. Elapsed is captured at the CLI call
/// site, so it includes the wall-clock time spent stamping +
/// dispatching + waiting for the last receipt — i.e. exactly what
/// the user sees as "how long the upload took". This is the same
/// quantity `time` would report for `real`, but printed by the
/// binary so it can survive `> file` redirection without bash
/// timing-output going to stderr.
fn print_upload_throughput(bytes: usize, elapsed: std::time::Duration) {
    let secs = elapsed.as_secs_f64();
    if secs <= 0.0 || bytes == 0 {
        println!("upload took {:.2}s ({} bytes)", secs, bytes);
        return;
    }
    let bps = bytes as f64 / secs;
    let (rate, unit) = if bps >= 1024.0 * 1024.0 {
        (bps / (1024.0 * 1024.0), "MiB/s")
    } else if bps >= 1024.0 {
        (bps / 1024.0, "KiB/s")
    } else {
        (bps, "B/s")
    };
    println!(
        "upload: {} bytes in {:.2}s = {:.2} {}",
        bytes, secs, rate, unit,
    );
}

/// Load a 32-byte overlay nonce from `path`. Creates the file with
/// a fresh random nonce on first call. Subsequent calls return the
/// same nonce. Stored as hex (0x-prefixed) for human inspection; the
/// file is rewritten atomically via write-rename to avoid partial
/// writes on crash.
///
/// See the `--nonce-file` CLI documentation for why a stable overlay
/// matters for bee citizenship.
fn load_or_create_nonce(path: &std::path::Path) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    use std::io::Write;
    if let Ok(s) = std::fs::read_to_string(path) {
        let trimmed = s.trim().trim_start_matches("0x").trim_start_matches("0X");
        let bytes = hex::decode(trimmed)
            .map_err(|e| format!("--nonce-file {}: bad hex: {e}", path.display()))?;
        if bytes.len() != 32 {
            return Err(format!(
                "--nonce-file {}: expected 32 bytes, got {}",
                path.display(),
                bytes.len()
            )
            .into());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }
    // Missing — generate, persist, return. Atomic write-rename so a
    // crash mid-write can't leave a half-written file that loads
    // differently next time.
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|e| format!("os rng: {e}"))?;
    let tmp = path.with_extension("tmp");
    let mut f =
        std::fs::File::create(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
    f.write_all(format!("0x{}\n", hex::encode(nonce)).as_bytes())
        .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    drop(f);
    std::fs::rename(&tmp, path)
        .map_err(|e| format!("rename {} -> {}: {e}", tmp.display(), path.display()))?;
    eprintln!(
        "overlay-nonce: generated fresh nonce, persisted to {}",
        path.display()
    );
    Ok(nonce)
}

/// Parse a 20-byte Ethereum / chequebook address from hex with
/// optional `0x` prefix. Case-insensitive (we don't enforce EIP-55
/// checksumming because chequebook addresses are often copy-pasted
/// from bee logs in lowercase). Returns `Err` on length or charset
/// failure.
fn parse_address_hex(s: &str) -> Result<[u8; 20], String> {
    let trimmed = s.trim_start_matches("0x").trim_start_matches("0X");
    if trimmed.len() != 40 {
        return Err(format!(
            "expected 40 hex chars (20 bytes), got {} chars",
            trimmed.len()
        ));
    }
    let bytes = hex::decode(trimmed).map_err(|e| format!("bad hex: {e}"))?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Parse `--lane-pin URL,NODE,BENEFICIARY` entries into URL → pin.
fn parse_lane_pins(
    raw: &[String],
) -> Result<std::collections::HashMap<String, hoverfly::payer::LanePin>, String> {
    let mut out = std::collections::HashMap::new();
    for entry in raw {
        let parts: Vec<&str> = entry.split(',').collect();
        if parts.len() != 3 {
            return Err(format!(
                "--lane-pin must be URL,NODE,BENEFICIARY (0x-hex), got {entry:?}"
            ));
        }
        let url = parts[0].trim().trim_end_matches('/').to_string();
        if url.is_empty() {
            return Err(format!("--lane-pin has empty URL in {entry:?}"));
        }
        let node =
            parse_address_hex(parts[1].trim()).map_err(|e| format!("--lane-pin node: {e}"))?;
        let beneficiary = parse_address_hex(parts[2].trim())
            .map_err(|e| format!("--lane-pin beneficiary: {e}"))?;
        out.insert(
            url,
            hoverfly::payer::LanePin {
                node_eth_address: node,
                beneficiary,
            },
        );
    }
    Ok(out)
}

fn print_session_retire_diag() {
    use hoverfly::transport::diag;
    use std::sync::atomic::Ordering;
    let dead_low = diag::DEAD_RETIRE_LOW_GHOST.load(Ordering::Relaxed);
    let dead_prewarm = diag::DEAD_RETIRE_PREWARM_GHOST.load(Ordering::Relaxed);
    let dead_high = diag::DEAD_RETIRE_HIGH_GHOST.load(Ordering::Relaxed);
    let ghost_retire = diag::GHOST_RETIRE.load(Ordering::Relaxed);
    let max_pushes_retire = diag::MAX_PUSHES_RETIRE.load(Ordering::Relaxed);
    let prewarm_on_dead = diag::PREWARM_ON_DEAD.load(Ordering::Relaxed);
    let prewarm_on_ghost = diag::PREWARM_ON_GHOST.load(Ordering::Relaxed);
    let cheque_emitted = diag::CHEQUE_EMITTED.load(Ordering::Relaxed);
    let cheque_failed = diag::CHEQUE_FAILED.load(Ordering::Relaxed);
    let total = dead_low + dead_prewarm + dead_high + ghost_retire + max_pushes_retire;
    if total > 0 || prewarm_on_dead > 0 || prewarm_on_ghost > 0 {
        eprintln!(
            "session-retire: dead_low_ghost={} dead_prewarm_ghost={} dead_high_ghost={} ghost_threshold={} max_pushes={} total={}",
            dead_low, dead_prewarm, dead_high, ghost_retire, max_pushes_retire, total,
        );
        eprintln!(
            "prewarm: on_dead={} on_ghost={}",
            prewarm_on_dead, prewarm_on_ghost,
        );
    }
    if cheque_emitted > 0 || cheque_failed > 0 {
        eprintln!(
            "swap: cheques_emitted={} cheques_failed={}",
            cheque_emitted, cheque_failed,
        );
    }
    let conn_io = diag::CONN_CLOSED_IO.load(Ordering::Relaxed);
    let conn_ka = diag::CONN_CLOSED_KEEPALIVE.load(Ordering::Relaxed);
    let conn_clean = diag::CONN_CLOSED_CLEAN.load(Ordering::Relaxed);
    if conn_io > 0 || conn_ka > 0 || conn_clean > 0 {
        eprintln!(
            "conn-closed: io={} keepalive={} clean={}",
            conn_io, conn_ka, conn_clean,
        );
    }
    let hive_ok = diag::HIVE_ANNOUNCE_OK.load(Ordering::Relaxed);
    let hive_fail = diag::HIVE_ANNOUNCE_FAIL.load(Ordering::Relaxed);
    if hive_ok > 0 || hive_fail > 0 {
        eprintln!("hive-announce: ok={} fail={}", hive_ok, hive_fail);
    }
    let push_a = diag::PUSH_LATENCY_LT_100MS.load(Ordering::Relaxed);
    let push_b = diag::PUSH_LATENCY_100_500MS.load(Ordering::Relaxed);
    let push_c = diag::PUSH_LATENCY_500MS_2S.load(Ordering::Relaxed);
    let push_d = diag::PUSH_LATENCY_2_5S.load(Ordering::Relaxed);
    let push_e = diag::PUSH_LATENCY_5_10S.load(Ordering::Relaxed);
    let push_f = diag::PUSH_LATENCY_GT_10S.load(Ordering::Relaxed);
    let push_total = push_a + push_b + push_c + push_d + push_e + push_f;
    if push_total > 0 {
        eprintln!(
            "push-latency-buckets: <100ms={} 100-500ms={} 500ms-2s={} 2-5s={} 5-10s={} >10s={}",
            push_a, push_b, push_c, push_d, push_e, push_f
        );
    }
    let open_a = diag::OPEN_STREAM_LT_10MS.load(Ordering::Relaxed);
    let open_b = diag::OPEN_STREAM_10_100MS.load(Ordering::Relaxed);
    let open_c = diag::OPEN_STREAM_100_500MS.load(Ordering::Relaxed);
    let open_d = diag::OPEN_STREAM_GT_500MS.load(Ordering::Relaxed);
    let open_total = open_a + open_b + open_c + open_d;
    if open_total > 0 {
        eprintln!(
            "open-stream-buckets: <10ms={} 10-100ms={} 100-500ms={} >500ms={}",
            open_a, open_b, open_c, open_d
        );
    }
    let out_ok = diag::PUSH_OUTCOME_OK.load(Ordering::Relaxed);
    let out_shallow = diag::PUSH_OUTCOME_SHALLOW.load(Ordering::Relaxed);
    let out_overdraft = diag::PUSH_OUTCOME_OVERDRAFT.load(Ordering::Relaxed);
    let out_error = diag::PUSH_OUTCOME_ERROR.load(Ordering::Relaxed);
    let out_total = out_ok + out_shallow + out_overdraft + out_error;
    if out_total > 0 {
        eprintln!(
            "push-outcomes: ok={} shallow={} overdraft={} error={} (total={})",
            out_ok, out_shallow, out_overdraft, out_error, out_total,
        );
    }
    let ch_a = diag::CHUNK_LATENCY_LT_500MS.load(Ordering::Relaxed);
    let ch_b = diag::CHUNK_LATENCY_500MS_2S.load(Ordering::Relaxed);
    let ch_c = diag::CHUNK_LATENCY_2_5S.load(Ordering::Relaxed);
    let ch_d = diag::CHUNK_LATENCY_5_15S.load(Ordering::Relaxed);
    let ch_e = diag::CHUNK_LATENCY_GT_15S.load(Ordering::Relaxed);
    let ch_total = ch_a + ch_b + ch_c + ch_d + ch_e;
    if ch_total > 0 {
        eprintln!(
            "chunk-latency: <500ms={} 500ms-2s={} 2-5s={} 5-15s={} >15s={} (total={})",
            ch_a, ch_b, ch_c, ch_d, ch_e, ch_total,
        );
    }
    if let Ok(map) = diag::CONN_CLOSED_IO_DETAIL.lock() {
        if !map.is_empty() {
            // Sort descending by count so the dominant cause is first.
            let mut rows: Vec<(&String, &u64)> = map.iter().collect();
            rows.sort_by(|a, b| b.1.cmp(a.1));
            let parts: Vec<String> = rows.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
            eprintln!("conn-closed-io-detail: {}", parts.join(" "));
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // The library reads HOVERFLY_BUFFER_MULT from the environment at
    // upload dispatch time (`src/client.rs::push_chunks_inner`). The
    // `--buffer-multiplier` CLI flag plumbs the same knob without
    // requiring the user to export an env var. An explicit env var
    // takes precedence over the CLI default — set the env var from
    // the CLI value only if the env var is unset, so an explicit
    // `HOVERFLY_BUFFER_MULT=N` from the shell still wins.
    if std::env::var_os("HOVERFLY_BUFFER_MULT").is_none() {
        // Safety: single-threaded at this point (main hasn't done
        // anything else yet); unsafe in nightly's edition-2024
        // because env::set_var is process-wide.
        unsafe {
            std::env::set_var("HOVERFLY_BUFFER_MULT", cli.buffer_multiplier.to_string());
        }
    }

    let level = if cli.trace {
        Level::TRACE
    } else if cli.debug {
        Level::DEBUG
    } else if cli.verbose {
        Level::INFO
    } else {
        Level::WARN
    };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let cfg = TransportConfig {
        timeout: Duration::from_secs(cli.timeout),
        // Long idle timeout so warm connections aren't self-closed between
        // ops; harmless for one-shots (connections are busy during upload).
        idle_timeout: Duration::from_secs(600),
        dial_timeout: Duration::from_secs(cli.dial_timeout),
        network_id: cli.network_id,
        advertise: None,
        max_concurrent_substream_upgrades: cli.substream_upgrade_cap,
    };
    let doh = Doh::with_url(&cli.doh_url);

    // Build SWAP config once if a chequebook is provided; reused across
    // all `Transport`s spawned by subcommands below. Failing to parse
    // any of the user-supplied values is a fatal CLI error — we'd
    // rather refuse to start than silently downgrade to
    // pseudosettle-only when the user expected to pay.
    let swap_cfg = if let Some(cb_hex) = cli.chequebook.as_ref() {
        let cb = parse_address_hex(cb_hex).map_err(|e| format!("--chequebook: {e}"))?;
        let per_peer_cap = alloy_primitives::U256::from_str_radix(
            cli.chequebook_per_peer_cap_bzz.trim_start_matches("0x"),
            if cli.chequebook_per_peer_cap_bzz.starts_with("0x") {
                16
            } else {
                10
            },
        )
        .map_err(|e| format!("--chequebook-per-peer-cap-bzz: {e}"))?;
        let store = hoverfly::cheques::ChequeStore::load_or_create(&cli.cheques_file, cb)
            .map_err(|e| format!("loading {}: {e}", cli.cheques_file.display()))?;
        eprintln!(
            "swap: chequebook=0x{} chain_id={} per_peer_cap_bzz={} cheques_file={}",
            hex::encode(cb),
            cli.chequebook_chain_id,
            per_peer_cap,
            cli.cheques_file.display(),
        );
        Some(hoverfly::transport::SwapConfig {
            chequebook: cb,
            chain_id: cli.chequebook_chain_id,
            max_cumulative_per_peer_bzz: per_peer_cap,
            store: std::sync::Arc::new(tokio::sync::Mutex::new(store)),
        })
    } else {
        None
    };

    match cli.command {
        Commands::Discover {
            peer,
            output,
            wait,
            append,
            rounds,
            discover_concurrency,
            healthcheck,
            healthcheck_concurrency,
            ws_only,
        } => {
            let signer = SwarmSigner::random(cli.network_id);
            let transport = Transport::new(signer, cfg);
            let bootstrap: Multiaddr = peer.parse()?;
            let progress: hoverfly::client::DiscoverProgressFn = Arc::new(|ev| {
                use hoverfly::client::DiscoverEvent::*;
                match ev {
                    RoundStarted {
                        round,
                        total_rounds,
                        frontier_size,
                        total_peers_so_far,
                    } => {
                        println!(
                            "  round {round}/{total_rounds}: dialing {frontier_size} peer(s) (have {total_peers_so_far} so far)"
                        );
                    }
                    RoundFinished {
                        round,
                        total_rounds,
                        new_peers_this_round,
                        total_peers,
                    } => {
                        println!(
                            "  round {round}/{total_rounds} done: +{new_peers_this_round} new (total {total_peers})"
                        );
                    }
                }
            });
            let discovered = hoverfly::client::discover_recursive_with_progress(
                &transport,
                &doh,
                &bootstrap,
                Duration::from_secs(wait),
                rounds.max(1),
                discover_concurrency,
                Some(progress),
            )
            .await?;
            println!("discovered {} peers ({} hop(s))", discovered.len(), rounds);

            let mut store = if append {
                PeerStore::load_or_create(&output)
            } else {
                PeerStore::new()
            };
            let mut kept = 0usize;
            let mut dropped_non_ws = 0usize;
            for mut p in discovered {
                if ws_only {
                    // Keep only browser-dialable (/ws, /wss) underlays; drop the
                    // peer entirely if it has none. (`discover` already stripped
                    // unroutable/private IPs, so what's left is publicly dialable.)
                    p.underlays.retain(|u| hoverfly::peers::is_ws_underlay(u));
                    if p.underlays.is_empty() {
                        dropped_non_ws += 1;
                        continue;
                    }
                }
                kept += 1;
                store.upsert(p);
            }
            if ws_only {
                println!(
                    "ws-only: kept {kept} peer(s) with a /ws underlay, dropped {dropped_non_ws} tcp-only peer(s)"
                );
            }

            if healthcheck {
                println!("probing {} peers for reachability...", store.len());
                hoverfly::client::healthcheck_peers(&transport, &store, healthcheck_concurrency)
                    .await;
                hoverfly::peers::apply_log(&mut store, transport.reachability_log());
            }

            store.save(&output)?;
            println!("wrote {} peers to {}", store.len(), output.display());
        }

        Commands::Fetch {
            hash,
            output,
            path,
            list,
            peerlist,
            max_retries,
            concurrency,
            #[cfg(unix)]
            daemon,
        } => {
            #[cfg(unix)]
            if let Some(sock) = daemon {
                // `--output` is only needed when actually writing bytes.
                // `--list` enumerates the manifest and writes nothing, so
                // don't demand it in that mode.
                if !list && output.is_none() {
                    return Err("--output is required when using --daemon (unless --list)".into());
                }
                let req = hoverfly::daemon::Request::Fetch(hoverfly::daemon::FetchRequest {
                    hash,
                    path,
                    output: output.clone(),
                    max_retries,
                    concurrency,
                    list,
                });
                let resp = hoverfly::daemon::call(&sock, &req).await?;
                match resp {
                    hoverfly::daemon::Response::Listed { entries } => {
                        println!("{} entries:", entries.len());
                        for e in entries {
                            let ct = e.content_type.as_deref().unwrap_or("-");
                            println!("  {}  {}  [{}]", e.reference, e.path, ct);
                        }
                        return Ok(());
                    }
                    hoverfly::daemon::Response::Fetched {
                        bytes_written,
                        content_type,
                    } => {
                        let ct = content_type.as_deref().unwrap_or("-");
                        // Safe: non-list mode required `output` above.
                        let out_display = output
                            .as_deref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default();
                        println!(
                            "fetched {} bytes ({}) -> {} (via daemon)",
                            bytes_written, ct, out_display,
                        );
                        return Ok(());
                    }
                    hoverfly::daemon::Response::Err { message } => {
                        return Err(format!("daemon error: {message}").into());
                    }
                    other => return Err(format!("unexpected daemon response: {:?}", other).into()),
                }
            }
            let signer = SwarmSigner::random(cli.network_id);
            let transport = Transport::new(signer, cfg);
            let mut peers = PeerStore::load_or_create(&peerlist);
            if peers.is_empty() {
                return Err(format!(
                    "peerlist {} is empty — run `hoverfly discover` first",
                    peerlist.display()
                )
                .into());
            }

            let result: Result<(), Box<dyn std::error::Error>> = (async {
                if list {
                    let entries =
                        list_manifest_ex(&transport, &peers, &hash, max_retries, concurrency)
                            .await?;
                    println!("{} entries:", entries.len());
                    for e in entries {
                        let ct = e.content_type.as_deref().unwrap_or("-");
                        println!("  {}  {}  [{}]", e.reference, e.path, ct);
                    }
                    Ok(())
                } else {
                    let output = output.ok_or("--output is required (omit only with --list)")?;
                    // Byte-based progress bar (TTY only; `None` when piped so
                    // log captures stay clean). Drives on file-body bytes as
                    // they join, for both plain and erasure-coded objects.
                    let progress = make_byte_progress_bar();
                    if let Some(p) = path {
                        let (bytes, content_type) = fetch_manifest_path_progress(
                            &transport,
                            &peers,
                            &hash,
                            &p,
                            max_retries,
                            concurrency,
                            progress.as_ref(),
                        )
                        .await?;
                        std::fs::write(&output, &bytes)?;
                        let ct = content_type.as_deref().unwrap_or("-");
                        println!(
                            "fetched {} bytes ({}) -> {}",
                            bytes.len(),
                            ct,
                            output.display()
                        );
                    } else {
                        let bytes = fetch_bytes_progress(
                            &transport,
                            &peers,
                            &hash,
                            max_retries,
                            concurrency,
                            progress.as_ref(),
                        )
                        .await?;
                        std::fs::write(&output, &bytes)?;
                        println!("fetched {} bytes -> {}", bytes.len(), output.display());
                    }
                    Ok(())
                }
            })
            .await;

            // Persist reachability observations back to peers.json on
            // both success and error so the next run starts faster.
            hoverfly::peers::apply_log(&mut peers, transport.reachability_log());
            let _ = peers.save(&peerlist);
            result?;
        }

        Commands::Upload {
            file,
            batch,
            depth,
            rpc_url,
            no_owner_check,
            immutable,
            key,
            peerlist,
            pusher,
            max_retries,
            raw,
            manifest_path,
            content_type,
            concurrency,
            collection,
            index_document,
            error_document,
            redundancy,
            #[cfg(unix)]
            daemon,
        } => {
            // Resolve the batch depth. If the user passed `--depth`, trust
            // it. Otherwise read the batch's on-chain struct: infer depth
            // and (unless `--no-owner-check`) verify the batch owner
            // matches `--key`'s address — catching the two classic
            // silent-failure modes (wrong depth → bad bucket index math;
            // wrong key → stamps bee rejects → endless "could not push
            // chunk" retries).
            // Resolve depth AND mutability together. When `--depth` is
            // supplied we skip the on-chain read, so mutability comes from
            // the `--immutable` flag. Otherwise both come from chain (the
            // authoritative source) and the flag is ignored.
            let (depth, immutable): (u8, bool) = match depth {
                Some(d) => (d, immutable),
                None => {
                    let stamp_addr: alloy_primitives::Address =
                        hoverfly::batch::MAINNET_POSTAGE_STAMP
                            .parse()
                            .expect("hardcoded valid");
                    let info = hoverfly::batch::read_batch(&rpc_url, stamp_addr, &batch)
                        .await
                        .map_err(|e| {
                            format!(
                                "could not read batch depth on-chain (pass --depth to skip, \
                                 or set a working --rpc-url): {e}"
                            )
                        })?;
                    if info.not_found {
                        return Err(format!(
                            "batch {batch} not found on-chain at {} — wrong batch ID or \
                             not yet mined? Pass --depth to override.",
                            stamp_addr
                        )
                        .into());
                    }
                    if !no_owner_check {
                        // Derive the upload key's address and compare.
                        let signer_addr = {
                            let s = SwarmSigner::from_hex_with_nonce(
                                &key,
                                "0x0000000000000000000000000000000000000000000000000000000000000000",
                                cli.network_id,
                            )?;
                            alloy_primitives::Address::from(*s.eth_address())
                        };
                        if signer_addr != info.owner {
                            return Err(format!(
                                "batch owner mismatch: batch {batch} is owned by {} on-chain, \
                                 but --key derives to {}. bee will reject every stamp signed by \
                                 this key (\"could not push chunk\"). Use the batch owner's key, \
                                 or pass --no-owner-check if you are authorised to sign for it.",
                                info.owner, signer_addr,
                            )
                            .into());
                        }
                    }
                    (info.depth, info.immutable)
                }
            };

            #[cfg(unix)]
            if let Some(sock) = daemon {
                // Render the upload progress bar on THIS (client) terminal.
                // The daemon streams `Progress { done, total }` frames back
                // over the socket; `call_upload` invokes the callback on each.
                // When the terminal is not a TTY (`make_progress_bar` returns
                // None) we ask for no progress stream to avoid useless frames.
                let progress_cb = make_progress_bar();
                let req = hoverfly::daemon::Request::Upload(hoverfly::daemon::UploadRequest {
                    file: file.clone(),
                    batch: batch.clone(),
                    depth,
                    immutable,
                    key: key.clone(),
                    max_retries,
                    concurrency,
                    raw,
                    collection,
                    manifest_path: manifest_path.clone(),
                    content_type: content_type.clone(),
                    index_document: index_document.clone(),
                    error_document: error_document.clone(),
                    redundancy: Some(redundancy.to_string()),
                    progress: progress_cb.is_some(),
                });
                // Time the daemon round-trip end-to-end on the client
                // side. Includes IPC and any daemon-side work; mirrors
                // exactly what the user perceives. The daemon itself
                // doesn't report timing, so this is the only way to
                // get a throughput number for daemon-mode runs (used
                // in PERFORMANCE.md A/B comparisons).
                let upload_started = std::time::Instant::now();
                let resp = hoverfly::daemon::call_upload(&sock, &req, progress_cb.as_ref()).await?;
                let elapsed = upload_started.elapsed();
                match resp {
                    hoverfly::daemon::Response::Uploaded { root, bytes } => {
                        let cid = root_hex_to_cid(&root);
                        println!(
                            "uploaded {} bytes — manifest root: {} (via daemon)",
                            bytes, root
                        );
                        if let Some(c) = cid.as_deref() {
                            println!("bzz.limo:   https://bzz.limo/bzz/{root}/");
                            println!("subdomain:  https://{c}.bzz.limo/");
                        }
                        print_upload_throughput(bytes, elapsed);
                        return Ok(());
                    }
                    hoverfly::daemon::Response::Err { message } => {
                        return Err(format!("daemon error: {message}").into());
                    }
                    other => return Err(format!("unexpected daemon response: {:?}", other).into()),
                }
            }

            // Load (or create) a stable overlay nonce. See the
            // `--nonce-file` CLI documentation and the bee-citizenship
            // notes in `signer::from_bytes_with_nonce` for why this
            // matters for upload throughput on long-running peer sets.
            let nonce = load_or_create_nonce(&cli.nonce_file)?;
            let signer = SwarmSigner::from_hex_with_nonce(
                &key,
                &format!("0x{}", hex::encode(nonce)),
                cli.network_id,
            )?;

            // Pusher mode: stamp locally and push pre-signed frames over
            // HTTP to a relay (or several, sharded). No transport/peerlist
            // here — the pusher owns the session pool. Handles raw,
            // single-file manifest, and collection/tar uploads.
            if !pusher.is_empty() {
                let is_tar = file
                    .extension()
                    .and_then(|s| s.to_str())
                    .map(|s| s.eq_ignore_ascii_case("tar"))
                    .unwrap_or(false);
                let is_collection = collection || (is_tar && !raw);
                let upload_started = std::time::Instant::now();
                // Windowed streaming: split + manifest once, then stamp a
                // window at a time as the scheduler drains it. Peak memory
                // is one window of frames instead of the whole file — the
                // browser has worked this way since the streamer landed;
                // the native path used to stamp everything up front and
                // would blow up on large files.
                let (streamer, total_bytes, kind): (_, usize, &str) = if is_collection {
                    let bytes = std::fs::read(&file)?;
                    let files = read_tar_files(&bytes)?;
                    if files.is_empty() {
                        return Err("tar archive contains no regular files".into());
                    }
                    let total: usize = files.iter().map(|f| f.data.len()).sum();
                    let index_doc = index_document
                        .as_deref()
                        .map(|s| if s.is_empty() { None } else { Some(s) })
                        .unwrap_or(Some("index.html"));
                    let s = hoverfly::client::UploadStreamer::new_collection(
                        &signer,
                        &batch,
                        depth,
                        immutable,
                        &files,
                        index_doc,
                        error_document.as_deref(),
                        redundancy,
                    )?;
                    (s, total, "collection")
                } else if raw {
                    let data = std::fs::read(&file)?;
                    let total = data.len();
                    let s = hoverfly::client::UploadStreamer::new_raw(
                        &signer, &batch, depth, immutable, &data, redundancy,
                    )?;
                    (s, total, "raw")
                } else {
                    let data = std::fs::read(&file)?;
                    let total = data.len();
                    let path = manifest_path.clone().unwrap_or_else(|| {
                        file.file_name()
                            .and_then(|s| s.to_str())
                            .map(str::to_string)
                            .unwrap_or_else(|| "file".to_string())
                    });
                    let ct = content_type.clone().or_else(|| guess_content_type(&path));
                    let s = hoverfly::client::UploadStreamer::new_file(
                        &signer,
                        &batch,
                        depth,
                        immutable,
                        &data,
                        &path,
                        ct.as_deref(),
                        redundancy,
                    )?;
                    (s, total, "manifest")
                };
                let n_chunks = streamer.total_chunks();
                let progress = make_progress_bar();
                // Metered lanes: pay only when the user has explicitly given
                // a chequebook. Without one we push exactly as before and a
                // metered lane simply meters us in soft mode — nothing here
                // deploys or funds anything on its own.
                let pay_cfg = match cli.chequebook.as_ref() {
                    Some(cb_hex) => {
                        let cb =
                            parse_address_hex(cb_hex).map_err(|e| format!("--chequebook: {e}"))?;
                        let pins = parse_lane_pins(&cli.lane_pin)?;
                        // The relay checks funding against `liquidBalanceFor`
                        // at accept time; we check total issuance against the
                        // total liquid before signing, so we never hand over a
                        // cheque that cannot be cashed. Read with ZERO
                        // beneficiary: `liquidBalanceFor(0x0)` is the total
                        // liquid (no hard deposit for zero), i.e. the global
                        // ceiling across all lanes — not any lane's figure.
                        // `issuer` is beneficiary-independent, so this also
                        // fail-fasts a chequebook/sign-key mismatch that would
                        // otherwise surface mid-upload as 403/400 after
                        // stamping.
                        let (balance_plur, issuer_ok) =
                            match hoverfly::batch::read_chequebook_state(
                                &rpc_url,
                                alloy_primitives::Address::from(cb),
                                alloy_primitives::Address::ZERO,
                            )
                            .await
                            {
                                Ok(st) => {
                                    let issuer: [u8; 20] = st.issuer.into_array();
                                    if issuer != *signer.eth_address() {
                                        return Err(format!(
                                        "--chequebook issuer 0x{} != signing key 0x{}: only the issuer can pay (relay enforces issuer==account)",
                                        hex::encode(issuer),
                                        hex::encode(signer.eth_address())
                                    )
                                    .into());
                                    }
                                    eprintln!(
                                        "metered: chequebook=0x{} issuer=0x{} total_liquid={} PLUR chain={}",
                                        hex::encode(cb),
                                        hex::encode(issuer),
                                        st.liquid_for_us,
                                        cli.chequebook_chain_id,
                                    );
                                    (u128::try_from(st.liquid_for_us).unwrap_or(u128::MAX), true)
                                }
                                Err(e) => {
                                    // Soft-fail: an RPC outage must not abort an
                                    // upload whose lanes are all open/soft and
                                    // would serve unpaid. Per-lane relay checks
                                    // still enforce funding at accept time.
                                    eprintln!(
                                        "metered: chequebook state unreadable ({e}); continuing with no global balance pre-check"
                                    );
                                    (u128::MAX, false)
                                }
                            };
                        let _ = issuer_ok;
                        let store = hoverfly::cheques::ChequeStore::load_or_create(
                            &cli.cheques_file,
                            cb,
                        )
                        .map_err(|e| format!("loading {}: {e}", cli.cheques_file.display()))?;
                        // `batch` is the hex string the user passed; the
                        // challenge binds the raw 32 bytes.
                        let batch_raw = hex::decode(batch.trim_start_matches("0x"))
                            .map_err(|e| format!("--batch: {e}"))?;
                        let batch_id: [u8; 32] = batch_raw
                            .as_slice()
                            .try_into()
                            .map_err(|_| "--batch must be 32 bytes".to_string())?;
                        Some(hoverfly::payer::PaymentConfig {
                            signer: signer.clone(),
                            batch: batch_id,
                            chequebook: cb,
                            chain_id: cli.chequebook_chain_id,
                            cheques: std::sync::Arc::new(std::sync::Mutex::new(store)),
                            balance_plur,
                            pins,
                        })
                    }
                    None => None,
                };
                let root = hoverfly::client::push_stream_via_pushers_paid(
                    &pusher,
                    streamer,
                    progress.as_ref(),
                    pay_cfg.as_ref(),
                )
                .await?;
                drop(progress);
                let elapsed = upload_started.elapsed();
                let root_hex = hex::encode(root.as_bytes());
                println!(
                    "uploaded {} bytes ({} chunks) via {} pusher lane(s) — {} root: {}",
                    total_bytes,
                    n_chunks,
                    pusher.len(),
                    kind,
                    root_hex,
                );
                if let Some(c) = root_hex_to_cid(&root_hex) {
                    println!("bzz.limo:   https://bzz.limo/bzz/{root_hex}/");
                    println!("subdomain:  https://{c}.bzz.limo/");
                }
                print_upload_throughput(total_bytes, elapsed);
                return Ok(());
            }

            // Attach SWAP if configured. We don't validate that the
            // signer's Ethereum address matches the chequebook's
            // on-chain `issuer()` — that requires an RPC call we
            // intentionally don't make (see PERFORMANCE.md SWAP scope).
            // If they don't match, every cheque bee receives will fail
            // `chequestore.go:160 issuer != expectedIssuer` and reset
            // the swap substream; you'll see this in the
            // `cheque_failed` diag counter.
            // Always attach a default status snapshot. Bee opens
            // `/swarm/status/1.1.3/status` over our outbound
            // connections via its `pkg/salud` worker; if we don't
            // respond, bee marks us Unhealthy and we get
            // preferentially disconnected via the kademlia bin-prune
            // path (`pkg/topology/kademlia/kademlia.go:700-704`).
            // The default snapshot uses best-effort plausible values
            // for the percentile-gated fields (see
            // `protocols::status::StatusSnapshot::default`).
            let status_snapshot = hoverfly::protocols::status::StatusSnapshot::default();
            let transport = match swap_cfg.clone() {
                Some(sc) => Transport::new(signer.clone(), cfg)
                    .with_swap(sc)
                    .with_status_snapshot(status_snapshot),
                None => Transport::new(signer.clone(), cfg).with_status_snapshot(status_snapshot),
            };
            let mut peers = PeerStore::load_or_create(&peerlist);
            if peers.is_empty() {
                return Err(format!("peerlist {} is empty", peerlist.display()).into());
            }

            // Auto-detect tar by extension if the user didn't pass --raw.
            let is_tar = file
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("tar"))
                .unwrap_or(false);
            if (collection || (is_tar && !raw)) && !raw {
                let bytes = std::fs::read(&file)?;
                let files = read_tar_files(&bytes)?;
                if files.is_empty() {
                    return Err("tar archive contains no regular files".into());
                }
                let n_files = files.len();
                let total: usize = files.iter().map(|f| f.data.len()).sum();
                // Default the website index to `index.html`. An empty
                // string explicitly opts out (no root entry written).
                let index_doc = index_document
                    .as_deref()
                    .map(|s| if s.is_empty() { None } else { Some(s) })
                    .unwrap_or(Some("index.html"));
                let progress = make_progress_bar();
                let root = upload_collection(
                    &transport,
                    &peers,
                    &signer,
                    &batch,
                    depth,
                    immutable,
                    files,
                    index_doc,
                    error_document.as_deref(),
                    redundancy,
                    max_retries,
                    concurrency,
                    progress.as_ref(),
                )
                .await?;
                drop(progress);
                let root_hex = hex::encode(root.as_bytes());
                println!(
                    "uploaded {} files ({} bytes) — manifest root: {}",
                    n_files, total, root_hex,
                );
                if let Some(c) = root_hex_to_cid(&root_hex) {
                    println!("bzz.limo:   https://bzz.limo/bzz/{root_hex}/");
                    println!("subdomain:  https://{c}.bzz.limo/");
                }
                println!("retrieve a file with: hoverfly fetch {root_hex} --path <name> -o <out>");
                println!("list contents with: hoverfly fetch {root_hex} --list");
                hoverfly::peers::apply_log(&mut peers, transport.reachability_log());
                let _ = peers.save(&peerlist);
                print_session_retire_diag();
                return Ok(());
            }

            let data = std::fs::read(&file)?;
            // Wall-clock for "real upload time" — covers stamp +
            // dispatch + wait-for-final-receipt. Reported alongside
            // throughput so the user doesn't need to wrap with
            // `time`. Captured here (not inside the library) so we
            // don't need to thread a return-time through every
            // `upload_*` signature.
            let upload_started = std::time::Instant::now();
            if raw {
                let progress = make_progress_bar();
                let root = upload_bytes_ex(
                    &transport,
                    &peers,
                    &signer,
                    &batch,
                    depth,
                    immutable,
                    &data,
                    redundancy,
                    max_retries,
                    concurrency,
                    progress.as_ref(),
                )
                .await?;
                drop(progress);
                let elapsed = upload_started.elapsed();
                let root_hex = hex::encode(root.as_bytes());
                println!("uploaded {} bytes — root (raw): {}", data.len(), root_hex);
                if let Some(c) = root_hex_to_cid(&root_hex) {
                    println!("cid: {c}");
                }
                print_upload_throughput(data.len(), elapsed);
            } else {
                let path = manifest_path.unwrap_or_else(|| {
                    file.file_name()
                        .and_then(|s| s.to_str())
                        .map(str::to_string)
                        .unwrap_or_else(|| "file".to_string())
                });
                let ct = content_type.or_else(|| guess_content_type(&path));
                let progress = make_progress_bar();
                let root = upload_file_with_manifest_ex(
                    &transport,
                    &peers,
                    &signer,
                    &batch,
                    depth,
                    immutable,
                    &data,
                    &path,
                    ct.as_deref(),
                    redundancy,
                    max_retries,
                    concurrency,
                    progress.as_ref(),
                )
                .await?;
                drop(progress);
                let elapsed = upload_started.elapsed();
                let display_ct = ct.as_deref().unwrap_or("-");
                let root_hex = hex::encode(root.as_bytes());
                println!(
                    "uploaded {} bytes ({}) — manifest root: {}",
                    data.len(),
                    display_ct,
                    root_hex,
                );
                if let Some(c) = root_hex_to_cid(&root_hex) {
                    println!("bzz.limo:   https://bzz.limo/bzz/{root_hex}/{path}");
                    println!("subdomain:  https://{c}.bzz.limo/{path}");
                }
                println!("retrieve with: hoverfly fetch {root_hex} --path {path} -o {path}");
                print_upload_throughput(data.len(), elapsed);
            }

            hoverfly::peers::apply_log(&mut peers, transport.reachability_log());
            let _ = peers.save(&peerlist);
            // Persist cheques.json so the next run's cumulative payouts
            // stay strictly increasing (bee rejects otherwise — see
            // `cheques.rs` module docs).
            if let Some(sc) = transport.swap() {
                if let Err(e) = sc.store.lock().await.save() {
                    eprintln!("warning: cheques.json save failed: {e}");
                }
            }
            print_session_retire_diag();
        }

        Commands::Bmt {
            file,
            manifest_path,
            content_type,
            collection,
            index_document,
            error_document,
            redundancy,
        } => {
            let data = std::fs::read(&file)?;

            // Auto-detect tar by extension, mirroring `upload`'s logic so
            // `bmt <f>.tar` reports the same root `upload <f>.tar` produces.
            let is_tar = file
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("tar"))
                .unwrap_or(false);

            if collection || is_tar {
                let files = read_tar_files(&data)?;
                if files.is_empty() {
                    return Err("tar archive contains no regular files".into());
                }
                let n_files = files.len();
                let total: usize = files.iter().map(|f| f.data.len()).sum();
                // Same index-document defaulting as the upload collection
                // path: default to `index.html`, empty string opts out.
                let index_doc = index_document
                    .as_deref()
                    .map(|s| if s.is_empty() { None } else { Some(s) })
                    .unwrap_or(Some("index.html"));
                let (manifest_root, n_chunks) = hoverfly::client::collection_root(
                    &files,
                    index_doc,
                    error_document.as_deref(),
                    redundancy,
                )?;
                let root_hex = hex::encode(manifest_root.as_bytes());
                println!(
                    "collection: {} files, {} bytes, {} unique chunks",
                    n_files, total, n_chunks
                );
                println!("manifest root (upload <tar>): {root_hex}");
                if let Some(c) = root_hex_to_cid(&root_hex) {
                    println!("  cid: {c}");
                }
                return Ok(());
            }

            // Bare content root — identical to `upload --raw`.
            let (file_root, n_chunks) = hoverfly::client::bmt_root(&data, redundancy)?;
            let file_root_hex = hex::encode(file_root.as_bytes());

            // Manifest root — what the default (non-raw) `upload` yields.
            // Mirror the upload path's path/content-type defaulting so the
            // two agree when the same flags are passed to `upload`.
            let path = manifest_path.unwrap_or_else(|| {
                file.file_name()
                    .and_then(|s| s.to_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| "file".to_string())
            });
            let ct = content_type.or_else(|| guess_content_type(&path));
            let (manifest_root, _manifest_chunks) =
                hoverfly::manifest::build_single_entry_manifest(&path, file_root, ct.as_deref())
                    .map_err(|e| format!("building manifest: {e}"))?;
            let manifest_root_hex = hex::encode(manifest_root.as_bytes());

            println!("file: {} bytes, {} chunks", data.len(), n_chunks);
            println!("file BMT root (upload --raw):  {file_root_hex}");
            if let Some(c) = root_hex_to_cid(&file_root_hex) {
                println!("  cid: {c}");
            }
            let display_ct = ct.as_deref().unwrap_or("-");
            println!("manifest root (upload, path={path} [{display_ct}]): {manifest_root_hex}");
            if let Some(c) = root_hex_to_cid(&manifest_root_hex) {
                println!("  cid: {c}");
            }
        }

        #[cfg(feature = "pusher")]
        Commands::Pusher {
            listen,
            peerlist,
            probe,
            rpc_url,
            meter,
            origin,
            beneficiary,
            chequebook_chain,
            state_dir,
            price_plur_per_kib,
            min_cheque_plur,
            settle_every_plur,
            max_outstanding_plur,
            credit_ratio,
            meter_hard,
        } => {
            // Premined overlay nonce. On ephemeral-FS hosts (Render,
            // Lambda) there is no persistent `--nonce-file`, so a random
            // overlay would be minted every boot — landing us in bee's
            // already-full bin 0 and getting oversaturation-dropped
            // (PERFORMANCE.md "Vanity overlay"). HOVERFLY_OVERLAY_NONCE
            // (0x-hex, 32 bytes) pins a premined vanity nonce from the
            // environment; falls back to the nonce-file otherwise.
            let nonce = match std::env::var("HOVERFLY_OVERLAY_NONCE") {
                Ok(h) if !h.trim().is_empty() => {
                    let raw = h.trim().trim_start_matches("0x").trim_start_matches("0X");
                    let b = hex::decode(raw)
                        .map_err(|e| format!("HOVERFLY_OVERLAY_NONCE: bad hex: {e}"))?;
                    if b.len() != 32 {
                        return Err(format!(
                            "HOVERFLY_OVERLAY_NONCE: expected 32 bytes, got {}",
                            b.len()
                        )
                        .into());
                    }
                    let mut n = [0u8; 32];
                    n.copy_from_slice(&b);
                    n
                }
                _ => load_or_create_nonce(&cli.nonce_file)?,
            };
            let node_identity = std::env::var("HOVERFLY_PUSHER_IDENTITY")
                .ok()
                .filter(|s| !s.trim().is_empty());
            // Metered mode is all-or-nothing: every precondition is checked
            // here and in `build_metered`, and a failure refuses to start
            // rather than serving a half-configured meter that a paying
            // client would discover the hard way.
            // Env fallbacks so a deployed relay can be switched to metered
            // without changing its start command — the same pattern
            // HOVERFLY_PUSH_POOL and HOVERFLY_PUSHER_IDENTITY already use,
            // and the only lever available on hosts where the command line
            // is fixed by the platform.
            let envs = |k: &str| std::env::var(k).ok().filter(|s| !s.trim().is_empty());
            // Truthy parsing: `1`/`true`/`yes`/`on` enable; `0`/`false`/`no`/
            // `off`/empty never do. The old `v != "0"` treated
            // `HOVERFLY_METER=false` as *enabled* — a boolean footgun on a
            // money switch.
            let truthy = |v: &str| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            };
            let meter = meter || envs("HOVERFLY_METER").is_some_and(|v| truthy(&v));
            let meter_hard = meter_hard || envs("HOVERFLY_METER_HARD").is_some_and(|v| truthy(&v));
            let split_origins = |v: String| -> Vec<String> {
                v.split(',')
                    .map(|s| s.trim().trim_end_matches('/').to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            };
            let origin = if origin.is_empty() {
                envs("HOVERFLY_METER_ORIGIN")
                    .map(split_origins)
                    .unwrap_or_default()
            } else {
                // CLI repeated `--origin a --origin b` is already split by
                // clap; a single `--origin a,b` is one hostname that never
                // matches — split it too so CLI and env agree.
                origin.into_iter().flat_map(|o| split_origins(o)).collect()
            };
            let beneficiary = beneficiary.or_else(|| envs("HOVERFLY_METER_BENEFICIARY"));
            let state_dir = state_dir.or_else(|| envs("HOVERFLY_METER_STATE_DIR").map(Into::into));
            let parse_env_plur = |k: &str| -> Result<Option<u128>, String> {
                match envs(k) {
                    Some(v) => v.parse().map(Some).map_err(|e| format!("{k}: {e}")),
                    None => Ok(None),
                }
            };
            let price_plur_per_kib =
                price_plur_per_kib.or(parse_env_plur("HOVERFLY_METER_PRICE_PLUR_PER_KIB")?);
            let min_cheque_plur =
                min_cheque_plur.or(parse_env_plur("HOVERFLY_METER_MIN_CHEQUE_PLUR")?);
            let settle_every_plur =
                settle_every_plur.or(parse_env_plur("HOVERFLY_METER_SETTLE_EVERY_PLUR")?);
            let max_outstanding_plur =
                max_outstanding_plur.or(parse_env_plur("HOVERFLY_METER_MAX_OUTSTANDING_PLUR")?);
            let credit_ratio = credit_ratio.or(parse_env_plur("HOVERFLY_METER_CREDIT_RATIO")?);
            let meter_opts = if meter {
                let mut params = hoverfly::meter::Params::default();
                if let Some(v) = price_plur_per_kib {
                    params.price_plur_per_kib = v;
                }
                if let Some(v) = min_cheque_plur {
                    params.min_cheque_plur = v;
                }
                if let Some(v) = settle_every_plur {
                    params.settle_every_plur = v;
                }
                if let Some(v) = max_outstanding_plur {
                    params.max_outstanding_plur = v;
                }
                if let Some(v) = credit_ratio {
                    params.credit_ratio = v;
                }
                let beneficiary = beneficiary
                    .as_deref()
                    .ok_or("--meter requires --beneficiary")?;
                let raw = hex::decode(beneficiary.trim_start_matches("0x"))
                    .map_err(|e| format!("--beneficiary: {e}"))?;
                if raw.len() != 20 {
                    return Err("--beneficiary must be a 20-byte address".into());
                }
                let mut b = [0u8; 20];
                b.copy_from_slice(&raw);
                Some(hoverfly::pusher::MeterOpts {
                    origins: origin,
                    beneficiary: b,
                    chain_id: chequebook_chain,
                    params,
                    state_dir: state_dir
                        .ok_or("--meter requires --state-dir (durable state is mandatory)")?,
                    hard_mode: meter_hard,
                })
            } else {
                None
            };
            hoverfly::pusher::run(hoverfly::pusher::PusherOpts {
                listen,
                peerlist,
                probe_enabled: probe,
                nonce,
                network_id: cli.network_id,
                rpc_url,
                node_identity,
                transport: cfg,
                meter: meter_opts,
            })
            .await?;
        }

        #[cfg(unix)]
        Commands::Daemon {
            socket,
            peerlist,
            pool_size,
            listen,
            identity,
            advertise,
            discover_rounds,
            bootnode,
        } => {
            // Install a Ctrl-C handler that sends a shutdown request to
            // ourselves via the socket, triggering graceful peerlist save.
            //
            // A SECOND Ctrl-C force-exits. tokio's handler replaces the
            // default SIGINT disposition for the process lifetime, so
            // without this a wedged graceful path (e.g. the peerlist
            // persist waiting on a lock) made the daemon unkillable from
            // the terminal — every further ^C was silently swallowed.
            let sock_path = socket.clone();
            tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    eprintln!("shutting down (Ctrl-C again to force-quit)…");
                    if hoverfly::daemon::call(&sock_path, &hoverfly::daemon::Request::Shutdown)
                        .await
                        .is_err()
                    {
                        // Socket not bound yet / already gone — nothing to
                        // shut down gracefully; don't leave an unkillable
                        // process behind.
                        std::process::exit(130);
                    }
                    if tokio::signal::ctrl_c().await.is_ok() {
                        eprintln!("force quit");
                        std::process::exit(130);
                    }
                }
            });

            let listen_cfg = match listen {
                Some(s) => {
                    let ma: Multiaddr = s
                        .parse()
                        .map_err(|e| format!("invalid --listen multiaddr: {e}"))?;
                    let id_hex =
                        identity.ok_or("--identity <HEX> is required when --listen is set")?;
                    // Stable overlay nonce — same rationale as the
                    // upload command. The daemon especially benefits
                    // because it's the long-running configuration
                    // most likely to accumulate kademlia memberships
                    // over time.
                    let nonce = load_or_create_nonce(&cli.nonce_file)?;
                    let signer = SwarmSigner::from_hex_with_nonce(
                        &id_hex,
                        &format!("0x{}", hex::encode(nonce)),
                        cli.network_id,
                    )?;
                    let advertised = advertise
                        .map(|s| -> Result<Multiaddr, Box<dyn std::error::Error>> {
                            let base: Multiaddr = s
                                .parse()
                                .map_err(|e| format!("invalid --advertise multiaddr: {e}"))?;
                            let already_has_p2p = base
                                .iter()
                                .any(|p| matches!(p, libp2p::multiaddr::Protocol::P2p(_)));
                            if already_has_p2p {
                                Ok(base)
                            } else {
                                let peer_id = hoverfly::inbound::peer_id_from_identity(&signer);
                                Ok(base.with(libp2p::multiaddr::Protocol::P2p(peer_id)))
                            }
                        })
                        .transpose()?;
                    println!(
                        "daemon identity: overlay={} eth={}{}",
                        hex::encode(signer.overlay()),
                        hex::encode(signer.eth_address()),
                        advertised
                            .as_ref()
                            .map(|a| format!(" advertise={a}"))
                            .unwrap_or_default(),
                    );
                    Some(hoverfly::daemon::ListenConfig {
                        listen: ma,
                        advertise: advertised,
                        identity: signer,
                        // Status snapshot served on inbound salud
                        // probes. Defaults are best-effort plausible
                        // for mainnet May 2026. Future: expose CLI
                        // flags for the percentile-critical fields if
                        // the defaults start failing.
                        status_snapshot: hoverfly::protocols::status::StatusSnapshot::default(),
                    })
                }
                None => None,
            };

            // Always pass DoH + bootnodes through. Whether the pre-fill
            // bootnode discover actually runs is decided automatically
            // by `ensure_pool` based on peerlist warmth: a warm peerlist
            // (enough fresh known-good peers) skips it and fills the
            // pool straight from disk; a cold/stale one runs it so the
            // node self-heals. The background maintenance loop always
            // works off the peerlist.
            let discover = {
                let doh = Doh::with_url(&cli.doh_url);
                let bootnodes: Vec<Multiaddr> = bootnode
                    .iter()
                    .map(|s| {
                        s.parse::<Multiaddr>()
                            .map_err(|e| format!("invalid --bootnode multiaddr {s}: {e}"))
                    })
                    .collect::<Result<_, _>>()?;
                if bootnodes.is_empty() {
                    return Err("at least one --bootnode is required".into());
                }
                Some((doh, bootnodes))
            };
            hoverfly::daemon::run(
                socket,
                peerlist,
                cli.network_id,
                pool_size,
                Duration::from_secs(cli.dial_timeout),
                Duration::from_secs(cli.timeout),
                listen_cfg,
                swap_cfg.clone(),
                discover,
                Some(cli.nonce_file.clone()),
                discover_rounds,
            )
            .await?;
        }

        #[cfg(unix)]
        Commands::SavePeers { socket } => {
            let resp = hoverfly::daemon::call(&socket, &hoverfly::daemon::Request::SavePeers)
                .await
                .map_err(|e| format!("daemon call failed: {e}"))?;
            match resp {
                hoverfly::daemon::Response::Ok => {
                    println!("daemon saved peerlist");
                }
                hoverfly::daemon::Response::Err { message } => {
                    return Err(format!("daemon refused save: {message}").into());
                }
                other => {
                    return Err(format!("unexpected daemon response: {other:?}").into());
                }
            }
        }

        Commands::Status { socket } => {
            let resp = hoverfly::daemon::call(&socket, &hoverfly::daemon::Request::Status)
                .await
                .map_err(|e| format!("daemon call failed: {e}"))?;
            match resp {
                hoverfly::daemon::Response::Status {
                    pool_target,
                    pool_len,
                    live_count,
                    peerlist_total,
                    peerlist_dialable,
                    pool_initialized,
                } => {
                    if !pool_initialized {
                        println!(
                            "pool: not yet initialized (eager fill still running or no request served)"
                        );
                    } else {
                        println!(
                            "pool: {live_count} live / {pool_len} entries / {pool_target} target"
                        );
                        if live_count < pool_target {
                            println!(
                                "  note: {live_count} < {pool_target} target — pool is under target \
                                 (peers being pruned faster than refilled, or peerlist too thin)"
                            );
                        }
                    }
                    println!("peerlist: {peerlist_dialable} dialable / {peerlist_total} total");
                }
                hoverfly::daemon::Response::Err { message } => {
                    return Err(format!("daemon error: {message}").into());
                }
                other => {
                    return Err(format!("unexpected daemon response: {other:?}").into());
                }
            }
        }

        Commands::VanityOverlay {
            key,
            target_overlay,
            peerlist,
            target_po,
            min_coverage,
            output,
            max_attempts,
            network_id,
        } => {
            use alloy_signer_local::PrivateKeySigner;
            use hoverfly::signer::derive_overlay;
            use hoverfly::transport::proximity;

            // Derive our eth_address from the key — this is the input
            // half of the overlay hash that's fixed by our identity.
            let key_bytes = hex::decode(key.trim_start_matches("0x"))?;
            if key_bytes.len() != 32 {
                return Err(format!("key must be 32 bytes hex, got {}", key_bytes.len()).into());
            }
            let signing_key = PrivateKeySigner::from_slice(&key_bytes)?;
            let eth_address: [u8; 20] = signing_key.address().0.0;
            eprintln!(
                "vanity-overlay: eth_address={} network_id={} target_po={}",
                hex::encode(eth_address),
                network_id,
                target_po,
            );

            // Three distinct search modes:
            //
            // - **anchored / multi-target** (`--target-overlay` set
            //   one or more times): maximize the *minimum* PO across
            //   the listed targets. Anchors us near a specific
            //   peer or cluster of peers. Search cost: ~2^(k×n) for
            //   PO=k across n targets if the targets are far apart;
            //   much cheaper if the targets are themselves close.
            //
            // - **coverage** (no `--target-overlay`, uses peers.json):
            //   maximize the count of peers at PO≥target. Bounded
            //   by uniform expectation `N × 2^-target_po`; the best
            //   we can do is ~2-3× that.
            let parsed_targets: Vec<[u8; 32]> = target_overlay
                .iter()
                .map(|hex_addr| {
                    let bytes = hex::decode(hex_addr.trim_start_matches("0x"))?;
                    if bytes.len() != 32 {
                        return Err(format!(
                            "target-overlay must be 32 bytes hex, got {}",
                            bytes.len()
                        )
                        .into());
                    }
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&bytes);
                    Ok::<_, Box<dyn std::error::Error>>(a)
                })
                .collect::<Result<Vec<_>, _>>()?;

            let (targets, anchored_mode): (Vec<[u8; 32]>, bool) = if !parsed_targets.is_empty() {
                eprintln!(
                    "vanity-overlay: anchored mode, {} target(s):",
                    parsed_targets.len()
                );
                for (i, t) in parsed_targets.iter().enumerate() {
                    eprintln!("  [{}] {}", i, hex::encode(t));
                }
                (parsed_targets, true)
            } else {
                let store = hoverfly::PeerStore::load_or_create(&peerlist);
                let peers: Vec<[u8; 32]> = store
                    .iter()
                    .filter_map(|p| {
                        let bytes = hex::decode(p.overlay.trim_start_matches("0x")).ok()?;
                        if bytes.len() != 32 {
                            return None;
                        }
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&bytes);
                        Some(a)
                    })
                    .collect();
                if peers.len() < 50 {
                    eprintln!(
                        "warning: peers.json has only {} peers — run `discover` first for a meaningful coverage-mode search",
                        peers.len()
                    );
                }
                eprintln!(
                    "vanity-overlay: coverage mode against {} target peers (min-coverage={:.2})",
                    peers.len(),
                    min_coverage
                );
                (peers, false)
            };

            let min_matches = if anchored_mode {
                targets.len() // anchored: need all targets at PO≥target
            } else {
                ((targets.len() as f64) * min_coverage) as usize
            };

            // Brute-force search. nonce is just a counter we serialize
            // into 32 bytes; no need for randomness (the hash diffuses
            // any sequential pattern). Counter-based is also
            // reproducible — same key + same target list → same
            // winning nonce.
            let start = std::time::Instant::now();
            // For anchored mode, we score on the *minimum* PO across
            // the target set (we want EVERY anchor to be reachable in
            // its deep bin). For coverage mode, we score on the
            // count of peers ≥ target_po.
            let mut best_score = 0i64;
            let mut best_min_po = 0u8;
            let mut best_matches = 0usize;
            let mut best_nonce = [0u8; 32];
            let mut best_overlay = [0u8; 32];
            for attempt in 0..max_attempts {
                let mut nonce = [0u8; 32];
                nonce[..8].copy_from_slice(&attempt.to_le_bytes());
                nonce[8..16].copy_from_slice(&attempt.to_le_bytes());
                nonce[16..24].copy_from_slice(&attempt.to_le_bytes());
                nonce[24..32].copy_from_slice(&attempt.to_le_bytes());

                let overlay = derive_overlay(&eth_address, network_id, &nonce);
                let mut matches = 0usize;
                let mut min_po = u8::MAX;
                for p in &targets {
                    let po = proximity(&overlay, p);
                    if po >= target_po {
                        matches += 1;
                    }
                    if po < min_po {
                        min_po = po;
                    }
                }

                // Score: for anchored, sum of POs (rewards lifting
                // weak links). For coverage, just the match count.
                let score: i64 = if anchored_mode {
                    targets.iter().map(|p| proximity(&overlay, p) as i64).sum()
                } else {
                    matches as i64
                };

                if score > best_score {
                    best_score = score;
                    best_min_po = min_po;
                    best_matches = matches;
                    best_nonce = nonce;
                    best_overlay = overlay;
                    let elapsed = start.elapsed();
                    if anchored_mode {
                        // Print per-target PO for visibility.
                        let pos: Vec<u8> = targets.iter().map(|p| proximity(&overlay, p)).collect();
                        eprintln!(
                            "vanity-overlay: attempt {} ({:.0} k/s): overlay={} → POs={:?} min={}",
                            attempt + 1,
                            (attempt as f64 + 1.0) / elapsed.as_secs_f64() / 1000.0,
                            hex::encode(overlay),
                            pos,
                            min_po
                        );
                    } else {
                        eprintln!(
                            "vanity-overlay: attempt {} ({:.0} k/s): overlay={} → {} peers at PO≥{} ({:.1}%)",
                            attempt + 1,
                            (attempt as f64 + 1.0) / elapsed.as_secs_f64() / 1000.0,
                            hex::encode(overlay),
                            matches,
                            target_po,
                            100.0 * matches as f64 / targets.len() as f64
                        );
                    }
                    let done = if anchored_mode {
                        min_po >= target_po
                    } else {
                        matches >= min_matches
                    };
                    if done {
                        eprintln!(
                            "vanity-overlay: target reached after {} attempts in {:.1}s",
                            attempt + 1,
                            elapsed.as_secs_f64()
                        );
                        break;
                    }
                }
                if attempt > 0 && attempt % 1_000_000 == 0 {
                    eprintln!(
                        "vanity-overlay: progress {}/{} ({:.0} k/s) — best matches={} min_po={} score={}",
                        attempt,
                        max_attempts,
                        (attempt as f64) / start.elapsed().as_secs_f64() / 1000.0,
                        best_matches,
                        best_min_po,
                        best_score,
                    );
                }
            }

            if best_matches == 0 && best_min_po == 0 {
                return Err("vanity-overlay: no overlay matched — try lower --target-po".into());
            }
            std::fs::write(&output, hex::encode(best_nonce))?;
            if anchored_mode {
                let pos: Vec<u8> = targets
                    .iter()
                    .map(|p| proximity(&best_overlay, p))
                    .collect();
                println!(
                    "wrote {} → nonce={} overlay={} (POs={:?}, min={})",
                    output.display(),
                    hex::encode(best_nonce),
                    hex::encode(best_overlay),
                    pos,
                    best_min_po,
                );
            } else {
                println!(
                    "wrote {} → nonce={} overlay={} ({} peers at PO≥{} = {:.1}%)",
                    output.display(),
                    hex::encode(best_nonce),
                    hex::encode(best_overlay),
                    best_matches,
                    target_po,
                    100.0 * best_matches as f64 / targets.len() as f64
                );
            }
        }

        #[cfg(all(unix, feature = "pusher"))]
        Commands::Cashout {
            rpc_url,
            key,
            state_dir,
            recipient,
            min_amount,
            chequebook,
            dry_run,
            chain_id,
            timeout,
        } => {
            let signer = parse_signer(&key)?;
            let beneficiary = signer.address();
            let recipient: alloy_primitives::Address = match recipient {
                Some(r) => r.parse().map_err(|e| format!("--recipient: {e}"))?,
                None => beneficiary,
            };
            let floor = parse_bzz_amount(&min_amount)?;
            let only: Option<alloy_primitives::Address> = match chequebook {
                Some(c) => Some(c.parse().map_err(|e| format!("--chequebook: {e}"))?),
                None => None,
            };
            let ledger_path = state_dir.join("ledger.json");
            let ledger = hoverfly::ledger::Ledger::load_or_create(&ledger_path)
                .map_err(|e| format!("reading {}: {e}", ledger_path.display()))?;
            let held = ledger.held_cheques();
            println!(
                "beneficiary 0x{}  recipient 0x{}  ({} cheque(s) held)",
                hex::encode(beneficiary),
                hex::encode(recipient),
                held.len()
            );
            if held.is_empty() {
                println!("nothing to cash");
                return Ok(());
            }
            let mut cashed = 0usize;
            let mut skipped = 0usize;
            for (account, cb, cheque) in held {
                let cb_addr = alloy_primitives::Address::from(cb);
                if only.is_some_and(|o| o != cb_addr) {
                    continue;
                }
                let cumulative = alloy_primitives::U256::from(cheque.cumulative_plur);
                let q = hoverfly::batch::quote_cashout(
                    &rpc_url,
                    cb_addr,
                    alloy_primitives::Address::from(beneficiary),
                    cumulative,
                )
                .await?;
                println!();
                println!(
                    "chequebook 0x{}  (account 0x{})",
                    hex::encode(cb),
                    hex::encode(account)
                );
                println!(
                    "  cumulative   {cheque_cumulative}",
                    cheque_cumulative = cheque.cumulative_plur
                );
                println!("  unclaimed    {}", q.requested_plur);
                println!(
                    "  payable now  {}{}",
                    q.payable_plur,
                    if q.would_bounce {
                        "   <- chequebook cannot cover the claim"
                    } else {
                        ""
                    }
                );
                if q.already_bounced {
                    println!("  NOTE: this chequebook has bounced before");
                }
                if cheque.signature == [0u8; 65] {
                    println!("  SKIP: no stored signature (ledger predates signature persistence)");
                    skipped += 1;
                    continue;
                }
                if q.payable_plur < floor {
                    println!(
                        "  SKIP: below --min-amount ({min_amount} BZZ); gas would cost more than this collects"
                    );
                    skipped += 1;
                    continue;
                }
                if dry_run {
                    println!("  DRY RUN: would cash {}", q.payable_plur);
                    continue;
                }
                let tx = hoverfly::batch::cash_cheque(
                    &signer,
                    &rpc_url,
                    chain_id,
                    cb_addr,
                    recipient,
                    cumulative,
                    &cheque.signature,
                    std::time::Duration::from_secs(timeout),
                )
                .await?;
                println!("  CASHED  tx 0x{}", hex::encode(tx));
                cashed += 1;
            }
            println!();
            println!("{cashed} cashed, {skipped} skipped");
        }
        #[cfg(unix)]
        Commands::Chequebook { action } => match action {
            ChequebookAction::Deploy {
                rpc_url,
                key,
                chain_id,
                timeout,
            } => {
                let signer = parse_signer(&key)?;
                let issuer = signer.address();
                let factory =
                    hoverfly::batch::swap_factory_for_chain(chain_id).ok_or_else(|| {
                        format!(
                            "no vetted SimpleSwapFactory for chain {chain_id} — a factory address \
                         must never be guessed, since a fake one can return a forged issuer()"
                        )
                    })?;
                println!("deploying chequebook: issuer 0x{}", hex::encode(issuer));
                println!("  factory  0x{}", hex::encode(factory));
                let out = hoverfly::batch::deploy_chequebook(
                    &signer,
                    hoverfly::batch::DeployChequebookParams {
                        rpc_url,
                        chain_id,
                        factory,
                        issuer,
                        receipt_timeout: std::time::Duration::from_secs(timeout),
                    },
                )
                .await?;
                if out.already_deployed {
                    println!("  already deployed at 0x{}", hex::encode(out.address));
                } else {
                    println!("  tx       0x{}", hex::encode(out.tx));
                    println!("  deployed 0x{}", hex::encode(out.address));
                }
                println!();
                println!("Fund it before it can pay anything:");
                println!(
                    "  hoverfly chequebook fund --key <KEY> --chequebook 0x{} --amount 0.05",
                    hex::encode(out.address)
                );
            }
            ChequebookAction::Fund {
                rpc_url,
                key,
                chequebook,
                amount,
                chain_id,
                timeout,
            } => {
                let signer = parse_signer(&key)?;
                let cb: alloy_primitives::Address = chequebook
                    .parse()
                    .map_err(|e| format!("--chequebook: {e}"))?;
                let plur = parse_bzz_amount(&amount)?;
                // Gnosis only: there is no vetted Sepolia BZZ token const,
                // and funding via the wrong ERC-20 would transfer the wrong
                // token (or fail confusingly). Reject non-Gnosis here rather
                // than funding with the mainnet token address.
                if chain_id != 100 {
                    return Err(format!(
                        "chequebook fund supports Gnosis (chain 100) only; got chain {chain_id}"
                    )
                    .into());
                }
                let bzz: alloy_primitives::Address = hoverfly::batch::MAINNET_BZZ_TOKEN
                    .parse()
                    .map_err(|e| format!("bzz token: {e}"))?;
                println!(
                    "funding 0x{} with {amount} BZZ ({plur} PLUR)",
                    hex::encode(cb)
                );
                let tx = hoverfly::batch::fund_chequebook(
                    &signer,
                    &rpc_url,
                    chain_id,
                    bzz,
                    cb,
                    plur,
                    std::time::Duration::from_secs(timeout),
                )
                .await?;
                println!("  tx 0x{}", hex::encode(tx));
            }
            ChequebookAction::Status {
                rpc_url,
                chequebook,
                beneficiary,
            } => {
                let cb: alloy_primitives::Address = chequebook
                    .parse()
                    .map_err(|e| format!("--chequebook: {e}"))?;
                let ben: alloy_primitives::Address = match beneficiary {
                    Some(b) => b.parse().map_err(|e| format!("--beneficiary: {e}"))?,
                    None => alloy_primitives::Address::ZERO,
                };
                let st = hoverfly::batch::read_chequebook_state(&rpc_url, cb, ben).await?;
                println!("chequebook 0x{}", hex::encode(cb));
                println!("  issuer            0x{}", hex::encode(st.issuer));
                println!("  liquid for 0x{}  {}", hex::encode(ben), st.liquid_for_us);
                println!("  paid out to it    {}", st.paid_out_to_us);
                println!(
                    "  bounced           {}{}",
                    st.bounced,
                    if st.bounced {
                        "  <- a relay will refuse this chequebook"
                    } else {
                        ""
                    }
                );
            }
        },
        Commands::Batch { action } => match action {
            BatchAction::Create {
                rpc_url,
                key,
                size,
                duration,
                amount_per_chunk,
                depth,
                immutable,
                owner,
                postage_stamp,
                bzz_token,
                chain_id,
            } => {
                use alloy_signer_local::PrivateKeySigner;
                use hoverfly::batch::{
                    CreateBatchParams, MAINNET_BZZ_TOKEN, MAINNET_POSTAGE_STAMP,
                    amount_for_duration, create_batch, depth_for_size, parse_duration, parse_size,
                    read_last_price,
                };

                let signer: PrivateKeySigner = key
                    .strip_prefix("0x")
                    .unwrap_or(&key)
                    .parse()
                    .map_err(|e| format!("--key parse: {e}"))?;
                let signer_addr = signer.address();

                let postage_stamp_addr: alloy_primitives::Address = postage_stamp
                    .as_deref()
                    .unwrap_or(MAINNET_POSTAGE_STAMP)
                    .parse()
                    .map_err(|e| format!("--postage-stamp: {e}"))?;

                // Resolve depth + amount from either (--size, --duration)
                // or (--depth, --amount-per-chunk). Clap's `requires` rules
                // guarantee at least one of the pairs is fully present.
                let (resolved_depth, resolved_amount) = match (size, duration) {
                    (Some(sz), Some(dur)) => {
                        let size_bytes = parse_size(&sz)?;
                        let secs = parse_duration(&dur)?;
                        let d = depth_for_size(size_bytes).ok_or_else(|| {
                            format!(
                                "size '{sz}' exceeds the maximum tabulated effective volume \
                                 (depth=41 ≈ 8.93 PB). Pass --depth/--amount-per-chunk \
                                 explicitly if you really need this."
                            )
                        })?;
                        let last_price = read_last_price(&rpc_url, postage_stamp_addr).await?;
                        let amount = amount_for_duration(last_price, secs);
                        println!(
                            "resolved size={sz} duration={dur} (last_price={last_price} PLUR/chunk/block) → depth={d} amount={amount}"
                        );
                        (d, amount)
                    }
                    (None, None) => {
                        let d = depth
                            .ok_or("must specify either (--size --duration) or (--depth --amount-per-chunk)")?;
                        let amount = amount_per_chunk
                            .as_ref()
                            .ok_or("must specify --amount-per-chunk alongside --depth")?
                            .parse::<alloy_primitives::U256>()
                            .map_err(|e| format!("--amount-per-chunk: {e}"))?;
                        (d, amount)
                    }
                    _ => unreachable!("clap `requires` ensures --size+--duration come as a pair"),
                };

                let params = CreateBatchParams {
                    rpc_url,
                    owner: owner
                        .as_deref()
                        .map(|s| s.parse().map_err(|e| format!("--owner: {e}")))
                        .transpose()?
                        .unwrap_or(signer_addr),
                    postage_stamp: postage_stamp_addr,
                    bzz_token: bzz_token
                        .as_deref()
                        .unwrap_or(MAINNET_BZZ_TOKEN)
                        .parse()
                        .map_err(|e| format!("--bzz-token: {e}"))?,
                    initial_balance_per_chunk: resolved_amount,
                    depth: resolved_depth,
                    immutable,
                    chain_id,
                    receipt_timeout: std::time::Duration::from_secs(120),
                };

                println!(
                    "creating batch (owner={}, depth={}, amount/chunk={} PLUR, immutable={}) ...",
                    params.owner, params.depth, params.initial_balance_per_chunk, params.immutable
                );

                let info = create_batch(&signer, params).await?;

                println!("batch created:");
                println!("  batch_id:    0x{}", hex::encode(info.batch_id));
                println!("  owner:       {}", info.owner);
                println!("  depth:       {}", info.depth);
                println!("  bucket:      {}", info.bucket_depth);
                println!("  immutable:   {}", info.immutable);
                println!("  total_paid:  {} PLUR", info.total_amount);
                println!("  normalised:  {} PLUR", info.normalised_balance);
                if info.approve_tx != alloy_primitives::B256::ZERO {
                    println!("  approve_tx:  0x{}", hex::encode(info.approve_tx));
                }
                println!("  create_tx:   0x{}", hex::encode(info.create_tx));
            }
        },

        #[cfg(feature = "bridge")]
        Commands::Bridge {
            from_chain,
            from_token,
            amount,
            from_decimals,
            to,
            origin_rpc_url,
            gnosis_rpc_url,
            key,
            recipient,
            api_key,
            xdai_topup_threshold,
            xdai_topup_amount,
            bridge_timeout,
        } => {
            use hoverfly::bridge::{
                BridgeParams, BridgeTarget, RelayClient, TradeType, bridge, chain_id_from_name,
                resolve_token,
            };

            let origin_chain_id = chain_id_from_name(&from_chain)
                .ok_or_else(|| format!("--from-chain: unknown chain '{from_chain}'"))?;
            let target = BridgeTarget::parse(&to).map_err(|e| format!("{e}"))?;

            let signer: alloy_signer_local::PrivateKeySigner = key
                .trim_start_matches("0x")
                .parse()
                .map_err(|e| format!("--key: {e}"))?;
            let signer_addr = alloy_signer::Signer::address(&signer);

            let recipient = match recipient {
                Some(r) => {
                    let b = parse_address_hex(&r).map_err(|e| format!("--recipient: {e}"))?;
                    alloy_primitives::Address::from(b)
                }
                None => signer_addr,
            };

            // Resolve --from-token: a bare symbol (e.g. "USDC") is looked
            // up against Relay's chain token list for both address AND
            // decimals; a raw 0x address is used verbatim with
            // --from-decimals; omitted means the native gas token.
            let relay = RelayClient::new(api_key.clone());
            let token = resolve_token(
                &relay,
                origin_chain_id,
                from_token.as_deref(),
                from_decimals,
            )
            .await
            .map_err(|e| format!("--from-token: {e}"))?;

            // Convert whole-unit amounts to smallest-unit U256 via the
            // resolved decimals.
            let amount_units: f64 = amount
                .trim()
                .parse()
                .map_err(|e| format!("--amount: bad number '{amount}': {e}"))?;
            let amount_wire = whole_to_smallest_unit(amount_units, token.decimals)
                .ok_or_else(|| format!("--amount: '{amount}' out of range"))?;

            let to_wei_18 = |x: f64| -> u128 { (x * 1e18) as u128 };

            let params = BridgeParams {
                origin_chain_id,
                origin_currency: token.address,
                amount: amount_wire,
                target,
                recipient,
                origin_rpc_url,
                gnosis_rpc_url,
                trade_type: TradeType::ExactInput,
                api_key,
                xdai_topup_threshold_wei: to_wei_18(xdai_topup_threshold),
                xdai_topup_amount_wei: to_wei_18(xdai_topup_amount),
                timeout: Duration::from_secs(bridge_timeout),
            };

            println!(
                "bridging {} {} (decimals {}) on chain {} -> {} on Gnosis, recipient {} ...",
                amount,
                from_token.as_deref().unwrap_or("native"),
                token.decimals,
                origin_chain_id,
                to,
                recipient
            );
            println!("  (Relay is permissionless; this may take a few minutes per leg)");

            let outcome = bridge(&signer, params).await?;

            println!("bridge complete. recipient: {}", outcome.recipient);
            for leg in &outcome.legs {
                println!(
                    "  leg [{}]: ~{} {}",
                    leg.label, leg.output_formatted, leg.output_symbol
                );
                println!("    requestId: {}", leg.request_id);
                for (i, h) in leg.origin_tx_hashes.iter().enumerate() {
                    println!("    origin tx {}: 0x{}", i + 1, hex::encode(h));
                }
            }
            println!(
                "next: hoverfly batch create --rpc-url {} --key <KEY> --size <SIZE> --duration <DURATION>",
                "https://rpc.gnosischain.com"
            );
        }
    }

    Ok(())
}

/// Convert a whole-unit amount (e.g. `2.5` USDC) to its smallest-unit
/// integer representation given `decimals`. Returns `None` on negative or
/// non-finite input. Uses string-free f64 math; fine for the precision
/// the CLI needs (Relay re-quotes exact amounts anyway).
#[cfg(feature = "bridge")]
fn whole_to_smallest_unit(whole: f64, decimals: u8) -> Option<alloy_primitives::U256> {
    if !whole.is_finite() || whole < 0.0 {
        return None;
    }
    // Multiply in f64 then round; for the magnitudes the CLI handles
    // (< ~10^15 smallest units) this stays well within f64's 2^53 exact
    // integer range.
    let scaled = (whole * 10f64.powi(decimals as i32)).round();
    if !scaled.is_finite() || scaled < 0.0 {
        return None;
    }
    Some(alloy_primitives::U256::from(scaled as u128))
}

/// Parse a 32-byte hex private key into a signer.
#[cfg(unix)]
fn parse_signer(
    key: &str,
) -> Result<alloy_signer_local::PrivateKeySigner, Box<dyn std::error::Error>> {
    let raw = hex::decode(key.trim_start_matches("0x"))?;
    if raw.len() != 32 {
        return Err(format!("key must be 32 bytes hex, got {}", raw.len()).into());
    }
    Ok(alloy_signer_local::PrivateKeySigner::from_slice(&raw)?)
}

/// Decimal BZZ → PLUR. BZZ has **16** decimals, not 18: getting this wrong
/// by two orders of magnitude is the kind of mistake that silently deposits
/// 100× too little and makes every cheque bounce.
#[cfg(unix)]
fn parse_bzz_amount(s: &str) -> Result<alloy_primitives::U256, Box<dyn std::error::Error>> {
    const DECIMALS: usize = 16;
    let s = s.trim();
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    if frac.len() > DECIMALS {
        return Err(format!("BZZ has {DECIMALS} decimals; '{s}' has more").into());
    }
    if whole.is_empty() && frac.is_empty() {
        return Err("empty amount".into());
    }
    let mut digits = String::from(whole);
    digits.push_str(frac);
    digits.push_str(&"0".repeat(DECIMALS - frac.len()));
    if !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("'{s}' is not a decimal amount").into());
    }
    Ok(alloy_primitives::U256::from_str_radix(&digits, 10)?)
}

#[cfg(all(test, unix))]
mod chequebook_cli_tests {
    use super::*;

    /// BZZ has 16 decimals. An 18-decimal assumption would under-fund by
    /// 100×, and every cheque drawn on it would then fail the relay's
    /// funding check for no visible reason.
    #[test]
    fn bzz_amounts_use_sixteen_decimals() {
        let one = parse_bzz_amount("1").expect("1 BZZ");
        assert_eq!(one.to_string(), "10000000000000000");
        assert_eq!(
            parse_bzz_amount("0.05").expect("0.05").to_string(),
            "500000000000000"
        );
        assert_eq!(
            parse_bzz_amount("0.0001").expect("small").to_string(),
            "1000000000000"
        );
        assert_eq!(
            parse_bzz_amount("1.5").expect("1.5").to_string(),
            "15000000000000000"
        );
    }

    #[test]
    fn malformed_amounts_are_refused() {
        for bad in ["", ".", "abc", "1.2.3", "-1", "0.00000000000000001"] {
            assert!(parse_bzz_amount(bad).is_err(), "{bad} must be refused");
        }
    }
}
