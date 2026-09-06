//! WASM bindings — exposes a single `HoverflyClient` class to JavaScript.
//!
//! Keep the API symmetric with the CLI: `discover()`, `fetch()`, `upload()`,
//! all returning Promises. The class holds a `PeerStore` in memory across calls
//! and lets the caller import/export it as JSON.

#![cfg(target_arch = "wasm32")]

use core::time::Duration;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;

use futures_timer::Delay;
use js_sys::{Array, Reflect, Uint8Array};
use libp2p::Multiaddr;
use wasm_bindgen::prelude::*;

use crate::DEFAULT_DOH_URL;
use crate::client::{
    RetrievalCache, UploadFile, UploadStreamer, fetch_bytes_cached_ex,
    fetch_manifest_path_cached_meta, list_manifest_ex, upload_bytes_ex, upload_collection,
    upload_file_with_manifest_ex,
};
use crate::doh::Doh;
use crate::peers::PeerStore;
use crate::signer::SwarmSigner;
use crate::transport::{Transport, TransportConfig};

/// Per-chunk peer racing for browser fetches. This is the width of the race for
/// a SINGLE chunk — useful while cold (discover a fast forwarder), but wasteful
/// once warm: the first good forwarder answers quickly and the extra attempts
/// just consume substream slots on the single ws+yamux driver. So keep it
/// modest and let the joiner's chunks-in-flight (`joiner_concurrency`, ~24) be
/// the throughput lever — pumping many distinct chunks through the few warm
/// forwarders rather than redundantly racing each chunk against the whole pool.
/// (Earlier this was conflated with the joiner concurrency at 12, which capped
/// browser throughput around ~20 chunks/s.)
const FETCH_CONCURRENCY: usize = 4;

/// Default warm retrieval-session pool target the in-browser daemon keeps open
/// in the background (see [`HoverflyClient::start`]). This is the in-wasm
/// analogue of the native daemon's warm connection pool: rather than opening
/// retrieval sessions lazily on the first fetch (cold), the daemon proactively
/// dials browser-dialable (/ws[s]) forwarders and keeps them warm, so
/// `connectedPeerCount` is non-zero at idle and the first site load reuses live
/// sessions instead of dialing cold.
///
/// `0` (the default) means UNLIMITED — warm every reachable dialable peer. The
/// effective ceiling is then just how many of the (scarce, flaky) browser /ws
/// peers actually accept a connection; each is a live wss connection multiplexed
/// over the single ws+yamux driver. A positive value caps the pool at that many
/// sessions instead.
const DEFAULT_WARM_POOL: usize = 0;

/// Upload session-pool target for the browser pusher.
///
/// The native CLI defaults to 8 (`DEFAULT_UPLOAD_CONCURRENCY`) and the VPS
/// daemon runs 256+, but the browser is different in BOTH directions:
///
/// - `push_chunks_with_pool` now tops the pool up mid-upload (`maintain=true`
///   on the one-shot path): every `HOVERFLY_PUSH_TOPUP_SECS` (default 2 s — the
///   browser has no env, so it uses the default) it prunes dead entries and
///   re-dials fresh peers back to the opening size. Before that the pool opened
///   ONCE, and since `/wss` AutoTLS underlays rotate and sessions die fast, a
///   small pool (8) decayed to `eligible=0` partway through a multi-thousand-
///   chunk upload and the tail spun on retries. The top-up keeps the live set
///   near this target; the larger initial size still helps warm-start but no
///   longer has to survive the whole push on its own.
/// - But everything multiplexes over the single browser ws+yamux driver, and
///   browsers cap concurrent WS connections per host, so we can't go to 256
///   like the VPS. 48 is the empirical sweet spot: enough live forwarders to
///   keep `eligible > 0` for the whole upload without saturating the driver.
const UPLOAD_POOL: usize = 48;

/// How many maintenance ticks between background re-discovery rounds in the
/// browser daemon. Discovery is a one-shot path (throwaway swarm per peer — see
/// the loop in [`HoverflyClient::start`]), so running it every tick churns the
/// connection driver for little gain once the peer store is warm. At the default
/// 45s tick, `8` re-discovers roughly every 6 minutes — enough to track peer
/// churn without the per-tick swarm-rebuild flood. The warm session pool (the
/// connections retrieval reuses) is still topped up every tick.
const DISCOVER_EVERY_N: u64 = 8;

/// Human-readable label for a warm-pool target in logs: `usize::MAX` is the
/// unlimited sentinel, anything else is a concrete cap.
fn warm_pool_label(target: usize) -> String {
    if target == usize::MAX {
        "unlimited".to_string()
    } else {
        format!("target {target}")
    }
}

#[wasm_bindgen(start)]
pub fn _wasm_init() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    console_error_panic_hook::set_once();
    // Route `tracing` events to the browser console. The `tracing_wasm` layer
    //   - emits each event at its own console level (warn -> console.warn etc.)
    //     so retrieval `warn!`/`info!` are visible without enabling Verbose, and
    //   - keeps the `target` (e.g. `hoverfly::fetch`) so events are filterable.
    //
    // Compose it with a per-target `Targets` filter: libp2p is *very* chatty at
    // INFO — its swarm logs `local_peer_id = …` once per constructed swarm, and
    // we stand up a throwaway swarm PER DIAL, so a browser pool fill (dozens of
    // dials through the mostly-dead `/wss` candidate set) floods the console
    // with hundreds of identical INFO lines that bury hoverfly's own logs and
    // cost real console/serialization time. Pin libp2p (and other noisy
    // low-level crates) to WARN while keeping hoverfly + everything else at INFO.
    let mut builder = tracing_wasm::WASMLayerConfigBuilder::new();
    builder.set_report_logs_in_timings(false);
    let wasm_layer = tracing_wasm::WASMLayer::new(builder.build());
    // Apply the per-target filter at the registry level (a `Filtered`
    // subscriber layer), not on the WASMLayer directly — `tracing_wasm`'s
    // layer doesn't expose the per-layer `with_filter` combinator against this
    // tracing-subscriber version.
    let filter = tracing_subscriber::filter::Targets::new()
        .with_default(tracing::Level::INFO)
        .with_target("libp2p_swarm", tracing::Level::WARN)
        .with_target("libp2p", tracing::Level::WARN)
        .with_target("libp2p_gossipsub", tracing::Level::WARN)
        .with_target("multistream_select", tracing::Level::WARN)
        .with_target("yamux", tracing::Level::WARN);
    tracing_subscriber::registry()
        .with(filter)
        .with(wasm_layer)
        .init();
}

#[wasm_bindgen]
pub struct HoverflyClient {
    /// libp2p transport, shared (`Arc`) with the background daemon loop so
    /// foreground fetches and background discovery dial through the same
    /// identity + per-peer dial cooldown.
    transport: Arc<Transport>,
    /// Candidate peer list behind shared interior mutability. The background
    /// daemon loop (see [`HoverflyClient::start`]) merges freshly-discovered
    /// peers in; every fetch snapshots it under a short borrow — never held
    /// across an `.await` — and retrieves against that snapshot. `Rc<RefCell>`
    /// is sound because wasm is single-threaded.
    peers: Rc<RefCell<PeerStore>>,
    doh: Arc<Doh>,
    signer_key: Option<String>,
    network_id: u64,
    /// Shared session cache + peer scoreboard. A long-lived (daemon-style)
    /// client reuses this across every fetch so warm sessions and learned
    /// peer scores carry over — the first request pays discovery, later ones
    /// reuse live forwarders.
    cache: RetrievalCache,
    /// `true` once the background daemon loop has been spawned. Guards
    /// against spawning more than one loop on repeated `start()` calls.
    running: Rc<RefCell<bool>>,
    /// Count of foreground fetches currently in flight. The background
    /// discovery loop skips its round while this is non-zero: on the browser's
    /// single ws+yamux connection driver, a discovery round's dial/substream
    /// churn resets in-flight retrieval substreams (observed as
    /// `retrieval: unexpected end of file` / `ConnectionReset: Canceled`),
    /// stalling exactly the cold-load burst (e.g. a 40-module site) it collides
    /// with. Pausing discovery while fetches run keeps the connections quiet for
    /// retrieval; discovery resumes once the burst drains. `Rc<Cell>` is sound
    /// on single-threaded wasm.
    inflight_fetches: Rc<Cell<usize>>,
    /// Live upload progress `(pushed, total)` chunk counts, updated by the
    /// push loop's progress callback. `Send + Sync` atomics (not `Rc<Cell>`)
    /// because the callback the pusher invokes is a `ProgressFn`
    /// (`Fn + Send + Sync`). The worker polls [`Self::upload_progress`] on a
    /// timer during an upload and forwards it to the UI — turning the fake
    /// staged bar into a real per-chunk one. Reset at the start of each upload.
    upload_done: Arc<std::sync::atomic::AtomicUsize>,
    upload_total: Arc<std::sync::atomic::AtomicUsize>,
}

/// RAII guard: increments the shared in-flight fetch counter on creation and
/// decrements on drop, so the background discovery loop can tell when any
/// foreground fetch is active (and pause). Drop runs on every exit path —
/// success, error, or early return — so the count can't leak.
struct FetchGuard(Rc<Cell<usize>>);
impl FetchGuard {
    fn new(c: &Rc<Cell<usize>>) -> Self {
        c.set(c.get() + 1);
        FetchGuard(c.clone())
    }
}
impl Drop for FetchGuard {
    fn drop(&mut self) {
        self.0.set(self.0.get().saturating_sub(1));
    }
}

#[wasm_bindgen]
impl HoverflyClient {
    /// Construct a client. `private_key_hex` is optional — provide it only for upload.
    /// `network_id` defaults to `1` (mainnet). `doh_url` defaults to Cloudflare.
    ///
    /// `nonce_hex` is the optional 32-byte overlay nonce. The Swarm overlay is
    /// `keccak256(eth_addr || network_id || nonce)`, so to keep a *stable*
    /// overlay across restarts a caller must persist and replay BOTH the key and
    /// the nonce — persisting the key alone still yields a fresh random overlay
    /// each launch (see `SwarmSigner::from_hex`), which defeats peers' kademlia
    /// memory of this node. A long-lived browser daemon passes both to reuse one
    /// identity across page loads.
    #[wasm_bindgen(constructor)]
    pub fn new(
        private_key_hex: Option<String>,
        network_id: Option<u64>,
        doh_url: Option<String>,
        timeout_secs: Option<u32>,
        nonce_hex: Option<String>,
    ) -> Result<HoverflyClient, JsError> {
        let network_id = network_id.unwrap_or(1);
        let doh_url = doh_url.unwrap_or_else(|| DEFAULT_DOH_URL.to_string());
        let timeout = Duration::from_secs(timeout_secs.unwrap_or(30) as u64);

        // key + nonce -> stable overlay (persisted, reusable daemon identity)
        // key only    -> stable eth identity, fresh random overlay nonce
        // neither      -> fully ephemeral (random key + nonce)
        let signer = match (&private_key_hex, &nonce_hex) {
            (Some(key), Some(nonce)) => {
                SwarmSigner::from_hex_with_nonce(key, nonce, network_id).map_err(into_js_err)?
            }
            (Some(key), None) => SwarmSigner::from_hex(key, network_id).map_err(into_js_err)?,
            (None, _) => SwarmSigner::random(network_id),
        };
        let cfg = TransportConfig {
            timeout,
            idle_timeout: Duration::from_secs(600),
            // Browsers need a far larger dial budget than native: a single dial
            // covers DNS + the browser's own TLS + WS upgrade to the AutoTLS
            // `wss://<sni>.libp2p.direct` endpoint, then Noise + Yamux + identify
            // + bee's handshake/pricing dance — all over a ~100ms+ RTT WebSocket.
            // The native default (3s, tuned for raw TCP) expires mid-chain in the
            // browser and surfaces as `peer failed: timeout` for every peer even
            // though the endpoint is reachable and its cert is valid.
            dial_timeout: Duration::from_secs(20),
            network_id,
            advertise: None,
            max_concurrent_substream_upgrades:
                crate::protocols::stream_pool::DEFAULT_MAX_CONCURRENT_OUTBOUND_UPGRADES,
        };

        Ok(Self {
            transport: Arc::new(Transport::new(signer, cfg)),
            peers: Rc::new(RefCell::new(PeerStore::new())),
            doh: Arc::new(Doh::with_url(doh_url)),
            signer_key: private_key_hex,
            network_id,
            cache: RetrievalCache::new(),
            running: Rc::new(RefCell::new(false)),
            inflight_fetches: Rc::new(Cell::new(0)),
            upload_done: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            upload_total: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// Replace the in-memory peer store from a peers.json string.
    #[wasm_bindgen(js_name = "loadPeers")]
    pub fn load_peers(&self, peers_json: &str) -> Result<(), JsError> {
        let store: PeerStore = serde_json::from_str(peers_json).map_err(into_js_err)?;
        *self.peers.borrow_mut() = store;
        Ok(())
    }

    /// Merge a peers.json string INTO the existing in-memory store (rather than
    /// replacing it like [`Self::load_peers`]). Each peer is `upsert`ed, so
    /// underlays are unioned and reachability fields keep the newer observation.
    ///
    /// This is what the upload dApp uses to combine its persisted IndexedDB
    /// cache with the hourly-refreshed CDN seed: the cache carries peers we
    /// actually reached last session, the seed carries fresh AutoTLS /ws[s]
    /// underlays (which rotate every ~2-3h), and merging gets both — instead of
    /// the seed clobbering the cache or a stale cache shadowing the seed.
    /// Returns the store size after the merge.
    #[wasm_bindgen(js_name = "mergePeers")]
    pub fn merge_peers(&self, peers_json: &str) -> Result<usize, JsError> {
        let incoming: PeerStore = serde_json::from_str(peers_json).map_err(into_js_err)?;
        let mut store = self.peers.borrow_mut();
        for peer in incoming.iter() {
            store.upsert(peer.clone());
        }
        Ok(store.len())
    }

    /// Export the current peer store as a JSON string.
    #[wasm_bindgen(js_name = "exportPeers")]
    pub fn export_peers(&self) -> Result<String, JsError> {
        serde_json::to_string_pretty(&*self.peers.borrow()).map_err(into_js_err)
    }

    /// Number of peers currently held in memory.
    #[wasm_bindgen(js_name = "peerCount")]
    pub fn peer_count(&self) -> usize {
        self.peers.borrow().len()
    }

    /// Number of peers we currently hold a live retrieval session (open
    /// connection) to — the warm forwarder set. This is distinct from
    /// `peerCount` (peers merely *known* in the store, mostly TCP-only) and from
    /// the JS-side "dialable" count (peers that *advertise* a /ws[s] underlay but
    /// we may never have reached): it counts connections actually established and
    /// reused for retrieval. The gateway surfaces this as "connected peers".
    #[wasm_bindgen(js_name = "connectedPeerCount")]
    pub async fn connected_peer_count(&self) -> usize {
        self.cache.connected_count().await
    }

    /// Proactively open retrieval sessions to up to `target` dialable (ws/wss)
    /// peers so the warm forwarder set is non-zero before the first fetch. The
    /// browser daemon calls this after warming (and on its maintenance tick) so
    /// the gateway shows live "connected peers" at idle and the first site load
    /// reuses already-open sessions instead of dialing cold. Returns the total
    /// session count now cached. Best-effort: unreachable peers are skipped.
    ///
    /// `target == 0` means UNLIMITED (dial every reachable dialable peer),
    /// matching [`HoverflyClient::start`]'s `warm_pool` convention.
    #[wasm_bindgen(js_name = "prewarmSessions")]
    pub async fn prewarm_sessions(&self, target: usize) -> usize {
        let target = if target == 0 { usize::MAX } else { target };
        let peers = self.peers.borrow().clone();
        self.cache.prewarm(&self.transport, &peers, target).await
    }

    /// Export resolved feed head-index hints as a JSON object
    /// `{ "<owner||topic hex>": <index>, … }`. The browser daemon persists this
    /// to IndexedDB so a returning visitor resolves a feed (e.g. swarm.eth) in
    /// ~1 fast round from the cached head instead of a cold ~30s gallop from 0.
    #[wasm_bindgen(js_name = "exportFeedHints")]
    pub fn export_feed_hints(&self) -> Result<String, JsError> {
        serde_json::to_string(&self.cache.export_feed_hints()).map_err(into_js_err)
    }

    /// Merge persisted feed hints (JSON object as produced by
    /// [`Self::export_feed_hints`]) back into the cache. Monotonic — never
    /// lowers a hint, so a stale persisted value can't move a feed backwards.
    #[wasm_bindgen(js_name = "loadFeedHints")]
    pub fn load_feed_hints(&self, hints_json: &str) -> Result<(), JsError> {
        let hints: std::collections::HashMap<String, u64> =
            serde_json::from_str(hints_json).map_err(into_js_err)?;
        self.cache.import_feed_hints(hints);
        Ok(())
    }

    /// Start the in-browser daemon: a long-lived background task that keeps
    /// the peer set warm. It runs one discovery round immediately — so the
    /// first fetch already has fresh, browser-dialable peers to race — then
    /// re-discovers every `interval_secs` for as long as the client lives.
    ///
    /// This is the in-browser analogue of the native unix-socket daemon's
    /// eager pool-fill + maintenance loop (`src/daemon.rs`): rather than the
    /// caller orchestrating discrete `discover()` then `fetch()` steps, the
    /// node maintains its own connectivity and `fetchManifestPath` / `fetch`
    /// simply talk to the running daemon. Because every method takes `&self`,
    /// fetches run concurrently with the background loop with no locking.
    ///
    /// `warm_pool` is the target size of the warm retrieval-session pool the
    /// daemon keeps open in the background (defaults to [`DEFAULT_WARM_POOL`]).
    /// This is what makes wasm "daemon mode" a real warm pool rather than just a
    /// fresh address book: after the eager discovery round (and on every quiet
    /// maintenance tick) the daemon dials browser-dialable forwarders and keeps
    /// the connections warm, so `connectedPeerCount` climbs at idle and the
    /// first fetch reuses live sessions. Pass `0` (the default) to warm
    /// UNLIMITED peers — every reachable dialable peer; the effective ceiling is
    /// then just how many /ws peers actually accept a connection. A positive
    /// value caps the pool at that many sessions.
    ///
    /// Idempotent: a second call refreshes peers but does not spawn a second
    /// loop. Returns the peer count after the initial round.
    ///
    /// `skip_prewarm` (default `false`): when `true`, discover peers and run the
    /// maintenance loop's periodic re-discovery, but do NOT open or maintain the
    /// warm *retrieval* session pool. The upload dApp sets this — it never
    /// fetches, and the pushsync pool the upload path opens is entirely separate
    /// from the retrieval sessions this would warm. Warming retrieval sessions
    /// there just doubled cold-start dialing (retrieval pool + then the upload's
    /// own pushsync pool) and made bring-up far slower than the native pusher for
    /// no benefit. Gateway callers omit it to keep the fetch-warming behavior.
    pub async fn start(
        &self,
        bootstrap: String,
        interval_secs: u32,
        wait_secs: u32,
        warm_pool: Option<u32>,
        skip_prewarm: Option<bool>,
    ) -> Result<usize, JsError> {
        let skip_prewarm = skip_prewarm.unwrap_or(false);
        // 0 (or omitted -> default 0) => unlimited: dial every reachable peer.
        // `prewarm` treats usize::MAX as "no cap" (it never reaches the target,
        // so it drains the whole candidate list).
        let warm_pool = match warm_pool.map(|n| n as usize).unwrap_or(DEFAULT_WARM_POOL) {
            0 => usize::MAX,
            n => n,
        };
        let bootstrap_ma: Multiaddr = bootstrap
            .parse()
            .map_err(|e: libp2p::multiaddr::Error| into_js_err(e))?;

        // Eager initial fill — the first fetch should not start cold.
        merge_discovered(
            &self.transport,
            &self.doh,
            &self.peers,
            &bootstrap_ma,
            Duration::from_secs(wait_secs as u64),
        )
        .await;

        // Eager pool warm-up: open the warm retrieval-session pool now, off the
        // freshly-filled peer store, so `connectedPeerCount` is non-zero before
        // the first fetch and the first site load reuses these sessions instead
        // of dialing cold. Best effort — unreachable peers are skipped. Runs only
        // on the first `start()` (when the loop is about to be spawned); a repeat
        // `start()` just refreshes peers and lets the loop keep the pool topped.
        if !skip_prewarm && !*self.running.borrow() {
            let peers_snapshot = self.peers.borrow().clone();
            let n = self
                .cache
                .prewarm(&self.transport, &peers_snapshot, warm_pool)
                .await;
            tracing::info!(target: "hoverfly::wasm",
                "[daemon] eager warm-up: {} session(s) open ({})", n, warm_pool_label(warm_pool));
        }

        // Spawn the maintenance loop exactly once.
        let already_running = *self.running.borrow();
        if !already_running {
            *self.running.borrow_mut() = true;
            let transport = self.transport.clone();
            let doh = self.doh.clone();
            let peers = self.peers.clone();
            let running = self.running.clone();
            let inflight = self.inflight_fetches.clone();
            let cache = self.cache.clone();
            let bootstrap_ma = bootstrap_ma.clone();
            let interval = Duration::from_secs(interval_secs.max(1) as u64);
            let wait = Duration::from_secs(wait_secs as u64);
            wasm_bindgen_futures::spawn_local(async move {
                let mut tick: u64 = 0;
                loop {
                    // Sleep first: `start` already did the eager round above,
                    // so there's no need to discover again immediately.
                    Delay::new(interval).await;
                    tick = tick.wrapping_add(1);
                    let keep_running = *running.borrow();
                    if !keep_running {
                        break;
                    }
                    // Don't discover OR warm sessions while a foreground fetch is
                    // in flight: on the browser's single ws+yamux driver, the
                    // dial/substream churn of a discovery round or a pool warm-up
                    // resets in-flight retrieval substreams and stalls the fetch.
                    // If a fetch (or burst) is active, defer — re-check on a short
                    // cadence and run only once the connections go quiet, so the
                    // pool is maintained between page loads but never mid-load.
                    let mut deferrals = 0u32;
                    while inflight.get() > 0 {
                        // Cap the wait so a wedged in-flight counter (shouldn't
                        // happen — FetchGuard's Drop always decrements) can't
                        // starve discovery forever; after ~interval of deferral
                        // proceed anyway.
                        if deferrals >= 10 {
                            break;
                        }
                        deferrals += 1;
                        Delay::new(Duration::from_secs(2)).await;
                    }
                    if !*running.borrow() {
                        break;
                    }

                    // Discovery is a ONE-SHOT path: `discover_peers` stands up a
                    // throwaway libp2p swarm per dialed peer, harvests hive
                    // gossip, and discards the connection. That's correct for the
                    // CLI (dial, read, exit) but wasteful in a long-lived browser
                    // daemon — re-running it every tick spun up a fresh swarm +
                    // full handshake/pricing dance every `interval`, flooding the
                    // console and churning the single ws+yamux driver for almost
                    // no benefit: the eager round at `start()` already filled the
                    // peer store, and warm retrieval sessions persist separately.
                    // So re-discover only occasionally (every DISCOVER_EVERY_N
                    // ticks) just to refresh the store as peers churn; the warm
                    // pool — the connections retrieval actually reuses — is topped
                    // up every tick below.
                    if tick % DISCOVER_EVERY_N == 0 {
                        merge_discovered(&transport, &doh, &peers, &bootstrap_ma, wait).await;
                    }

                    // Top the warm session pool back up: sessions die (peer drop,
                    // idle close) and are evicted by the fetch path, so the pool
                    // decays between loads. Re-warming here (while connections are
                    // quiet) keeps the "connected peers" count from sagging to 0 at
                    // idle — the warm-pool half of daemon mode. Re-check in-flight:
                    // a discovery round (when it ran) may have let a fetch start.
                    // `skip_prewarm` (upload dApp) leaves the retrieval pool
                    // alone entirely — it only wants peer discovery, not warm
                    // fetch sessions it never uses.
                    if !skip_prewarm && inflight.get() == 0 {
                        let peers_snapshot = peers.borrow().clone();
                        let n = cache.prewarm(&transport, &peers_snapshot, warm_pool).await;
                        tracing::debug!(target: "hoverfly::wasm",
                            "[daemon] pool warm: {} session(s) open ({})", n, warm_pool_label(warm_pool));
                    }
                }
            });
        }

        Ok(self.peers.borrow().len())
    }

    /// Stop the background daemon loop. It exits after its current sleep.
    pub fn stop(&self) {
        *self.running.borrow_mut() = false;
    }

    /// Enable the persistent IndexedDB chunk cache (L2). Once enabled, every
    /// retrieved chunk is written back to IndexedDB and future fetches (this
    /// session or later) reuse stored chunks instead of hitting the network —
    /// immutable + content-addressed, so it's safe to keep indefinitely. This
    /// sits on top of the per-fetch in-memory cache. `db_name` is the
    /// IndexedDB database name to use.
    #[wasm_bindgen(js_name = "enableChunkStore")]
    pub async fn enable_chunk_store(&self, db_name: String) -> Result<(), JsError> {
        // Open once here to verify the database is usable (so a storage error
        // surfaces to the caller now, not silently on the first fetch). The
        // opened handle is bound to THIS thread; the retrieval paths run on
        // rayon worker threads and open their own per-thread handles lazily —
        // see `idb_chunk_store`'s threading note. So we only record the name.
        let _verify = crate::idb_chunk_store::IdbChunkStore::open(&db_name)
            .await
            .map_err(into_js_err)?;
        crate::idb_chunk_store::set_store_name(db_name);
        Ok(())
    }

    /// Number of chunks served from the persistent L2 (IndexedDB) cache since
    /// load. Non-zero with a cold in-memory cache means fetches are being
    /// served from IndexedDB rather than the network.
    #[wasm_bindgen(js_name = "chunkStoreHits")]
    pub fn chunk_store_hits(&self) -> u32 {
        crate::idb_chunk_store::hits()
    }

    /// Run a single discovery round now and merge the results into the
    /// in-memory peer store. The daemon's background loop does this
    /// automatically once [`HoverflyClient::start`] has been called; this is
    /// exposed for an explicit "refresh peers" affordance. Returns the new
    /// peer count.
    pub async fn discover(&self, bootstrap: String, wait_secs: u32) -> Result<usize, JsError> {
        let bootstrap_ma: Multiaddr = bootstrap
            .parse()
            .map_err(|e: libp2p::multiaddr::Error| into_js_err(e))?;
        merge_discovered(
            &self.transport,
            &self.doh,
            &self.peers,
            &bootstrap_ma,
            Duration::from_secs(wait_secs as u64),
        )
        .await;
        Ok(self.peers.borrow().len())
    }

    /// Fetch content. `root_hex` is a 32-byte content address in hex.
    /// Reassembles the BMT tree into the full byte stream.
    pub async fn fetch(&self, root_hex: String, max_retries: usize) -> Result<Uint8Array, JsError> {
        let _guard = FetchGuard::new(&self.inflight_fetches);
        let peers = self.peers.borrow().clone();
        let bytes = fetch_bytes_cached_ex(
            &self.transport,
            &peers,
            &root_hex,
            max_retries,
            FETCH_CONCURRENCY,
            &self.cache,
        )
        .await
        .map_err(into_js_err)?;
        Ok(Uint8Array::from(bytes.as_slice()))
    }

    /// Resolve `path` through the mantaray manifest rooted at `root_hex` and
    /// fetch the resulting file's bytes + `Content-Type`. This is the gateway
    /// entry point: `fetchManifestPath("<root>", "index.html", 3)`. An empty
    /// `path` returns the manifest's root entry. Uses the shared retrieval
    /// cache so warm sessions/peer scores persist across requests.
    #[wasm_bindgen(js_name = "fetchManifestPath")]
    pub async fn fetch_manifest_path(
        &self,
        root_hex: String,
        path: String,
        max_retries: usize,
    ) -> Result<ManifestFetch, JsError> {
        let _guard = FetchGuard::new(&self.inflight_fetches);
        let peers = self.peers.borrow().clone();
        let (bytes, content_type, feed_resolved) = fetch_manifest_path_cached_meta(
            &self.transport,
            &peers,
            &root_hex,
            &path,
            max_retries,
            FETCH_CONCURRENCY,
            &self.cache,
        )
        .await
        .map_err(into_js_err)?;
        Ok(ManifestFetch {
            bytes,
            content_type,
            feed_resolved,
        })
    }

    /// List every entry in the mantaray manifest at `root_hex` as a JSON
    /// string: `[{"path","reference","contentType"}]`. Useful for directory
    /// index pages.
    #[wasm_bindgen(js_name = "listManifest")]
    pub async fn list_manifest(
        &self,
        root_hex: String,
        max_retries: usize,
    ) -> Result<String, JsError> {
        let peers = self.peers.borrow().clone();
        let entries = list_manifest_ex(
            &self.transport,
            &peers,
            &root_hex,
            max_retries,
            FETCH_CONCURRENCY,
        )
        .await
        .map_err(into_js_err)?;
        let json: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "path": e.path,
                    "reference": e.reference,
                    "contentType": e.content_type,
                })
            })
            .collect();
        serde_json::to_string(&json).map_err(into_js_err)
    }

    /// Upload raw bytes with an existing postage batch. Returns the BMT root
    /// hash hex. This is the lowest-level upload: no manifest, so the reference
    /// carries no filename or content-type. Prefer [`Self::upload_file`] (which
    /// wraps the bytes in a single-entry mantaray manifest) for anything a
    /// gateway should serve with a sensible `Content-Type`.
    pub async fn upload(
        &self,
        data: Uint8Array,
        batch_id_hex: String,
        depth: u8,
        immutable: bool,
        max_retries: usize,
        redundancy: Option<String>,
    ) -> Result<String, JsError> {
        let signer = self.upload_signer()?;
        let buf = data.to_vec();
        let peers = self.peers.borrow().clone();
        let progress = self.make_progress();
        let root = upload_bytes_ex(
            &self.transport,
            &peers,
            &signer,
            &batch_id_hex,
            depth,
            immutable,
            &buf,
            parse_redundancy(redundancy.as_deref())?,
            max_retries,
            UPLOAD_POOL,
            Some(&progress),
        )
        .await
        .map_err(into_js_err)?;
        Ok(hex::encode(root.as_bytes()))
    }

    /// Upload a single file wrapped in a one-entry mantaray manifest: `path`
    /// (the filename) maps to the file's content, with optional `content_type`
    /// metadata. Returns the *manifest* root — a gateway resolves
    /// `<root>/<path>` to the bytes and serves them with the recorded
    /// `Content-Type`, and a bare `<root>/` resolves to the single entry too
    /// (the single-file fallback gateways use). This is the upload a dApp wants
    /// for "upload this file and give me a usable bzz link".
    #[wasm_bindgen(js_name = "uploadFile")]
    pub async fn upload_file(
        &self,
        data: Uint8Array,
        path: String,
        content_type: Option<String>,
        batch_id_hex: String,
        depth: u8,
        immutable: bool,
        max_retries: usize,
        redundancy: Option<String>,
    ) -> Result<String, JsError> {
        let signer = self.upload_signer()?;
        let buf = data.to_vec();
        let peers = self.peers.borrow().clone();
        let progress = self.make_progress();
        let root = upload_file_with_manifest_ex(
            &self.transport,
            &peers,
            &signer,
            &batch_id_hex,
            depth,
            immutable,
            &buf,
            &path,
            content_type.as_deref(),
            parse_redundancy(redundancy.as_deref())?,
            max_retries,
            UPLOAD_POOL,
            Some(&progress),
        )
        .await
        .map_err(into_js_err)?;
        Ok(hex::encode(root.as_bytes()))
    }

    /// Upload a collection of files as a multi-entry mantaray manifest — the
    /// in-browser equivalent of bee's tar / multipart `POST /bzz` directory
    /// upload. Each file is BMT-split independently and gets one manifest entry
    /// keyed by its in-archive `path`; duplicate chunks across files are
    /// stamped once. Returns the manifest root.
    ///
    /// `files` is a JS array of objects `{ path: string, data: Uint8Array,
    /// contentType?: string }`. `index_document` / `error_document` (e.g.
    /// `"index.html"` / `"error.html"`) are written as website metadata on the
    /// root so a gateway serves `<root>/` as the index and unknown paths as the
    /// error page — turning the collection into a browsable website.
    ///
    /// Tar parsing stays in JS (the `tar` crate is `cli`-feature-gated and not
    /// in the wasm build); the caller unpacks the archive and passes the entry
    /// list here.
    #[wasm_bindgen(js_name = "uploadCollection")]
    pub async fn upload_collection(
        &self,
        files: Array,
        index_document: Option<String>,
        error_document: Option<String>,
        batch_id_hex: String,
        depth: u8,
        immutable: bool,
        max_retries: usize,
        redundancy: Option<String>,
    ) -> Result<String, JsError> {
        let signer = self.upload_signer()?;
        let upload_files = parse_upload_files(&files)?;
        if upload_files.is_empty() {
            return Err(JsError::new("collection is empty (no files)"));
        }
        let peers = self.peers.borrow().clone();
        let progress = self.make_progress();
        let root = upload_collection(
            &self.transport,
            &peers,
            &signer,
            &batch_id_hex,
            depth,
            immutable,
            upload_files,
            index_document.as_deref(),
            error_document.as_deref(),
            parse_redundancy(redundancy.as_deref())?,
            max_retries,
            UPLOAD_POOL,
            Some(&progress),
        )
        .await
        .map_err(into_js_err)?;
        Ok(hex::encode(root.as_bytes()))
    }

    /// Begin a **streaming** upload for the pusher path (single file or
    /// raw). Splits + builds the manifest once, then the returned
    /// [`UploadStream`] stamps and yields frames one window at a time via
    /// `nextBatch`, freeing each window as it goes — flat memory regardless
    /// of file size (500 MB / multi-GB without OOMing the tab). Stamp time
    /// also overlaps the push instead of blocking up front.
    #[wasm_bindgen(js_name = "beginUpload")]
    pub fn begin_upload(
        &self,
        data: Uint8Array,
        path: String,
        content_type: Option<String>,
        batch_id_hex: String,
        depth: u8,
        immutable: bool,
        raw: bool,
        redundancy: Option<String>,
    ) -> Result<UploadStream, JsError> {
        let signer = self.upload_signer()?;
        let buf = data.to_vec();
        let level = parse_redundancy(redundancy.as_deref())?;
        let inner = if raw {
            UploadStreamer::new_raw(&signer, &batch_id_hex, depth, immutable, &buf, level)
        } else {
            UploadStreamer::new_file(
                &signer,
                &batch_id_hex,
                depth,
                immutable,
                &buf,
                &path,
                content_type.as_deref(),
                level,
            )
        }
        .map_err(into_js_err)?;
        Ok(UploadStream { inner })
    }

    /// Streaming variant of [`Self::prepare_collection`] — a windowed
    /// [`UploadStream`] over a tar / directory, so large collections don't
    /// materialize every frame at once.
    #[wasm_bindgen(js_name = "beginCollection")]
    pub fn begin_collection(
        &self,
        files: Array,
        index_document: Option<String>,
        error_document: Option<String>,
        batch_id_hex: String,
        depth: u8,
        immutable: bool,
        redundancy: Option<String>,
    ) -> Result<UploadStream, JsError> {
        let signer = self.upload_signer()?;
        let upload_files = parse_upload_files(&files)?;
        if upload_files.is_empty() {
            return Err(JsError::new("collection is empty (no files)"));
        }
        let inner = UploadStreamer::new_collection(
            &signer,
            &batch_id_hex,
            depth,
            immutable,
            &upload_files,
            index_document.as_deref(),
            error_document.as_deref(),
            parse_redundancy(redundancy.as_deref())?,
        )
        .map_err(into_js_err)?;
        Ok(UploadStream { inner })
    }

    /// Wrap an [`UploadStream`] in a scheduler-driven multi-lane session.
    ///
    /// `lanes` is only a count here — the session refers to lanes by index
    /// and never performs I/O, so JS keeps the URL list and does the
    /// `fetch`ing. See [`UploadSession`] for the loop shape.
    #[wasm_bindgen(js_name = "beginSession")]
    pub fn begin_session(&self, lanes: usize, stream: UploadStream) -> UploadSession {
        let cfg = crate::pushsched::Config::default();
        let infos = (0..lanes.max(1))
            .map(|_| crate::pushsched::LaneInfo::default())
            .collect();
        UploadSession {
            sched: crate::pushsched::Scheduler::new(infos, cfg),
            root: hex::encode(stream.inner.root().as_bytes()),
            total_hint: stream.inner.total_chunks(),
            stream: Some(stream.inner),
            frames: std::collections::HashMap::new(),
            exhausted: false,
        }
    }

    /// Live upload progress as `[pushed, total]` chunk counts. The worker
    /// polls this on a timer while an upload is in flight and forwards it to
    /// the UI, so the progress bar tracks real chunk pushes instead of a fake
    /// staged animation. `total` is 0 before the first upload and between
    /// uploads; during an upload it's the chunk count and `pushed` climbs to it.
    #[wasm_bindgen(js_name = "uploadProgress")]
    pub fn upload_progress(&self) -> Vec<usize> {
        use std::sync::atomic::Ordering;
        vec![
            self.upload_done.load(Ordering::Relaxed),
            self.upload_total.load(Ordering::Relaxed),
        ]
    }

    /// One-line dump of the transport diagnostic counters (push outcomes +
    /// latency histograms + retirement causes). The worker logs this at the
    /// end of an upload so browser throughput can be debugged from real data
    /// (where did the time go?) instead of guesswork.
    #[wasm_bindgen(js_name = "uploadDiagnostics")]
    pub fn upload_diagnostics(&self) -> String {
        crate::transport::diag::summary()
    }

    /// Reset the progress counters and build a [`ProgressFn`] that records
    /// `(done, total)` into this client's atomics on every chunk. Called at the
    /// start of each upload; the returned closure is handed to the pusher.
    fn make_progress(&self) -> crate::client::ProgressFn {
        use std::sync::atomic::Ordering;
        self.upload_done.store(0, Ordering::Relaxed);
        self.upload_total.store(0, Ordering::Relaxed);
        let done = self.upload_done.clone();
        let total = self.upload_total.clone();
        Arc::new(move |d: usize, t: usize| {
            total.store(t, Ordering::Relaxed);
            done.store(d, Ordering::Relaxed);
        })
    }

    /// Build the stamp signer from the private key the client was constructed
    /// with. Errors if the client is fetch-only (no key).
    fn upload_signer(&self) -> Result<SwarmSigner, JsError> {
        let key = self
            .signer_key
            .as_deref()
            .ok_or_else(|| JsError::new("client constructed without a private key"))?;
        SwarmSigner::from_hex(key, self.network_id).map_err(into_js_err)
    }
}

/// Decode the optional `redundancy` argument every upload entry point takes.
///
/// `undefined`/`null` means bee's default upload level (MEDIUM), so a dApp that
/// passes nothing gets the same erasure coding a bee gateway would apply to
/// `POST /bzz` — the object stays readable when some of its data chunks are
/// unretrievable, which is the normal state of a fresh upload for a
/// forwarding-dependent client. Pass `"none"` to opt out (cheaper in postage,
/// and a different reference).
fn parse_redundancy(level: Option<&str>) -> Result<crate::erasure::Level, JsError> {
    match level {
        None => Ok(crate::erasure::DEFAULT_UPLOAD_LEVEL),
        Some(s) if s.trim().is_empty() => Ok(crate::erasure::DEFAULT_UPLOAD_LEVEL),
        Some(s) => s.parse().map_err(|e: String| JsError::new(&e)),
    }
}

/// Decode a JS array of `{ path, data, contentType? }` into `UploadFile`s.
/// `path` and `data` (a `Uint8Array`) are required per entry; `contentType`
/// is optional. Reading the `Uint8Array` copies its bytes out of wasm-shared
/// memory into an owned `Vec<u8>`.
fn parse_upload_files(files: &Array) -> Result<Vec<UploadFile>, JsError> {
    let mut out = Vec::with_capacity(files.length() as usize);
    for (i, entry) in files.iter().enumerate() {
        let path = Reflect::get(&entry, &JsValue::from_str("path"))
            .ok()
            .and_then(|v| v.as_string())
            .ok_or_else(|| JsError::new(&format!("files[{i}]: missing string `path`")))?;
        let data_val = Reflect::get(&entry, &JsValue::from_str("data"))
            .map_err(|_| JsError::new(&format!("files[{i}]: missing `data`")))?;
        if !data_val.is_instance_of::<Uint8Array>() {
            return Err(JsError::new(&format!(
                "files[{i}]: `data` must be a Uint8Array"
            )));
        }
        let data = Uint8Array::from(data_val).to_vec();
        let content_type = Reflect::get(&entry, &JsValue::from_str("contentType"))
            .ok()
            .and_then(|v| v.as_string());
        out.push(UploadFile {
            path,
            content_type,
            data,
        });
    }
    Ok(out)
}

/// Result of a manifest path fetch: file bytes plus the optional
/// `Content-Type` recorded in the manifest entry's metadata.
#[wasm_bindgen]
pub struct ManifestFetch {
    bytes: Vec<u8>,
    content_type: Option<String>,
    feed_resolved: bool,
}

#[wasm_bindgen]
impl ManifestFetch {
    /// The resolved file's content bytes.
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Uint8Array {
        Uint8Array::from(self.bytes.as_slice())
    }

    /// The `Content-Type` from the manifest entry's metadata, if present.
    #[wasm_bindgen(getter, js_name = "contentType")]
    pub fn content_type(&self) -> Option<String> {
        self.content_type.clone()
    }

    /// True iff the reference resolved through a **feed manifest** — i.e. the
    /// content is mutable (the feed's reference is stable but its head moves
    /// forward). The gateway uses this to avoid caching feed-backed responses
    /// as immutable, which would otherwise pin a visitor to one feed update
    /// forever and break later updates.
    #[wasm_bindgen(getter, js_name = "feedResolved")]
    pub fn feed_resolved(&self) -> bool {
        self.feed_resolved
    }
}

/// A windowed streaming upload (see [`HoverflyClient::begin_upload`]). JS
/// pulls `nextBatch(batchSize)` until it returns `undefined`, pushing each
/// body to a relay — memory stays flat regardless of file size.
#[wasm_bindgen]
pub struct UploadStream {
    inner: UploadStreamer,
}

#[wasm_bindgen]
impl UploadStream {
    /// Reference root (hex) — fixed by the initial split, available before
    /// any chunk is pushed.
    #[wasm_bindgen(getter)]
    pub fn root(&self) -> String {
        hex::encode(self.inner.root().as_bytes())
    }

    /// Total chunk count (for progress totals).
    #[wasm_bindgen(getter, js_name = "chunkCount")]
    pub fn chunk_count(&self) -> usize {
        self.inner.total_chunks()
    }

    /// Stamp + encode the next window as a POST body, or `undefined` when
    /// the stream is exhausted. Each call frees the window it consumed.
    #[wasm_bindgen(js_name = "nextBatch")]
    pub fn next_batch(&mut self, batch_size: usize) -> Result<Option<Uint8Array>, JsError> {
        let work = self.inner.next_batch(batch_size).map_err(into_js_err)?;
        if work.is_empty() {
            return Ok(None);
        }
        let body = crate::pushframe::encode_batch(&work);
        Ok(Some(Uint8Array::from(body.as_slice())))
    }
}

/// A multi-lane relay upload driven from JS.
///
/// The browser used to own its own scheduler (round-robin lanes, whole-bundle
/// failover, no weights, no stickiness) while the CLI owned a better one in
/// Rust — two implementations that inevitably drifted. This exposes the *same*
/// [`crate::pushsched::Scheduler`] the native path uses; JS is left with only
/// the parts it must own, `fetch` and the clock.
///
/// Usage:
/// ```js
/// const s = client.beginSession(urls, stream)
/// for (const [i, u] of urls.entries()) s.setLaneStatus(i, await (await fetch(u + '/v1/status')).json())
/// while (!s.done) {
///   const req = s.nextRequest(Date.now())
///   if (req === undefined) { await sleep(s.waitMs(Date.now())); continue }
///   // POST req.body to urls[req.lane], stream NDJSON acks:
///   //   s.reportAck(req.lane, addrHex, ok, Date.now())
///   // then: s.reportBatch(req.batch, req.lane, acked, elapsedMs, ok, Date.now())
/// }
/// ```
#[wasm_bindgen]
pub struct UploadSession {
    sched: crate::pushsched::Scheduler,
    stream: Option<UploadStreamer>,
    frames: std::collections::HashMap<[u8; 32], crate::client::StampedChunk>,
    root: String,
    total_hint: usize,
    exhausted: bool,
}

/// One dispatch for JS to perform.
#[wasm_bindgen]
pub struct PushRequest {
    lane: usize,
    batch: u64,
    body: Vec<u8>,
    hedge: bool,
}

#[wasm_bindgen]
impl PushRequest {
    /// Index into the lane URL list this session was created with.
    #[wasm_bindgen(getter)]
    pub fn lane(&self) -> usize {
        self.lane
    }
    /// Opaque id to pass back to `reportBatch`.
    #[wasm_bindgen(getter)]
    pub fn batch(&self) -> f64 {
        self.batch as f64
    }
    /// Encoded frames to POST.
    #[wasm_bindgen(getter)]
    pub fn body(&self) -> Uint8Array {
        Uint8Array::from(self.body.as_slice())
    }
    /// True when this duplicates work already in flight on another lane
    /// (a straggler hedge). Purely informational for logging.
    #[wasm_bindgen(getter)]
    pub fn hedge(&self) -> bool {
        self.hedge
    }
}

/// Window of chunks stamped per refill. Same rationale as the native
/// `PUSH_WINDOW`: keep lanes fed without holding the whole file's frames.
const SESSION_WINDOW: usize = 1024;

#[wasm_bindgen]
impl UploadSession {
    /// Reference root (hex), fixed by the split before anything is pushed.
    #[wasm_bindgen(getter)]
    pub fn root(&self) -> String {
        self.root.clone()
    }

    #[wasm_bindgen(getter, js_name = "chunkCount")]
    pub fn chunk_count(&self) -> usize {
        self.total_hint.max(self.sched.total())
    }

    #[wasm_bindgen(getter)]
    pub fn acked(&self) -> usize {
        self.sched.acked()
    }

    #[wasm_bindgen(getter)]
    pub fn failed(&self) -> usize {
        self.sched.failed()
    }

    #[wasm_bindgen(getter)]
    pub fn hedges(&self) -> usize {
        self.sched.hedges()
    }

    #[wasm_bindgen(getter)]
    pub fn done(&self) -> bool {
        self.exhausted && self.sched.done()
    }

    /// Feed a lane's `/v1/status` JSON. Per lane and idempotent: a relay
    /// that is asleep when polled simply keeps its default priors instead
    /// of degrading routing for every other lane.
    ///
    /// Returns `false` when the lane was taken out of rotation instead of
    /// scheduled — today that means it enforces payment
    /// (`docs/pusher-incentives.md` §7.3) and this build has no way to pay.
    /// The browser stamps but never settles: the chequebook lives in the
    /// native client, so a hard lane would answer every POST with 401 for a
    /// missing capability, and that is not a 402 — it counts against lane
    /// health and burns one attempt per chunk rediscovering something the
    /// lane announced up front. Soft-metered lanes are kept, since those
    /// bill and serve; an unpaying client is served exactly like on `open`.
    #[wasm_bindgen(js_name = "setLaneStatus")]
    pub fn set_lane_status(&mut self, lane: usize, status: JsValue) -> Result<bool, JsError> {
        // Round-trip through JSON text rather than pulling in
        // serde-wasm-bindgen for one struct.
        let txt = js_sys::JSON::stringify(&status)
            .map_err(|_| JsError::new("status is not JSON-serialisable"))?;
        let v: serde_json::Value = serde_json::from_str(&String::from(txt))
            .map_err(|e| JsError::new(&format!("status json: {e}")))?;
        let overlay = v
            .get("overlay")
            .and_then(|s| s.as_str())
            .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
        // The advertised `enforcement` is read without verifying the quote's
        // signature, unlike the native path. Verification protects a *payer*
        // from being overcharged; there is no payment here to protect, and
        // the only thing this flag can do is make us decline a lane. A lane
        // lying its way out of our traffic is a lane denying its own
        // service.
        let payment = v.get("payment");
        let hard_enforcement = payment
            .and_then(|p| p.get("enforcement"))
            .and_then(|x| x.as_str())
            == Some("hard");
        let price_plur_per_kib = payment
            .and_then(|p| p.get("price_plur_per_kib"))
            .and_then(|x| x.as_str())
            .and_then(|s| s.parse::<u128>().ok());
        self.sched.set_lane_info(
            lane,
            crate::pushsched::LaneInfo {
                overlay,
                batch_max: v
                    .get("batch_max")
                    .and_then(|x| x.as_u64())
                    .map(|x| x as usize),
                inflight_max: v
                    .get("inflight_max")
                    .and_then(|x| x.as_u64())
                    .map(|x| x as usize),
                budget_remaining_gb: v.get("budget_remaining_gb").and_then(|x| x.as_f64()),
                pool_live: v
                    .get("pool")
                    .and_then(|p| p.get("live"))
                    .and_then(|x| x.as_u64())
                    .map(|x| x as usize),
                price_plur_per_kib,
                hard_enforcement,
            },
        );
        if hard_enforcement {
            self.sched.retire_lane(lane);
            return Ok(false);
        }
        Ok(true)
    }

    /// Next POST to issue, or `undefined` if nothing is dispatchable right
    /// now (everything in flight, or every lane backing off — see
    /// `waitMs`). Stamps another window when the backlog runs low.
    #[wasm_bindgen(js_name = "nextRequest")]
    pub fn next_request(&mut self, now_ms: f64) -> Result<Option<PushRequest>, JsError> {
        let now = now_ms.max(0.0) as u64;
        while !self.exhausted
            && self.sched.total() - self.sched.acked() - self.sched.failed() < SESSION_WINDOW
        {
            self.refill()?;
        }
        let Some(a) = self.sched.next(now) else {
            return Ok(None);
        };
        let batch: Vec<crate::client::StampedChunk> = a
            .chunks
            .iter()
            .filter_map(|&i| self.frames.get(&self.sched.chunk_addr(i)).cloned())
            .collect();
        Ok(Some(PushRequest {
            lane: a.lane,
            batch: a.batch,
            body: crate::pushframe::encode_batch(&batch),
            hedge: a.hedge,
        }))
    }

    /// Record one streamed NDJSON ack. Idempotent per address, which is what
    /// makes hedging safe: the losing copy's late ack is ignored.
    #[wasm_bindgen(js_name = "reportAck")]
    pub fn report_ack(&mut self, lane: usize, addr_hex: &str, ok: bool, now_ms: f64) {
        let Ok(raw) = hex::decode(addr_hex.trim_start_matches("0x")) else {
            return;
        };
        let Ok(addr) = <[u8; 32]>::try_from(raw.as_slice()) else {
            return;
        };
        let before = self.sched.acked();
        self.sched.on_ack(lane, &addr, ok, now_ms.max(0.0) as u64);
        if self.sched.acked() > before {
            // Acked chunks are never re-dispatched, so the frame can go.
            self.frames.remove(&addr);
        }
    }

    /// Record the HTTP-level result of a dispatch, after all of its acks.
    #[wasm_bindgen(js_name = "reportBatch")]
    pub fn report_batch(
        &mut self,
        batch: f64,
        lane: usize,
        acked: usize,
        elapsed_ms: f64,
        ok: bool,
        now_ms: f64,
    ) {
        let outcome = if ok {
            crate::pushsched::BatchOutcome::Answered
        } else {
            crate::pushsched::BatchOutcome::Failed("post failed".into())
        };
        self.sched
            .on_batch_timing(lane, acked, elapsed_ms.max(0.0) as u64);
        self.sched
            .on_batch_result(batch as u64, outcome, now_ms.max(0.0) as u64);
    }

    /// A 402/401 is a bill (or stale capability), not a fault — pause the
    /// lane without charging health or burning a retry attempt. The browser
    /// has no chequebook, so a hard lane that flips mid-run pauses rather
    /// than failing its chunks; hard lanes are still retired upfront via
    /// `setLaneStatus`, this is the mid-run recovery.
    #[wasm_bindgen(js_name = "reportPaymentRequired")]
    pub fn report_payment_required(&mut self, batch: f64, _lane: usize, now_ms: f64) {
        // `_lane` is for JS call-site symmetry with `reportBatch`; the
        // scheduler resolves the lane from the batch id.
        self.sched.on_batch_result(
            batch as u64,
            crate::pushsched::BatchOutcome::PaymentRequired,
            now_ms.max(0.0) as u64,
        );
    }

    /// Milliseconds to wait before calling `nextRequest` again when it
    /// returned `undefined`. `0` means "there is work in flight, wait on
    /// that instead".
    #[wasm_bindgen(js_name = "waitMs")]
    pub fn wait_ms(&self, now_ms: f64) -> f64 {
        let now = now_ms.max(0.0) as u64;
        match self.sched.next_wake_ms(now) {
            Some(t) if t > now => (t - now) as f64,
            _ => 0.0,
        }
    }

    /// Non-empty when the run cannot proceed: every lane is gone, or the
    /// remaining chunks exhausted their attempts. The counterpart of the
    /// erasure joiner's early bail — better to report a hopeless state than
    /// to keep timing out against it.
    #[wasm_bindgen(js_name = "stallReason")]
    pub fn stall_reason(&self, now_ms: f64) -> Option<String> {
        if !self.exhausted {
            return None;
        }
        self.sched
            .stalled(now_ms.max(0.0) as u64)
            .map(|r| format!("{r:?}"))
    }

    /// Per-lane counters, for logging: `[{acked, failed, bytes, rate, health}]`.
    #[wasm_bindgen(js_name = "laneStats")]
    pub fn lane_stats(&self) -> JsValue {
        let stats: Vec<serde_json::Value> = self
            .sched
            .lane_stats()
            .into_iter()
            .map(|s| {
                serde_json::json!({
                    "acked": s.acked,
                    "failed": s.failed,
                    "bytes": s.bytes,
                    "rate": s.rate,
                    "health": s.health.map(|h| format!("{h:?}")),
                })
            })
            .collect();
        let txt = serde_json::to_string(&stats).unwrap_or_else(|_| "[]".into());
        js_sys::JSON::parse(&txt).unwrap_or(JsValue::NULL)
    }

    fn refill(&mut self) -> Result<(), JsError> {
        let Some(stream) = self.stream.as_mut() else {
            self.exhausted = true;
            return Ok(());
        };
        let batch = stream.next_batch(SESSION_WINDOW).map_err(into_js_err)?;
        if batch.is_empty() {
            self.exhausted = true;
            self.stream = None;
            return Ok(());
        }
        self.sched
            .admit(batch.iter().map(|c| (c.addr, c.wire.len() as u32)));
        for c in batch {
            self.frames.entry(c.addr).or_insert(c);
        }
        Ok(())
    }
}

fn into_js_err<E: core::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}

/// Run one discovery round against `bootstrap` and merge the freshly-found
/// peers into `peers`. Shared by the eager initial fill, the background
/// maintenance loop, and the manual `discover()` affordance.
///
/// Errors are swallowed (logged) — a failed round just means the next one
/// retries; the daemon must stay alive. The peer-store borrow is taken only
/// after the `discover` await resolves and is never held across an `.await`,
/// so it can never clash with a concurrent fetch's snapshot borrow.
/// Discovery depth for the in-browser daemon. Round 1 asks the bootstrap
/// (or seed peers) for hive announcements; round 2 dials the ws-dialable
/// peers *found in round 1* for theirs. One round yields ~20-30 known
/// peers — too few for the upload pool + mid-push top-up, which then
/// exhausts its candidate list and refills 0 while sessions keep dying
/// (observed: 533 KB upload grinding at pool=1-3 with 36 conn deaths).
/// Two rounds roughly triples the ws universe for one extra ~5-15 s of
/// background dialing; deeper than 2 hits diminishing returns because the
/// browser can only dial the /ws[s] subset of each hive burst anyway.
const WASM_DISCOVER_ROUNDS: usize = 2;

async fn merge_discovered(
    transport: &Transport,
    doh: &Doh,
    peers: &Rc<RefCell<PeerStore>>,
    bootstrap: &Multiaddr,
    wait: Duration,
) {
    match crate::client::discover_recursive(transport, doh, bootstrap, wait, WASM_DISCOVER_ROUNDS)
        .await
    {
        Ok(found) => {
            let n = found.len();
            let mut store = peers.borrow_mut();
            for p in found {
                store.upsert(p);
            }
            tracing::info!(target: "hoverfly::wasm",
                "[daemon] discover round ok: found {} peer(s), store now {}", n, store.len());
        }
        Err(e) => {
            tracing::warn!(target: "hoverfly::wasm", "[daemon] discover round failed: {e}");
        }
    }
}
