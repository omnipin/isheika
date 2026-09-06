//! High-level orchestration: `discover`, `fetch`, `upload`.
//!
//! Layered on top of `Transport` (libp2p WS) and nectar primitives. The
//! retrieval path implements [`nectar_primitives::store::ChunkGet`] over
//! peerlist-routed requests so that nectar's Joiner can drive multi-chunk
//! reassembly without knowing about libp2p.

use core::time::Duration;
use libp2p::Multiaddr;
use nectar_postage::{Batch, BatchId};
use nectar_postage_issuer::{BatchStamper, MemoryIssuer, RingIssuer, StampIssuer};

/// Boxed issuer so a single `BatchStamper` type covers both batch kinds:
/// immutable batches use the fill-only `MemoryIssuer`, mutable batches use
/// the overwrite-aware `RingIssuer` (nectar 0.3 split these; each rejects the
/// other's batch kind). Both are `dyn StampIssuer`, and the only issuer method
/// the stamping paths call is `prepare_stamp` via `issuer_mut()`.
type HoverflyStamper =
    BatchStamper<Box<dyn StampIssuer + Send>, alloy_signer_local::PrivateKeySigner>;
use nectar_primitives::bmt::DEFAULT_BODY_SIZE;
use nectar_primitives::chunk::{AnyChunk, ChunkAddress, ContentChunk, SingleOwnerChunk};
use nectar_primitives::file::{GenericJoiner, split};
use nectar_primitives::store::{ChunkGet, ChunkStoreError};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::dnsaddr::{DnsAddrError, resolve};
use crate::doh::Doh;
use crate::erasure::Level;
use crate::peers::{DialResult, Peer, PeerStore};
use crate::protocols::pushsync::PushsyncReceipt;
use crate::signer::SwarmSigner;
use crate::transport::{
    GHOST_BALANCE_LIMIT_PLUR, GHOST_BALANCE_PREWARM_DENOMINATOR, GHOST_BALANCE_PREWARM_NUMERATOR,
    PeerSession, PushOutcome, Transport, TransportError, is_connection_dead, peer_price,
};
use nectar_primitives::address::SwarmAddress;

const BUCKET_DEPTH: u8 = 16;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    #[error("dnsaddr: {0}")]
    DnsAddr(#[from] DnsAddrError),
    #[error("primitives: {0}")]
    Primitives(String),
    #[error("file: {0}")]
    File(String),
    #[error("store: {0}")]
    Store(#[from] ChunkStoreError),
    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("invalid hash length: {0}")]
    BadHashLen(usize),
    #[error("no peers: {0}")]
    NoPeers(String),
    #[error("invalid batch id length: {0}")]
    BadBatchLen(usize),
    /// Bee peers reject every chunk push with
    /// `invalid stamp: batchstore get: ... storage: not found`,
    /// meaning the postage batch isn't known on-chain (or has expired,
    /// or the per-chunk balance ran out under the price oracle). No
    /// number of retries against other peers will help — they all read
    /// from the same batchstore replication. We detect the first such
    /// response and abort the upload immediately so the user gets a
    /// clear error in seconds instead of MAX_CHUNK_RETRIES × 500 ms ×
    /// chunk_count of wasted retries.
    #[error("batch not on-chain or expired: {0}")]
    BatchNotFound(String),
    #[error("stamp: {0}")]
    Stamp(String),
    #[error("pusher: {0}")]
    Pusher(String),
    #[error("manifest: {0}")]
    Manifest(String),
    #[error("feed: {0}")]
    Feed(String),
    /// A chunk dispatch found only *shallow* pushsync receipts — every
    /// peer that answered forwarded the chunk but none inside the chunk's
    /// neighborhood-of-responsibility stored it (`proximity(storer, chunk)
    /// < storer.storage_radius`). A shallow receipt does NOT prove durable
    /// storage, so a chunk that only ever lands shallow is silently
    /// unretrievable later (the manifest resolves but the data 404/500s).
    ///
    /// This is a *retryable* error: the outer per-chunk retry loop
    /// re-dispatches the chunk across more peers / after pool churn (the
    /// neighborhood peer may be reachable on a later attempt). Only after
    /// the full `MAX_CHUNK_RETRIES` budget is exhausted does the dispatcher
    /// accept the deepest shallow as a last resort (mirroring bee's
    /// `maxPushErrors` give-up) rather than aborting the whole upload.
    #[error("shallow-only receipt (no neighborhood storer reached)")]
    ShallowOnly,
    /// Erasure-coded object could not be joined/reconstructed. This wraps a
    /// failure in the erasure-aware joiner (e.g. too many unretrievable data
    /// chunks even after pulling their RS parity siblings). Distinct from a
    /// plain fetch failure so the caller can tell "content genuinely
    /// unrecoverable right now" from "wrong join path".
    #[error("erasure: {0}")]
    Erasure(#[from] crate::erasure::ErasureError),
}

impl From<nectar_primitives::error::PrimitivesError> for ClientError {
    fn from(e: nectar_primitives::error::PrimitivesError) -> Self {
        Self::Primitives(e.to_string())
    }
}

impl From<nectar_primitives::file::FileError> for ClientError {
    fn from(e: nectar_primitives::file::FileError) -> Self {
        Self::File(e.to_string())
    }
}

/// Recognise bee's batchstore-not-found error so the dispatcher can
/// fast-fail an upload instead of running MAX_CHUNK_RETRIES against
/// every peer. The bee error message ends up wrapped as
/// `TransportError::Pushsync(PushsyncError::Peer("invalid stamp:
/// batchstore get: get batch <hex>: storage: not found, not found"))`.
/// We match on the two stable substrings (`batchstore get` + `storage:
/// not found`) — they straddle the batch hex and bee's internal error
/// chain formatting that could change between versions.
fn is_batch_not_found(e: &TransportError) -> bool {
    use crate::protocols::pushsync::PushsyncError;
    let TransportError::Pushsync(PushsyncError::Peer(msg)) = e else {
        return false;
    };
    msg.contains("batchstore get") && msg.contains("storage: not found")
}

/// Default number of peers raced in parallel per chunk fetch. Each peer
/// is given the full per-request timeout, but slow/dead peers no longer
/// block faster ones. Set to 1 to restore the legacy sequential behavior.
pub const DEFAULT_FETCH_CONCURRENCY: usize = 5;

/// How many DISTINCT chunks the file joiner pulls at once, given the per-chunk
/// peer-race width. This is the dominant throughput knob for a file body, and
/// is intentionally decoupled from (and larger than) the per-chunk race: once
/// the session pool is warm, a few forwarders serve many chunks in parallel, so
/// we want lots of chunks in flight rather than many redundant peer attempts on
/// each. Bounded so we don't blow past the warm pool's aggregate
/// `MAX_INFLIGHT_PER_SESSION` capacity or the single ws+yamux driver's budget.
pub fn joiner_concurrency(per_chunk_race: usize) -> usize {
    (per_chunk_race.saturating_mul(6)).clamp(24, 48)
}

/// Default number of peers dialed in parallel per discover round. Each
/// peer is held until bee finishes its gossip burst (~1 s typical;
/// capped at `wait_per_peer`); parallelising avoids 70-peer-round-2
/// dial chains taking `70 × ~1 s`.
pub const DEFAULT_DISCOVER_CONCURRENCY: usize = 16;

/// Callback invoked by the upload pipeline after each successful push.
/// Arguments are `(done, total)`. Cheap clone (`Arc`) so the same hook
/// can be shared across multiple concurrent uploads. Library is decoupled
/// from any specific UI: the CLI wires an `indicatif` progress bar in
/// here; programmatic users can plug in metrics counters / channels /
/// whatever they like.
pub type ProgressFn = std::sync::Arc<dyn Fn(usize, usize) + Send + Sync + 'static>;

/// What a single chunk's push actually achieved. Reported per chunk via
/// [`ChunkDoneFn`] so a relay can stream real acks (rather than one
/// batch-terminal verdict) and so the client scheduler has the receipt
/// quality it needs to decide whether routing choices matter at all
/// (docs/pusher-design.md §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushInfo {
    /// Proximity order between the chunk address and the peer whose
    /// receipt we accepted — how deep into the destination neighborhood
    /// the chunk actually landed. `0` when unknown (shallow accept).
    pub po: u8,
    /// Wall time from dispatch entry to receipt, in milliseconds.
    pub ms: u32,
    /// Proximity order of the *best* candidate the dispatcher had available
    /// for this chunk when it built its candidate list.
    ///
    /// Compared against [`Self::po`] this separates two very different
    /// explanations for chunks landing far from their neighborhood: if
    /// `best_po ≈ po` the pool simply doesn't contain a near peer (fix the
    /// pool), if `best_po ≫ po` the near peers existed but were skipped —
    /// at their in-flight cap, parked dead, or in dial cooldown (fix the
    /// dispatcher). Guessing between those two costs a lot of wasted work.
    pub best_po: u8,
    /// True when this chunk was accepted on a *shallow* receipt after the
    /// retry budget ran out: forwarded into the network, but no
    /// neighborhood storer confirmed it. Retrievability is not guaranteed.
    pub shallow: bool,
}

/// Callback invoked once per chunk as it resolves, with the chunk address
/// and either its [`PushInfo`] or a human-readable failure reason.
///
/// Distinct from [`ProgressFn`] (which only counts) because the pusher
/// relay has to name *which* chunks landed: `/v1/push` acks per chunk as
/// it lands, so a client re-dispatches only the chunks that actually
/// failed instead of re-pushing a whole 256-frame batch over one loss.
pub type ChunkDoneFn =
    std::sync::Arc<dyn Fn(&[u8; 32], Result<PushInfo, String>) + Send + Sync + 'static>;

/// A `ChunkGet` adapter that routes requests through libp2p retrieval to the
/// closest peers in a peerlist. Up to `concurrency` requests are raced in
/// parallel; whichever peer responds first with a valid chunk wins, and
/// the rest are dropped. If a peer fails, the next-closest candidate is
/// launched until either a success is observed or `max_retries` peers have
/// been exhausted.
#[derive(Clone)]
pub struct NetworkedStore<'a> {
    transport: &'a Transport,
    peers: &'a PeerStore,
    max_retries: usize,
    concurrency: usize,
    /// Process-local cache of chunks already fetched. Used by mantaray
    /// manifest decoding (which re-visits forks) and any composite call
    /// chain that touches a chunk more than once. Cheap (a HashMap +
    /// Mutex); chunks are at most 4 KiB so even tens of thousands of
    /// entries cost only single-digit MB.
    ///
    /// `Clone` shares the cache: pass a clone of the store to nectar's
    /// `join` and our manifest walkers and they'll reuse fetched chunks.
    /// Cached as **wire bytes** (`span_LE_8 || payload`) rather than a parsed
    /// `AnyChunk`: nectar cannot represent a bee erasure *parity* chunk, whose
    /// span is Reed–Solomon output rather than a length (see
    /// [`crate::erasure::wire_address`]). Keeping the delivered bytes makes the
    /// store the source of truth for both consumers — [`ChunkGet`] parses on
    /// demand, [`crate::erasure::WireGet`] takes the bytes as-is.
    cache: std::sync::Arc<std::sync::Mutex<HashMap<ChunkAddress, std::sync::Arc<Vec<u8>>>>>,
    /// Per-peer `PeerSession` cache shared across all of the joiner's
    /// concurrent chunk fetches for a single `fetch_bytes_ex` call.
    /// Without this, every chunk-level call to `Transport::fetch_chunk`
    /// would open a fresh libp2p connection to the same peer — for a
    /// 1407-chunk file fanned out by the joiner that's ~1407 concurrent
    /// dials to one Bee, which trips its connection / handshake limits
    /// and produces cascading timeouts. `Transport::fetch_chunk`'s doc
    /// explicitly says: "For multi-chunk workloads use `PeerSession`."
    /// Keyed by underlay multiaddr (stringified) so peers reachable via
    /// multiple underlays still get one session per actual connection.
    ///
    /// Each entry pairs the session with a `Semaphore` that caps concurrent
    /// in-flight fetches against that session at [`MAX_INFLIGHT_PER_SESSION`].
    /// Bee's `pkg/retrieval` enforces the same cap (their constant
    /// `IN_FLIGHT_CAP = 4`). Without this cap the joiner's parallel chunk
    /// fetches stack 16+ concurrent yamux substreams on one connection; bee
    /// tears them down mid-frame, producing
    /// `retrieval: frame: io: unexpected end of file`.
    sessions: std::sync::Arc<tokio::sync::Mutex<HashMap<String, CachedSession>>>,
    /// Cross-chunk peer scoreboard, shared (via `Clone`) across every
    /// `fetch_chunk_inner` call in a single fetch. Multi-MB objects are fanned
    /// out by the joiner into hundreds/thousands of per-chunk fetches; each one
    /// independently ranks candidates by proximity (closest-first). On a real
    /// hive-crawl pool the proximity-closest peers are *usually dead* (~86% of a
    /// 932-peer mainnet crawl never answer), so without shared memory every
    /// chunk re-pays a full sweep of 20 s timeouts re-discovering the handful of
    /// live forwarders. This scoreboard lets the *first* chunk's discovery
    /// benefit all the rest.
    ///
    /// Maps lowercased-hex overlay → reachability score:
    ///   score  > 0  → proven reachable forwarder → FRONT of the candidate queue
    ///   score == 0  → not yet tried / recovered   → middle (unknown)
    ///   score  < 0  → recently timed out / undialable → BACK of the queue
    /// A protocol-level response (delivery, or even "no peer found" — proof the
    /// peer is reachable and forwarding) bumps the score up; a timeout / dial
    /// failure decrements it. Crucially the score is NOT sticky in either
    /// direction: a known-good forwarder that we overload with 64-way fan-out
    /// until it starts timing out is gradually demoted (load rebalances onto
    /// other live peers), and a peer demoted by a transient blip climbs back as
    /// soon as it answers again. The score is clamped to a small band so
    /// recovery only takes a couple of responses. Empirically this is the
    /// difference between "1340 chunks time out at 0 bytes in 10 min" and
    /// "1340 chunks in ~90 s" on the same raw pool, and (with demotion) the
    /// difference between a 10k-chunk fetch stalling on a decaying peer set and
    /// completing.
    peer_scores: std::sync::Arc<std::sync::Mutex<HashMap<String, i32>>>,
}

/// A cached per-peer session for the retrieval path: a shared
/// [`PeerSession`] reused across the joiner's concurrent chunk fetches,
/// paired with the semaphore that caps its in-flight fetches at
/// [`MAX_INFLIGHT_PER_SESSION`].
type CachedSession = (
    std::sync::Arc<PeerSession>,
    std::sync::Arc<tokio::sync::Semaphore>,
);

/// Maximum concurrent fetches against a single `PeerSession`. Bee uses
/// `IN_FLIGHT_CAP = 4` per peer for fairness across many requesters, but a
/// read-only browser client pulls from a SCARCE set of warm forwarders — with
/// only a handful fast, a 4-cap leaves the joiner's chunks-in-flight starved
/// (effective throughput ≈ warm_forwarders × cap). 8 lets each good forwarder
/// serve more of the joiner's parallel chunks; each retrieval now closes its
/// substream promptly so this stays within yamux's per-connection budget.
const MAX_INFLIGHT_PER_SESSION: usize = 8;

/// Score a peer reaches (and is clamped to) on a protocol-level response.
/// Small so that a couple of consecutive timeouts demote a peer that has gone
/// bad, but positive enough to keep a healthy forwarder ahead of the unknowns.
const PEER_SCORE_MAX: i32 = 4;
/// Floor a peer is clamped to on repeated timeouts. Bounded so a peer that
/// timed out thousands of times early can still climb back to the front after
/// a couple of fresh responses, rather than being permanently buried.
const PEER_SCORE_MIN: i32 = -3;

/// Retrieval state that can persist *across* multiple fetches. A one-shot
/// CLI fetch builds the per-peer session cache and the cross-chunk peer
/// scoreboard from cold and throws them away on exit; a long-lived daemon
/// instead holds a single [`RetrievalCache`] and feeds it to every request
/// (via [`NetworkedStore::with_cache`]) so warm sessions and learned peer
/// scores carry over between downloads — the first request pays discovery,
/// every later one reuses the live forwarders. Cheap to clone (Arc bumps).
///
/// Note: only the session cache and the scoreboard are shared. The chunk
/// *content* cache is deliberately left per-fetch so a daemon's memory
/// doesn't grow without bound across unrelated downloads.
#[derive(Clone, Default)]
pub struct RetrievalCache {
    sessions: std::sync::Arc<tokio::sync::Mutex<HashMap<String, CachedSession>>>,
    peer_scores: std::sync::Arc<std::sync::Mutex<HashMap<String, i32>>>,
    /// Last resolved sequence index per feed (key = owner||topic hex). A feed's
    /// head only ever moves forward, so the previous resolution is a strong
    /// hint: the next lookup starts a short forward gallop from here instead of
    /// a full cold search. Steady-state (a daemon re-serving the same feed-
    /// backed site) this turns resolution into ~1 fast round.
    feed_index: std::sync::Arc<std::sync::Mutex<HashMap<String, u64>>>,
}

impl RetrievalCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Last known head index for a feed, if previously resolved.
    pub fn feed_hint(&self, key: &str) -> Option<u64> {
        self.feed_index.lock().unwrap().get(key).copied()
    }

    /// Record the resolved head index for a feed (monotonic: never moves back).
    pub fn set_feed_hint(&self, key: &str, index: u64) {
        let mut m = self.feed_index.lock().unwrap();
        let e = m.entry(key.to_string()).or_insert(0);
        if index > *e {
            *e = index;
        }
    }

    /// Export all known feed hints as `{ "<owner||topic hex>": <index>, … }`.
    /// Used by the browser daemon to persist hints to IndexedDB so a returning
    /// visitor anchors near the feed head instead of galloping from 0 (the
    /// difference between a ~1s warm resolve and a ~30s cold one).
    pub fn export_feed_hints(&self) -> HashMap<String, u64> {
        self.feed_index.lock().unwrap().clone()
    }

    /// Number of live (cached) per-peer retrieval sessions — i.e. forwarders we
    /// currently hold an open connection to. Unlike a peer-store count (peers we
    /// *know about*) or a dialable count (peers that *advertise* a /ws[s]
    /// underlay), this reflects connections actually established and reused for
    /// retrieval. Sessions are inserted on first connect and evicted on failure,
    /// so this tracks the warm forwarder set. Used by the browser daemon to show
    /// "connected peers" on the gateway status UI.
    ///
    /// Async because the session map is behind a `tokio::sync::Mutex`; awaiting
    /// the lock (rather than `try_lock`) avoids reporting a spurious 0 when a
    /// fetch momentarily holds it, which would flicker the polled status UI. The
    /// borrow is released immediately (no work held across the count).
    pub async fn connected_count(&self) -> usize {
        self.sessions.lock().await.len()
    }

    /// Proactively open retrieval sessions to dialable (ws/wss) peers so the
    /// warm forwarder set — and the `connected_count` the gateway surfaces — is
    /// non-zero *before* the first fetch. Without this, sessions only open
    /// lazily inside a fetch (see [`NetworkedStore::get_or_open_session`]), so a
    /// freshly-warmed daemon sits at "0 connected peers" until a site is loaded.
    ///
    /// Dials up to `target` peers that aren't already cached, capped at
    /// `target`, with a bounded in-flight window so a peerlist full of
    /// unreachable peers doesn't serialise on dial timeouts. Each successful
    /// session is inserted into the SAME shared `sessions` map a fetch reuses,
    /// so this both lights up the UI count AND pre-warms retrieval (the first
    /// fetch skips the connect for these peers). Best-effort: dial failures are
    /// logged to the reachability log and otherwise ignored. Returns the number
    /// of sessions now cached.
    ///
    /// `target` is the desired TOTAL session count; if the cache already holds
    /// that many we open none. Sessions that later die are evicted by the
    /// fetch path (`ConnectionClosed`), so re-calling this on the daemon's
    /// maintenance tick tops the pool back up.
    pub async fn prewarm(&self, transport: &Transport, peers: &PeerStore, target: usize) -> usize {
        use futures::stream::{FuturesUnordered, StreamExt};

        // Already at/above target — nothing to open.
        let already: std::collections::HashSet<String> = {
            let guard = self.sessions.lock().await;
            if guard.len() >= target {
                return guard.len();
            }
            guard.keys().cloned().collect()
        };
        let want = target.saturating_sub(already.len());
        if want == 0 {
            return already.len();
        }

        // Candidate underlays: dialable peers we don't already hold a session
        // to. `first_dialable_underlay` is ws-only on wasm, so this naturally
        // restricts to browser-dialable peers.
        let mut candidates: Vec<Multiaddr> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for peer in peers.iter() {
            if let Some(ua) = peer.first_dialable_underlay() {
                let key = ua.to_string();
                if already.contains(&key) || !seen.insert(key) {
                    continue;
                }
                candidates.push(ua);
            }
        }
        if candidates.is_empty() {
            return already.len();
        }

        // Dial with a bounded in-flight window. We try more candidates than
        // `want` because mainnet ws peers are flaky; stop once we reach the
        // target session count or the candidate list is exhausted.
        let parallelism = SESSION_DIAL_PARALLELISM.min(candidates.len());
        let mut iter = candidates.into_iter();
        let mut inflight = FuturesUnordered::new();
        let dial = |underlay: Multiaddr| async move {
            let res = PeerSession::connect(transport, &underlay).await;
            (underlay, res)
        };
        for _ in 0..parallelism {
            match iter.next() {
                Some(u) => inflight.push(dial(u)),
                None => break,
            }
        }

        while let Some((underlay, res)) = inflight.next().await {
            if let Ok(session) = res {
                let session_arc = std::sync::Arc::new(session);
                let sem_arc =
                    std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_PER_SESSION));
                let mut guard = self.sessions.lock().await;
                if guard.len() < target {
                    guard
                        .entry(underlay.to_string())
                        .or_insert_with(|| (session_arc, sem_arc));
                }
            }
            // Stop once we've reached the target; otherwise refill the window.
            let have = self.sessions.lock().await.len();
            if have >= target {
                break;
            }
            if let Some(u) = iter.next() {
                inflight.push(dial(u));
            }
        }
        self.sessions.lock().await.len()
    }

    /// Merge persisted feed hints back in (monotonic — never lowers a hint).
    pub fn import_feed_hints(&self, hints: HashMap<String, u64>) {
        let mut m = self.feed_index.lock().unwrap();
        for (k, v) in hints {
            let e = m.entry(k).or_insert(0);
            if v > *e {
                *e = v;
            }
        }
    }
}

impl<'a> NetworkedStore<'a> {
    /// Construct a store with sequential fetch (concurrency = 1).
    pub fn new(transport: &'a Transport, peers: &'a PeerStore, max_retries: usize) -> Self {
        Self {
            transport,
            peers,
            max_retries,
            concurrency: 1,
            cache: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
            sessions: std::sync::Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            peer_scores: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Construct a store that races up to `concurrency` peers in parallel
    /// per chunk. `concurrency` is clamped to at least 1.
    pub fn with_concurrency(
        transport: &'a Transport,
        peers: &'a PeerStore,
        max_retries: usize,
        concurrency: usize,
    ) -> Self {
        Self {
            transport,
            peers,
            max_retries,
            concurrency,
            cache: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
            sessions: std::sync::Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            peer_scores: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Like [`Self::with_concurrency`] but reuses the session cache and
    /// peer scoreboard from a shared [`RetrievalCache`] instead of
    /// starting cold. Used by the daemon so warm sessions and learned
    /// peer scores persist across fetch requests. The chunk content
    /// cache is still per-store (see [`RetrievalCache`] docs).
    pub fn with_cache(
        transport: &'a Transport,
        peers: &'a PeerStore,
        max_retries: usize,
        concurrency: usize,
        cache: &RetrievalCache,
    ) -> Self {
        Self {
            transport,
            peers,
            max_retries,
            concurrency,
            cache: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
            sessions: cache.sessions.clone(),
            peer_scores: cache.peer_scores.clone(),
        }
    }
}

impl<'a> NetworkedStore<'a> {
    /// Return a cached `PeerSession` for this underlay, opening (and
    /// caching) one if none exists yet. Multi-chunk workloads MUST share
    /// sessions across chunks to a peer — see the `sessions` field
    /// rationale on [`NetworkedStore`]. Concurrent first-time callers
    /// for the same peer may both connect (the second's session is
    /// dropped on insert via `or_insert_with`); one wasted dial is
    /// preferable to holding the cache lock across a multi-second
    /// `PeerSession::connect`.
    async fn get_or_open_session(
        &self,
        underlay: &Multiaddr,
    ) -> Result<CachedSession, TransportError> {
        let key = underlay.to_string();
        {
            let guard = self.sessions.lock().await;
            if let Some((s, sem)) = guard.get(&key) {
                return Ok((s.clone(), sem.clone()));
            }
        }
        // Not cached — connect without holding the lock.
        let session = PeerSession::connect(self.transport, underlay).await?;
        let session_arc = std::sync::Arc::new(session);
        let sem_arc = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_PER_SESSION));
        let mut guard = self.sessions.lock().await;
        let entry = guard
            .entry(key)
            .or_insert_with(|| (session_arc.clone(), sem_arc.clone()));
        Ok((entry.0.clone(), entry.1.clone()))
    }
}

impl<'a> NetworkedStore<'a> {
    /// Record that a peer answered at the protocol level this fetch (delivery
    /// or "no peer found"). Bumps its score toward [`PEER_SCORE_MAX`] so it
    /// sorts ahead of unknown/dead peers for every later chunk. A peer
    /// previously demoted by timeouts recovers to the front after a couple of
    /// responses (the `+2` step crosses zero from the `PEER_SCORE_MIN` floor in
    /// two hits).
    fn note_response(&self, overlay: &str) {
        let o = overlay.to_lowercase();
        let mut m = self.peer_scores.lock().unwrap();
        let e = m.entry(o).or_insert(0);
        *e = (*e + 2).clamp(1, PEER_SCORE_MAX);
    }

    /// Record that a peer timed out / failed to dial this fetch. Decrements its
    /// score toward [`PEER_SCORE_MIN`]; once it goes negative the peer sorts to
    /// the back so no further chunk leads with it. Not sticky: a healthy
    /// forwarder we overload until it times out is demoted gradually (load
    /// shifts to other live peers) and climbs back when it answers again.
    fn note_timeout(&self, overlay: &str) {
        let o = overlay.to_lowercase();
        let mut m = self.peer_scores.lock().unwrap();
        let e = m.entry(o).or_insert(0);
        *e = (*e - 1).max(PEER_SCORE_MIN);
    }

    // (validate_delivery / parse_delivery are free fns defined below the impl)

    /// Body of [`ChunkGet::get`]: retrieve, then parse into a nectar chunk.
    /// Pulled into a private helper so the `ChunkGet` impl can be split
    /// per-target: native uses `async fn`, wasm wraps in `SendWrapper` to
    /// satisfy the trait's `+ Send` bound.
    async fn fetch_chunk_inner(
        &self,
        address: ChunkAddress,
    ) -> Result<AnyChunk<DEFAULT_BODY_SIZE>, ChunkStoreError> {
        let wire = self.fetch_wire_inner(address).await?;
        parse_delivery(&wire, &address).ok_or_else(|| {
            // Reachable only for a bee erasure parity chunk, which nectar's
            // types cannot hold (its span is RS output, not a length). Those
            // are fetched through `WireGet` instead; the plain joiner and the
            // manifest walker never ask for one.
            ChunkStoreError::Other(
                "chunk is not representable as a nectar chunk (parity chunk?)"
                    .to_string()
                    .into(),
            )
        })
    }

    /// Retrieve a chunk's validated **wire bytes**, racing peers as described
    /// on [`NetworkedStore`]. This is the real retrieval loop;
    /// [`Self::fetch_chunk_inner`] is a parsing façade over it.
    async fn fetch_wire_inner(
        &self,
        address: ChunkAddress,
    ) -> Result<std::sync::Arc<Vec<u8>>, ChunkStoreError> {
        use futures::stream::{FuturesUnordered, StreamExt};

        // Cache hit: skip the entire network round-trip. Manifest decode
        // re-fetches the root multiple times during `walk_manifest` and
        // `lookup_manifest_path`; BMT joins re-visit intermediate nodes.
        if let Some(c) = self.cache.lock().unwrap().get(&address).cloned() {
            return Ok(c);
        }

        // L2 hit: persistent IndexedDB chunk cache (browser only). Chunks are
        // immutable + content-addressed, so a stored copy is reusable across
        // fetches and sessions. Re-verify the BMT address on read-back so a
        // corrupted/tampered store can never inject a bad chunk.
        //
        // The L2 lookup is best-effort and MUST NOT gate retrieval: under a
        // non-cross-origin-isolated context the wasm-bindgen-rayon thread pool
        // fails to init (`initThreadPool` errors) and the build runs single-
        // threaded, where the `indexed-db` crate's transaction future can stall
        // and never resolve — wedging the whole fetch *before* a single peer is
        // tried (no `candidate peers` log, nothing stored). Bound the read with
        // a short timeout: a hit still short-circuits the network, but a stalled
        // IndexedDB op falls through to retrieval instead of hanging forever.
        #[cfg(target_arch = "wasm32")]
        if let Some(store) = crate::idb_chunk_store::get_store().await {
            use futures::future::Either;
            let key = hex::encode(address.as_bytes());
            let get_fut = std::pin::pin!(store.get(key));
            let timeout = std::pin::pin!(futures_timer::Delay::new(Duration::from_secs(2)));
            let maybe_wire = match futures::future::select(get_fut, timeout).await {
                Either::Left((wire, _)) => wire,
                Either::Right((_, _)) => None, // L2 read stalled — fall through to network
            };
            if let Some(wire) = maybe_wire {
                if validate_delivery(&wire, &address) {
                    let wire = std::sync::Arc::new(wire);
                    self.cache.lock().unwrap().insert(address, wire.clone());
                    crate::idb_chunk_store::note_hit();
                    return Ok(wire);
                }
            }
        }

        let mut bytes32 = [0u8; 32];
        bytes32.copy_from_slice(address.as_bytes());

        // Consider ALL peers in the peerstore, ordered by proximity to the
        // chunk address. Bee's retrieval protocol forwards requests through
        // the receiving peer's kademlia table to the chunk's neighborhood,
        // so even far peers can yield a result — but closest-first still
        // wins on average because nearby peers are more likely to have the
        // chunk locally and skip the forwarding cost.
        //
        // Peers that recently failed to dial (per `peers.json`'s reachability
        // cache) are pushed to the back of the candidate list so we don't
        // waste timeouts on known-dead peers up front.
        //
        // `max_retries == 0` means "no cap"; otherwise it bounds the number
        // of peer attempts before giving up.
        let now = crate::peers::now_unix();
        // Proximity-ordered candidate list (closest to the chunk address first).
        // Bee's retrieval *forwards* a request through the receiving peer's
        // kademlia table toward the chunk's neighborhood, so any reachable
        // forwarder can ultimately serve any chunk — but a peer closer to the
        // chunk is more likely to hold it locally (or be one hop from it), so
        // proximity is the right *secondary* signal.
        let mut candidates: Vec<&Peer> = self.peers.closest(&address, usize::MAX);
        if candidates.is_empty() {
            return Err(ChunkStoreError::Other(
                "no peers in peerlist".to_string().into(),
            ));
        }
        let dialable = candidates
            .iter()
            .filter(|p| p.first_dialable_underlay().is_some())
            .count();
        info!(
            target: "hoverfly::fetch",
            "chunk {}: {} candidate peers ({} with a dialable /ws[s] underlay)",
            hex::encode(&address.as_bytes()[..4]),
            candidates.len(),
            dialable,
        );

        // Order candidates so the concurrency window is filled with peers we can
        // ACTUALLY reach and that we've SEEN forward, before anything else. The
        // previous ordering was proximity-first with reachability/score only as
        // a tie-breaker, which on mainnet meant the window filled with the
        // closest peers — overwhelmingly TCP-only (not browser-dialable) or
        // dead — so a `/ws`-only browser node burned its whole per-peer timeout
        // budget on peers it could never use and never reached a live forwarder
        // (observed: hundreds of `peer … failed: timeout`, 0 chunks).
        //
        // Sort key is `(reachability_class, forwarder_class)`; proximity
        // (already encoded in `candidates`' order) is preserved within each
        // bucket by the stable sort. Lower = tried sooner.
        //
        // reachability class:
        //   0 — proven forwarder this fetch (score > 0) AND dialable
        //   1 — dialable, not-yet-tried/recovered, not recently-unreachable
        //   2 — dialable but recently failed to dial (worth a late retry)
        //   3 — dialable but score < 0 (timed out for an earlier chunk)
        //   4 — NOT browser-dialable (only usable natively over TCP) — last
        //
        // forwarder class (within a reachability bucket): only FULL nodes
        // forward retrieval toward the chunk's neighborhood; light nodes answer
        // only from their own reserve, so a far-from-chunk light node almost
        // never has it and just burns a timeout. Prefer known full nodes, then
        // unknown (not yet probed), then known-light:
        //   0 — full_node == Some(true)
        //   1 — full_node == None (unknown)
        //   2 — full_node == Some(false) (light)
        //
        // On native (TCP) every peer is dialable so the non-dialable bucket is
        // empty and behaviour is proximity+forwarder within classes 0-3; in the
        // browser the non-dialable wall is shoved to the very back where it
        // can't starve the concurrency window of reachable forwarders.
        {
            let scores = self.peer_scores.lock().unwrap();
            candidates.sort_by_key(|p| {
                let dialable = p.first_dialable_underlay().is_some();
                let reach = if !dialable {
                    4u8
                } else {
                    let score = scores.get(&p.overlay.to_lowercase()).copied().unwrap_or(0);
                    if score > 0 {
                        0
                    } else if score < 0 {
                        3
                    } else if p.is_recently_unreachable(now) {
                        2
                    } else {
                        1
                    }
                };
                let forwarder = match p.full_node {
                    Some(true) => 0u8,
                    None => 1,
                    Some(false) => 2,
                };
                (reach, forwarder)
            });
        }
        let attempt_cap = if self.max_retries == 0 {
            candidates.len()
        } else {
            self.max_retries.min(candidates.len())
        };

        let concurrency = self.concurrency.max(1);

        // Per-attempt outcome — `Deferred` is distinct from `Failed` so the
        // dispatcher can re-queue the peer for retry rather than marking it as
        // having failed for *this chunk*. Without this distinction the loop
        // treats a per-peer dial-cooldown rejection as if the peer couldn't
        // serve the chunk at all, which is wrong: it's just a "try me later"
        // signal from another concurrent dispatch claiming the dial window.
        enum AttemptOutcome<C> {
            Got(C),
            Deferred,
            Failed(String),
        }

        // VecDeque so DialTooSoon-deferred peers can be re-queued at the back
        // instead of being treated as a peer failure. Tier 1 of the retrieval-
        // loop port (mirroring Bee's `pkg/retrieval` semantics): the keystone
        // fix for the cooldown-as-failure thrash hoverfly hits against post-2.8
        // mainnet (~37 `dial too soon` rejections/sec, 0 chunks retrieved).
        use std::collections::{HashMap, HashSet, VecDeque};
        let all_candidates: Vec<&Peer> = candidates.into_iter().take(attempt_cap).collect();
        let mut deque: VecDeque<&Peer> = all_candidates.iter().copied().collect();
        let initial_deque_len = deque.len();

        // Per-chunk skiplist of recently-failed peers — Tier 2 of the
        // retrieval-loop port. Mirrors Bee's `errSkip` from
        // `pkg/retrieval/retrieval.go:80,277-280` with the same 60-second
        // expiry. A peer that returned `storage: not found` (or any non-Deferred
        // failure) for *this chunk* is parked here for `skiplist_dur`; after
        // that the deque is refilled with re-eligible candidates so they get a
        // second chance (the peer's local state may have changed in the
        // meantime — fresh pushsync, neighborhood replay, etc.).
        let skiplist_dur = Duration::from_secs(60);
        let mut skiplist: HashMap<String, web_time::Instant> = HashMap::new();

        // Build a future that performs a single peer fetch and returns a
        // structured result. Captures peer metadata for logging and feeds
        // dial-result observations into the transport's reachability log.
        let log = self.transport.reachability_log().clone();
        let try_peer = |peer: &'a Peer| {
            let overlay = peer.overlay.clone();
            let underlay = peer.first_dialable_underlay();
            let log = log.clone();
            async move {
                let Some(underlay) = underlay else {
                    return (
                        peer,
                        overlay,
                        AttemptOutcome::Failed("no dialable underlay".to_string()),
                    );
                };
                let started = web_time::Instant::now();
                // Reuse a cached PeerSession for this peer across all of the
                // joiner's chunk requests (`Transport::fetch_chunk` doc — "For
                // multi-chunk workloads use `PeerSession`"). Falls back to `Deferred` /
                // `Failed` for the connect-time errors the original
                // `Transport::fetch_chunk` would have surfaced.
                let mut peer_full_node: Option<bool> = None;
                let res = match self.get_or_open_session(&underlay).await {
                    Ok((session, sem)) => {
                        // Record the peer's advertised node mode (full vs light)
                        // so a successful dial can persist it — full nodes
                        // forward retrieval, light nodes only serve local reserve.
                        peer_full_node = Some(session.peer_full_node());
                        // Cap concurrent fetches against this session to
                        // [`MAX_INFLIGHT_PER_SESSION`] (Bee's `IN_FLIGHT_CAP`).
                        // The permit is dropped at end of this block, releasing
                        // capacity for the next chunk waiting on the same peer.
                        let _permit = match sem.acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => {
                                // Semaphore closed (shouldn't happen unless
                                // cache was wiped mid-flight). Treat as
                                // transient and let the loop retry.
                                return (peer, overlay, AttemptOutcome::Deferred);
                            }
                        };
                        session.fetch_chunk(&bytes32).await
                    }
                    Err(e) => Err(e),
                };
                // If the session died (peer closed the connection, driver
                // task exited), evict it from the cache so the next fetch on
                // this peer reconnects. The caller treats `ConnectionClosed`
                // as `Deferred` (below) so the peer is requeued, not
                // skiplisted — by the time we re-dial, the new session will
                // be live.
                if matches!(res, Err(TransportError::ConnectionClosed)) {
                    let mut g = self.sessions.lock().await;
                    g.remove(&underlay.to_string());
                }
                let rtt_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
                match res {
                    Ok(delivery) => {
                        log.lock().unwrap().insert(
                            overlay.to_lowercase(),
                            crate::peers::DialResult::Success {
                                rtt_ms,
                                full_node: peer_full_node,
                            },
                        );
                        // Proven reachable forwarder — promote for every later
                        // chunk this fetch (see `peer_scores` field rationale).
                        self.note_response(&overlay);
                        // The delivered bytes are either a content-addressed
                        // chunk (CAC, address = BMT hash of data) or a single-
                        // owner chunk (SOC, address = keccak256(id||owner)).
                        // Feed updates are SOCs, whose address is NOT the BMT
                        // hash — so validating every delivery as a CAC rejects
                        // them ("address mismatch"). Try CAC first (the common
                        // case), then fall back to SOC, accepting whichever
                        // validates against the requested address.
                        if validate_delivery(&delivery.data, &address) {
                            (peer, overlay, AttemptOutcome::Got(delivery.data))
                        } else {
                            (
                                peer,
                                overlay,
                                AttemptOutcome::Failed("address mismatch".to_string()),
                            )
                        }
                    }
                    // DialTooSoon = another concurrent fetch claimed this peer's
                    // dial window. Transient deferral — re-queue the peer; do
                    // NOT record `DialResult::Failure` (it'd poison the peer's
                    // long-term reachability score) and do NOT log a warn (it
                    // produces a firehose of noise at ~37/sec under
                    // multi-chunk concurrency).
                    Err(TransportError::DialTooSoon { .. }) => {
                        (peer, overlay, AttemptOutcome::Deferred)
                    }
                    // Connection closed mid-fetch (e.g. bee closed our session
                    // after some quota / yamux state hit a limit). The session
                    // has already been evicted above; treating as `Deferred`
                    // requeues the peer for an immediate retry, which will
                    // open a fresh session. Skiplisting would penalise a peer
                    // that is otherwise serving us fine.
                    Err(TransportError::ConnectionClosed) => {
                        (peer, overlay, AttemptOutcome::Deferred)
                    }
                    Err(e) => {
                        log.lock()
                            .unwrap()
                            .insert(overlay.to_lowercase(), crate::peers::DialResult::Failure);
                        // Classify for the cross-chunk scoreboard. A `Retrieval`
                        // error means the peer answered at the protocol level
                        // (e.g. "no peer found") — it's a reachable forwarder
                        // that just lacked *this* chunk, so promote it (it may
                        // serve a different chunk). `Timeout` / `DialFailed`
                        // mean the peer is unreachable — demote so no other
                        // chunk wastes a timeout on it.
                        match &e {
                            TransportError::Retrieval(_) => self.note_response(&overlay),
                            TransportError::Timeout | TransportError::DialFailed(_) => {
                                self.note_timeout(&overlay)
                            }
                            _ => {}
                        }
                        (peer, overlay, AttemptOutcome::Failed(e.to_string()))
                    }
                }
            }
        };

        let mut inflight = FuturesUnordered::new();
        // Seed the initial window.
        for _ in 0..concurrency {
            if let Some(peer) = deque.pop_front() {
                inflight.push(try_peer(peer));
            } else {
                break;
            }
        }

        let mut last_err = String::from("no peers tried");
        let mut failed_attempts: usize = 0;
        // If the entire candidate set has cycled as `Deferred` without any
        // making real progress (no `Got`/`Failed`), every peer is in cooldown.
        // Sleep briefly so cooldowns can elapse rather than spinning. Mirrors
        // Bee's `overDraftRefresh = 600 ms` sleep when all peers are blocked.
        let cycle_threshold = initial_deque_len
            .saturating_add(concurrency)
            .saturating_add(1);
        let mut consecutive_deferrals: usize = 0;

        loop {
            // No work left in flight. Try to refill the deque with skiplisted
            // peers whose 60-second cooldown has elapsed (Tier 2). If the
            // skiplist is empty we've truly exhausted the pool with no live
            // entries to wait on; return the last error.
            if inflight.is_empty() && deque.is_empty() {
                let now = web_time::Instant::now();
                skiplist.retain(|_, expiry| *expiry > now);
                if skiplist.is_empty() {
                    break;
                }
                // Sleep to the earliest live skiplist expiry, then refill from
                // all_candidates whose entries have aged out. This is the
                // partner mechanism to Tier 1's cycle-sleep: instead of giving
                // up after one pass through the pool, we wait for failed peers
                // to become eligible again (their local state — pushsync,
                // neighborhood replay, network recovery — may have changed).
                let earliest = skiplist.values().min().copied().unwrap_or(now);
                if earliest > now {
                    tokio::time::sleep(earliest.saturating_duration_since(now)).await;
                }
                let now = web_time::Instant::now();
                skiplist.retain(|_, expiry| *expiry > now);
                let still_skipped: HashSet<String> = skiplist.keys().cloned().collect();
                for peer in all_candidates.iter() {
                    if !still_skipped.contains(&peer.overlay.to_lowercase()) {
                        deque.push_back(*peer);
                    }
                }
                // Re-seed inflight from the refilled deque.
                for _ in 0..concurrency {
                    if let Some(p) = deque.pop_front() {
                        inflight.push(try_peer(p));
                    } else {
                        break;
                    }
                }
                if inflight.is_empty() {
                    // Couldn't refill (skiplist entries kept all candidates out).
                    break;
                }
            }
            let Some((peer, overlay, outcome)) = inflight.next().await else {
                // inflight became empty between checks — re-enter the refill
                // branch on the next iteration.
                continue;
            };
            match outcome {
                AttemptOutcome::Got(wire) => {
                    let wire = std::sync::Arc::new(wire);
                    self.cache.lock().unwrap().insert(address, wire.clone());
                    // Write-back to the persistent L2 (browser). Fire-and-forget
                    // so the IndexedDB write never blocks retrieval — the chunk
                    // is already in L1 for this session. `get_store()` is awaited
                    // INSIDE the spawned task so the per-thread handle is opened
                    // on whichever worker thread runs the task (it's thread-
                    // affine; see idb_chunk_store's threading note).
                    #[cfg(target_arch = "wasm32")]
                    {
                        let key = hex::encode(address.as_bytes());
                        let bytes = wire.as_ref().clone();
                        wasm_bindgen_futures::spawn_local(async move {
                            if let Some(store) = crate::idb_chunk_store::get_store().await {
                                store.put(key, bytes).await;
                            }
                        });
                    }
                    return Ok(wire);
                }
                AttemptOutcome::Deferred => {
                    // Transient: do not log, do not record failure, requeue.
                    deque.push_back(peer);
                    consecutive_deferrals = consecutive_deferrals.saturating_add(1);
                    if consecutive_deferrals >= cycle_threshold {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        consecutive_deferrals = 0;
                    }
                }
                AttemptOutcome::Failed(e) => {
                    failed_attempts = failed_attempts.saturating_add(1);
                    // Per-peer fetch failures (timeout, `storage: not found`,
                    // dead dial) are ROUTINE on a light client whose requests are
                    // forwarded through the network — most peers tried for a
                    // chunk won't have it locally. Logging each at WARN floods
                    // the terminal and shreds the progress bar, so it's `debug!`
                    // (visible with `-d`). The chunk still succeeds via another
                    // peer, or (for erasure-coded content) is reconstructed from
                    // parity; a genuinely unrecoverable chunk surfaces as the
                    // returned error, not this line.
                    debug!(target: "hoverfly::fetch", "peer {} failed: {}", overlay, e);
                    last_err = e;
                    consecutive_deferrals = 0;
                    // Tier 2: park failed peer in per-chunk skiplist.
                    skiplist.insert(
                        overlay.to_lowercase(),
                        web_time::Instant::now() + skiplist_dur,
                    );
                }
            }
            if let Some(next) = deque.pop_front() {
                inflight.push(try_peer(next));
            }
        }
        // A whole chunk that no peer could serve is expected under erasure
        // coding: the erasure joiner deliberately lets some data chunks fail and
        // reconstructs them from the node's parity siblings. So this is `debug!`
        // too — the joiner decides whether it's actually fatal (and returns an
        // error if the node is unrecoverable). `-d` shows it.
        debug!(
            target: "hoverfly::fetch",
            "chunk {}: all peers failed after {} attempt(s) of {} candidates; last error: {}",
            hex::encode(&address.as_bytes()[..4]),
            failed_attempts,
            initial_deque_len,
            last_err,
        );
        Err(ChunkStoreError::Other(
            format!(
                "all peers failed ({failed_attempts}/{initial_deque_len} attempted): {last_err}"
            )
            .into(),
        ))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<'a> ChunkGet<DEFAULT_BODY_SIZE> for NetworkedStore<'a> {
    type Error = ChunkStoreError;

    async fn get(
        &self,
        address: &ChunkAddress,
    ) -> Result<AnyChunk<DEFAULT_BODY_SIZE>, Self::Error> {
        self.fetch_chunk_inner(*address).await
    }
}

#[cfg(target_arch = "wasm32")]
impl<'a> ChunkGet<DEFAULT_BODY_SIZE> for NetworkedStore<'a> {
    type Error = ChunkStoreError;

    async fn get(
        &self,
        address: &ChunkAddress,
    ) -> Result<AnyChunk<DEFAULT_BODY_SIZE>, Self::Error> {
        self.fetch_chunk_inner(*address).await
    }
}

/// Raw-bytes view of the store, for the erasure joiner. Same retrieval loop,
/// same caches — it just skips the nectar parse that a parity chunk can't
/// survive (see [`validate_delivery`]).
impl<'a> NetworkedStore<'a> {
    /// Seed the content cache with a chunk we obtained by other means.
    ///
    /// Used when the root is recovered from a dispersed replica: the bytes are
    /// the root's, but they arrived under the replica's address, so nothing has
    /// them filed under the root. Seeding lets whichever joiner runs next find
    /// the root for free instead of re-issuing the fetch that just failed.
    ///
    /// The caller is responsible for having verified the bytes hash to
    /// `address` (see `erasure::replicas::recover_root`).
    fn seed_wire(&self, address: ChunkAddress, wire: Vec<u8>) {
        self.cache
            .lock()
            .unwrap()
            .insert(address, std::sync::Arc::new(wire));
    }
}

impl<'a> crate::erasure::WireGet for NetworkedStore<'a> {
    type Error = ChunkStoreError;

    async fn get_wire(&self, address: &ChunkAddress) -> Result<Vec<u8>, Self::Error> {
        self.fetch_wire_inner(*address)
            .await
            .map(|w| w.as_ref().clone())
    }
}

/// Discover peers by dialing a bootstrap multiaddr (or `/dnsaddr/...`) and
/// listening on the hive stream. Equivalent to a single-hop discover.
pub async fn discover(
    transport: &Transport,
    doh: &Doh,
    bootstrap: &Multiaddr,
    wait: Duration,
) -> Result<Vec<Peer>, ClientError> {
    discover_recursive(transport, doh, bootstrap, wait, 1).await
}

/// Recursively discover peers up to `max_rounds` hops out from
/// `bootstrap`. Each round, every newly-found peer is itself dialed and
/// asked for its hive — building up a much larger peerset that spans
/// more of the swarm address space.
///
/// Uses [`DEFAULT_DISCOVER_CONCURRENCY`] parallel dials per round; for a
/// custom value use [`discover_recursive_with_concurrency`].
pub async fn discover_recursive(
    transport: &Transport,
    doh: &Doh,
    bootstrap: &Multiaddr,
    wait_per_peer: Duration,
    max_rounds: usize,
) -> Result<Vec<Peer>, ClientError> {
    discover_recursive_with_concurrency(
        transport,
        doh,
        bootstrap,
        wait_per_peer,
        max_rounds,
        DEFAULT_DISCOVER_CONCURRENCY,
    )
    .await
}

/// Like [`discover_recursive`], but with an explicit per-round
/// concurrency cap. `concurrency` controls how many peers are dialed in
/// parallel; each dial holds the hive stream open until bee finishes
/// its gossip burst (~1 s typical) or `wait_per_peer` elapses, whichever
/// comes first. With 70 peers in a round and `concurrency=16`, the
/// round completes in roughly `ceil(70/16) × ~1 s` rather than
/// `70 × ~1 s`.
pub async fn discover_recursive_with_concurrency(
    transport: &Transport,
    doh: &Doh,
    bootstrap: &Multiaddr,
    wait_per_peer: Duration,
    max_rounds: usize,
    concurrency: usize,
) -> Result<Vec<Peer>, ClientError> {
    discover_recursive_with_progress(
        transport,
        doh,
        bootstrap,
        wait_per_peer,
        max_rounds,
        concurrency,
        None,
    )
    .await
}

/// Progress callback emitted by [`discover_recursive_with_progress`].
/// The CLI uses this to surface per-round progress to stdout without
/// requiring `--verbose`. Stable enough across rounds to drive a
/// simple `println!`; not stable enough that downstream tooling
/// should pattern-match on its exact wording.
pub type DiscoverProgressFn = std::sync::Arc<dyn Fn(DiscoverEvent) + Send + Sync + 'static>;

/// One progress event during a recursive discover.
#[derive(Debug, Clone)]
pub enum DiscoverEvent {
    /// A new round is about to begin.
    RoundStarted {
        round: usize,
        total_rounds: usize,
        frontier_size: usize,
        total_peers_so_far: usize,
    },
    /// A round just completed.
    RoundFinished {
        round: usize,
        total_rounds: usize,
        new_peers_this_round: usize,
        total_peers: usize,
    },
}

pub async fn discover_recursive_with_progress(
    transport: &Transport,
    doh: &Doh,
    bootstrap: &Multiaddr,
    wait_per_peer: Duration,
    max_rounds: usize,
    concurrency: usize,
    progress: Option<DiscoverProgressFn>,
) -> Result<Vec<Peer>, ClientError> {
    use futures::stream::{FuturesUnordered, StreamExt};
    use std::collections::HashSet;

    let resolved = resolve(bootstrap, doh).await?;
    if resolved.is_empty() {
        return Err(ClientError::NoPeers(format!(
            "no ws/wss multiaddrs from {bootstrap}"
        )));
    }

    let concurrency = concurrency.max(1);
    let mut all: Vec<Peer> = Vec::new();
    let mut seen_overlays: HashSet<String> = HashSet::new();
    let mut frontier: Vec<Multiaddr> = resolved;

    for round in 0..max_rounds {
        if frontier.is_empty() {
            break;
        }
        info!(target: "hoverfly::discover",
            "round {} of {}: dialing {} peer(s) ({} in parallel)",
            round + 1, max_rounds, frontier.len(), concurrency);
        if let Some(p) = progress.as_ref() {
            p(DiscoverEvent::RoundStarted {
                round: round + 1,
                total_rounds: max_rounds,
                frontier_size: frontier.len(),
                total_peers_so_far: all.len(),
            });
        }
        let peers_before_round = all.len();

        let mut next_frontier: Vec<Multiaddr> = Vec::new();
        let mut iter = std::mem::take(&mut frontier).into_iter();
        let mut inflight = FuturesUnordered::new();

        // Closure-as-fn (rather than an outer fn) keeps the borrow of
        // `transport` clean and produces a single async-block type so
        // FuturesUnordered can hold them all.
        let dial = |ma: Multiaddr| async move {
            debug!(target: "hoverfly::discover", "dialing {}", ma);
            let res = transport.discover_peers(&ma, wait_per_peer).await;
            (ma, res)
        };

        // Seed initial window.
        for _ in 0..concurrency {
            let Some(ma) = iter.next() else { break };
            inflight.push(dial(ma));
        }

        while let Some((ma, res)) = inflight.next().await {
            match res {
                Ok(batch) => {
                    debug!(target: "hoverfly::discover",
                        "{} returned {} peers", ma, batch.len());
                    for mut p in batch {
                        // Drop underlays we can never dial end-to-end: private
                        // (RFC1918), loopback, link-local, CGNAT, etc. Bee hive
                        // gossip routinely includes a node's *internal* address
                        // (e.g. a k8s pod `10.233.x.x`) alongside its public
                        // one; keeping the private underlay only wastes a full
                        // dial-timeout later. Filtering here keeps both the
                        // native and wasm peerstores (and any `-o` dump) clean.
                        let before = p.underlays.len();
                        p.underlays.retain(|u| !crate::peers::has_unroutable_ip4(u));
                        if p.underlays.len() != before {
                            debug!(target: "hoverfly::discover",
                                "peer {}: dropped {} unroutable underlay(s)",
                                &p.overlay[..p.overlay.len().min(8)],
                                before - p.underlays.len());
                        }
                        // A peer with no routable underlay left is useless to us.
                        if p.underlays.is_empty() {
                            continue;
                        }
                        let key = p.overlay.to_lowercase();
                        if seen_overlays.insert(key) {
                            // Queue this peer as a discovery target for the
                            // next round if our transport can dial it. (Bee
                            // hive announcements often include both a TCP and
                            // a ws address per peer; native builds can use
                            // either, WASM builds only ws.)
                            if let Some(u) = p.first_dialable_underlay() {
                                next_frontier.push(u);
                            }
                            all.push(p);
                        }
                    }
                }
                Err(e) => {
                    debug!(target: "hoverfly::discover",
                        "discover from {} failed: {}", ma, e);
                }
            }
            // Refill the window.
            if let Some(ma) = iter.next() {
                inflight.push(dial(ma));
            }
        }

        info!(target: "hoverfly::discover",
            "round {} done: total unique peers = {}", round + 1, all.len());
        if let Some(p) = progress.as_ref() {
            p(DiscoverEvent::RoundFinished {
                round: round + 1,
                total_rounds: max_rounds,
                new_peers_this_round: all.len() - peers_before_round,
                total_peers: all.len(),
            });
        }
        frontier = next_frontier;
    }

    Ok(all)
}

/// Fetch arbitrary-size content addressed by `root` (32-byte content address).
/// Walks the BMT tree via [`nectar_primitives::file::join`].
pub async fn fetch_bytes(
    transport: &Transport,
    peers: &PeerStore,
    root_hex: &str,
    max_retries_per_chunk: usize,
) -> Result<Vec<u8>, ClientError> {
    fetch_bytes_ex(transport, peers, root_hex, max_retries_per_chunk, 1).await
}

/// Like [`fetch_bytes`], but races up to `concurrency` peers in parallel
/// per chunk request.
pub async fn fetch_bytes_ex(
    transport: &Transport,
    peers: &PeerStore,
    root_hex: &str,
    max_retries_per_chunk: usize,
    concurrency: usize,
) -> Result<Vec<u8>, ClientError> {
    fetch_bytes_cached_ex(
        transport,
        peers,
        root_hex,
        max_retries_per_chunk,
        concurrency,
        &RetrievalCache::new(),
    )
    .await
}

/// Like [`fetch_bytes_ex`], but reuses the session cache and peer
/// scoreboard from a shared [`RetrievalCache`] so a daemon keeps them
/// warm across requests.
pub async fn fetch_bytes_cached_ex(
    transport: &Transport,
    peers: &PeerStore,
    root_hex: &str,
    max_retries_per_chunk: usize,
    concurrency: usize,
    cache: &RetrievalCache,
) -> Result<Vec<u8>, ClientError> {
    let root = parse_root(root_hex)?;
    let store =
        NetworkedStore::with_cache(transport, peers, max_retries_per_chunk, concurrency, cache);
    join_target(&store, root, concurrency, None).await
}

/// Like [`fetch_bytes_ex`], but drives a byte-based `progress` callback as the
/// file body is joined (used by the CLI to render a progress bar). Works for
/// both plain and erasure-coded objects.
pub async fn fetch_bytes_progress(
    transport: &Transport,
    peers: &PeerStore,
    root_hex: &str,
    max_retries_per_chunk: usize,
    concurrency: usize,
    progress: Option<&ProgressFn>,
) -> Result<Vec<u8>, ClientError> {
    let root = parse_root(root_hex)?;
    let cache = RetrievalCache::new();
    let store =
        NetworkedStore::with_cache(transport, peers, max_retries_per_chunk, concurrency, &cache);
    join_target(&store, root, concurrency, progress).await
}

/// Join a BMT reference into its full byte content, transparently handling
/// **erasure-coded** objects.
///
/// Since ~bee v2.8.1, gateway uploads are Reed–Solomon erasure coded by default
/// (see [`crate::erasure`]). Such an object's root chunk encodes a redundancy
/// level in the top byte of its span, and its intermediate nodes carry parity
/// references that nectar's plain joiner would mis-traverse as data. So we
/// first fetch the root chunk (served from the store's cache on the subsequent
/// join, no extra round-trip) and inspect its span:
///
/// - **level-encoded** → drive the erasure-aware joiner
///   ([`crate::erasure::fetch_erasure_bytes`]), which fetches each node's data
///   children and, for any that time out (the exact failure mode of a fresh
///   upload on a light client — bee#5541), reconstructs them from the node's RS
///   parity siblings;
/// - **plain** → drive nectar's `GenericJoiner` as before.
///
/// The erasure joiner is byte-exact with bee's encoder, so a fully-retrievable
/// object round-trips identically down either path; the difference only shows
/// when some data chunks are unretrievable.
async fn join_target<'a>(
    store: &NetworkedStore<'a>,
    root: ChunkAddress,
    concurrency: usize,
    progress: Option<&ProgressFn>,
) -> Result<Vec<u8>, ClientError> {
    // Peek at the root span. `get` populates the store's in-memory cache, so
    // whichever joiner runs next re-reads the root for free.
    //
    // If the root can't be retrieved at all, fall back to its dispersed
    // replicas before giving up (bee `pkg/replicas`, applied — as bee does —
    // only to the root, which is the only chunk that has any). The upload level
    // is unknowable without the root, so the search assumes the widest level;
    // dispersal order means a narrower upload's replicas come up first.
    if ChunkGet::get(store, &root).await.is_err()
        && let Some(wire) = crate::erasure::replicas::recover_root(
            store,
            root,
            crate::erasure::replicas::DEFAULT_DOWNLOAD_LEVEL,
        )
        .await
    {
        store.seed_wire(root, wire);
    }

    if let Ok(root_chunk) = ChunkGet::get(store, &root).await {
        // `AnyChunk::span()` returns the raw little-endian span as a u64 with
        // the redundancy-level byte intact.
        let raw_span = root_chunk.span().to_le_bytes();
        if crate::erasure::joiner::root_is_erasure_coded(&raw_span) {
            info!(
                target: "hoverfly::fetch",
                "root {} is erasure-coded; using RS-aware joiner",
                root_chunk.address(),
            );
            // Same in-flight budget the plain joiner gets: the erasure path
            // used to race every sibling of a node at once (up to 128), which
            // overshoots the session pool's substream capacity and converts
            // throughput into `stream control` failures and retries.
            return Ok(crate::erasure::fetch_erasure_bytes_progress(
                store,
                root,
                progress,
                joiner_concurrency(concurrency),
            )
            .await?);
        }
    }

    // Plain (non-redundant) object: drive nectar's BMT joiner with a HIGHER
    // chunks-in-flight count than the per-chunk peer-race width. These are
    // different knobs: `concurrency` (the store's) is how many peers we race for
    // ONE chunk — useful while cold for discovery, wasteful once warm (the extra
    // attempts just consume substream slots). The joiner's concurrency is how
    // many DISTINCT chunks pull at once, which is the real throughput lever.
    // Decoupling them (and giving the joiner the larger value via
    // `joiner_concurrency`) pumps many chunks through the few warm forwarders
    // instead of redundantly racing each chunk against the whole pool.
    let joiner =
        GenericJoiner::<_, nectar_primitives::file::mode::PlainMode, DEFAULT_BODY_SIZE>::new(
            store, root,
        )
        .await?
        .with_concurrency(joiner_concurrency(concurrency));

    // Without a progress sink, `read_all()` is the simplest path. With one,
    // stream leaves by offset and reassemble, reporting bytes as they land so
    // the CLI can drive a byte-based bar (nectar's joiner has no progress
    // callback of its own).
    let Some(cb) = progress else {
        return Ok(joiner.read_all().await?);
    };

    use futures::StreamExt as _;
    let total = joiner.size() as usize;
    let mut out = vec![0u8; total];
    let mut done = 0usize;
    cb(0, total);
    let mut stream = std::pin::pin!(joiner.into_offset_stream());
    while let Some(item) = stream.next().await {
        let (offset, bytes) = item?;
        let start = offset as usize;
        let end = (start + bytes.len()).min(total);
        if start < total {
            out[start..end].copy_from_slice(&bytes[..end - start]);
        }
        done += bytes.len();
        cb(done.min(total), total);
    }
    cb(total, total);
    Ok(out)
}

/// Resolve `path` through the mantaray manifest at `root_hex` and fetch the
/// resulting entry's content. Returns `(content_bytes, content_type)` where
/// `content_type` is `None` if the manifest entry has no `Content-Type`
/// metadata.
pub async fn fetch_manifest_path(
    transport: &Transport,
    peers: &PeerStore,
    root_hex: &str,
    path: &str,
    max_retries_per_chunk: usize,
) -> Result<(Vec<u8>, Option<String>), ClientError> {
    fetch_manifest_path_ex(transport, peers, root_hex, path, max_retries_per_chunk, 1).await
}

/// Like [`fetch_manifest_path`], but races up to `concurrency` peers in
/// parallel per chunk request.
pub async fn fetch_manifest_path_ex(
    transport: &Transport,
    peers: &PeerStore,
    root_hex: &str,
    path: &str,
    max_retries_per_chunk: usize,
    concurrency: usize,
) -> Result<(Vec<u8>, Option<String>), ClientError> {
    fetch_manifest_path_cached_ex(
        transport,
        peers,
        root_hex,
        path,
        max_retries_per_chunk,
        concurrency,
        &RetrievalCache::new(),
    )
    .await
}

/// Like [`fetch_manifest_path_ex`], but reuses the session cache and
/// peer scoreboard from a shared [`RetrievalCache`] (daemon warm path).
pub async fn fetch_manifest_path_cached_ex(
    transport: &Transport,
    peers: &PeerStore,
    root_hex: &str,
    path: &str,
    max_retries_per_chunk: usize,
    concurrency: usize,
    cache: &RetrievalCache,
) -> Result<(Vec<u8>, Option<String>), ClientError> {
    let (bytes, content_type, _feed_resolved) = fetch_manifest_path_cached_meta(
        transport,
        peers,
        root_hex,
        path,
        max_retries_per_chunk,
        concurrency,
        cache,
    )
    .await?;
    Ok((bytes, content_type))
}

/// Like [`fetch_manifest_path_cached_ex`] but also reports whether the
/// reference was feed-backed (i.e. **mutable** — the gateway must not cache it
/// as immutable, since a feed's reference is stable but its head moves
/// forward). Returned as a tuple so callers that don't care can
/// `let (b, c, _) = …`.
pub async fn fetch_manifest_path_cached_meta(
    transport: &Transport,
    peers: &PeerStore,
    root_hex: &str,
    path: &str,
    max_retries_per_chunk: usize,
    concurrency: usize,
    cache: &RetrievalCache,
) -> Result<(Vec<u8>, Option<String>, bool), ClientError> {
    let root = parse_root(root_hex)?;
    // Single store shared between path lookup and content fetch; the
    // root chunk is hit by both phases so the cache saves a round-trip.
    let store =
        NetworkedStore::with_cache(transport, peers, max_retries_per_chunk, concurrency, cache);
    let ResolvedRoot {
        root,
        feed_resolved,
    } = resolve_feed_root(&store, root, Some(cache)).await?;
    let (target, content_type) = lookup_manifest_path(&store, root, path).await?;
    let bytes = join_target(&store, target, concurrency, None).await?;
    Ok((bytes, content_type, feed_resolved))
}

/// Like [`fetch_manifest_path_ex`], but drives a byte-based `progress` callback
/// as the resolved entry's body is joined (used by the CLI to render a progress
/// bar). Works for both plain and erasure-coded entries.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_manifest_path_progress(
    transport: &Transport,
    peers: &PeerStore,
    root_hex: &str,
    path: &str,
    max_retries_per_chunk: usize,
    concurrency: usize,
    progress: Option<&ProgressFn>,
) -> Result<(Vec<u8>, Option<String>), ClientError> {
    let root = parse_root(root_hex)?;
    let cache = RetrievalCache::new();
    let store =
        NetworkedStore::with_cache(transport, peers, max_retries_per_chunk, concurrency, &cache);
    let ResolvedRoot { root, .. } = resolve_feed_root(&store, root, Some(&cache)).await?;
    let (target, content_type) = lookup_manifest_path(&store, root, path).await?;
    let bytes = join_target(&store, target, concurrency, progress).await?;
    Ok((bytes, content_type))
}

/// List entries in the mantaray manifest at `root_hex`.
pub async fn list_manifest(
    transport: &Transport,
    peers: &PeerStore,
    root_hex: &str,
    max_retries_per_chunk: usize,
) -> Result<Vec<ManifestEntry>, ClientError> {
    list_manifest_ex(transport, peers, root_hex, max_retries_per_chunk, 1).await
}

/// Like [`list_manifest`], but races up to `concurrency` peers in
/// parallel per chunk request.
pub async fn list_manifest_ex(
    transport: &Transport,
    peers: &PeerStore,
    root_hex: &str,
    max_retries_per_chunk: usize,
    concurrency: usize,
) -> Result<Vec<ManifestEntry>, ClientError> {
    let root = parse_root(root_hex)?;
    let store =
        NetworkedStore::with_concurrency(transport, peers, max_retries_per_chunk, concurrency);
    let root = resolve_feed_root(&store, root, None).await?.root;
    walk_manifest(&store, root, Vec::new()).await
}

/// Validate delivered bytes against the address that was requested, trying both
/// chunk kinds. Returns whether the delivery is authentic for that address.
///
/// - Content-addressed chunk (CAC): address is the BMT hash of the data.
/// - Single-owner chunk (SOC): address is `keccak256(id || owner)`; the data
///   is `id(32) || signature(65) || wrapped-cac`. Feed updates are SOCs, so a
///   retrieval that requested a SOC address must be validated this way — the
///   CAC BMT check would (correctly) reject it.
///
/// The CAC check hashes the wire bytes directly
/// ([`crate::erasure::wire_address`]) rather than going through nectar's
/// `ContentChunk`, which additionally insists that a span below the body size
/// equal the payload length. Bee has no such rule and its erasure **parity**
/// chunks break it routinely (a parity span is RS output over the data shards'
/// spans, so at leaf level it is a small 16-bit number and lands at or below
/// 4096 for ~5% of parity chunks, measured across a sweep of file sizes at
/// MEDIUM). Validating through nectar therefore threw those away as "address
/// mismatch" — exactly the chunks the erasure joiner needs when data chunks are
/// unretrievable.
fn validate_delivery(data: &[u8], address: &ChunkAddress) -> bool {
    use nectar_primitives::Chunk as _;
    // CAC first — the overwhelmingly common case.
    if crate::erasure::wire_address(data).as_ref() == Some(address) {
        return true;
    }
    // Fall back to SOC: nectar computes its address as keccak256(id||owner)
    // and verifies the owner by recovering it from the signature over
    // keccak256(id || wrapped.bmt_hash), so a matching address means the
    // single-owner chunk is authentic.
    if let Ok(soc) = SingleOwnerChunk::<DEFAULT_BODY_SIZE>::try_from(data)
        && soc.address() == address
    {
        return true;
    }
    false
}

/// Parse already-validated wire bytes into a nectar chunk.
///
/// `None` for a bee erasure parity chunk — nectar's `ContentChunk` rejects its
/// span (see [`validate_delivery`]). Such chunks are only ever requested by the
/// erasure joiner, which reads wire bytes through [`crate::erasure::WireGet`]
/// and never needs a nectar type.
fn parse_delivery(data: &[u8], address: &ChunkAddress) -> Option<AnyChunk<DEFAULT_BODY_SIZE>> {
    use nectar_primitives::Chunk as _;
    if let Ok(cac) = ContentChunk::<DEFAULT_BODY_SIZE>::try_from(data) {
        if cac.address() == address {
            return Some(AnyChunk::from(cac));
        }
    }
    if let Ok(soc) = SingleOwnerChunk::<DEFAULT_BODY_SIZE>::try_from(data) {
        if soc.address() == address {
            return Some(AnyChunk::from(soc));
        }
    }
    None
}

/// If `root` is a *feed manifest* (its root node carries `swarm-feed-*`
/// metadata), resolve the feed to its current content root and return that;
/// otherwise return `root` unchanged. This lets feed-backed references (e.g.
/// mutable ENS sites like `swarm.eth`) be fetched transparently: callers walk
/// the returned root as an ordinary content manifest.
/// Outcome of [`resolve_feed_root`]: the content root to walk, plus whether the
/// supplied reference was a *feed manifest* (i.e. mutable). The mutability flag
/// is surfaced all the way to the gateway so it can avoid caching feed-backed
/// content as immutable (a feed's reference is stable but its content changes).
struct ResolvedRoot {
    root: ChunkAddress,
    /// True iff `root` was resolved through a feed (mutable content).
    feed_resolved: bool,
}

async fn resolve_feed_root(
    store: &NetworkedStore<'_>,
    root: ChunkAddress,
    cache: Option<&RetrievalCache>,
) -> Result<ResolvedRoot, ClientError> {
    use crate::feed::{Feed, resolve_latest};
    use crate::manifest::{decode_node, extract_feed_meta};

    let chunk = ChunkGet::<DEFAULT_BODY_SIZE>::get(store, &root)
        .await
        .map_err(|e| ClientError::Manifest(format!("fetch root {root}: {e}")))?;
    let node = decode_node(chunk.data()).map_err(|e| ClientError::Manifest(e.to_string()))?;

    let Some((owner_hex, topic_hex, ty)) = extract_feed_meta(&node) else {
        // ordinary content manifest — immutable, content-addressed
        return Ok(ResolvedRoot {
            root,
            feed_resolved: false,
        });
    };
    let feed = Feed::from_manifest_meta(&owner_hex, &topic_hex, &ty)
        .map_err(|e| ClientError::Feed(e.to_string()))?;

    // Use the last resolved index for this feed as a forward-search hint, so a
    // daemon re-serving the same feed-backed site resolves the head in ~1 round
    // instead of a full cold search. Key the cache on owner||topic.
    let feed_key = format!("{}{}", owner_hex.to_lowercase(), topic_hex.to_lowercase());
    let after = cache.and_then(|c| c.feed_hint(&feed_key)).unwrap_or(0);

    let (resolved, index) = resolve_latest(store, &feed, after)
        .await
        .map_err(|e| ClientError::Feed(e.to_string()))?;
    if let Some(c) = cache {
        c.set_feed_hint(&feed_key, index);
    }
    Ok(ResolvedRoot {
        root: resolved,
        feed_resolved: true,
    })
}

async fn lookup_manifest_path(
    store: &NetworkedStore<'_>,
    root: ChunkAddress,
    path: &str,
) -> Result<(ChunkAddress, Option<String>), ClientError> {
    use crate::manifest::{decode_node, extract_index_document};
    let mut current = root;
    // Owned so we can redirect to a website-index-document mid-walk (a borrow
    // of `path` couldn't be replaced with a freshly-derived index name).
    let mut remaining: Vec<u8> = path.as_bytes().to_vec();
    let mut last_content_type: Option<String> = None;
    // Guards the one-shot redirect to a `website-index-document` so a
    // pathological manifest (index pointing back at an empty path) can't loop.
    let mut index_redirected = false;

    loop {
        let chunk = ChunkGet::<DEFAULT_BODY_SIZE>::get(store, &current)
            .await
            .map_err(|e| ClientError::Manifest(format!("fetch node {current}: {e}")))?;
        let node = decode_node(chunk.data()).map_err(|e| ClientError::Manifest(e.to_string()))?;

        if remaining.is_empty() {
            if let Some(addr) = node.entry {
                return Ok((addr, last_content_type.clone()));
            }
            // No bare entry at this node. A collection upload (bee's
            // `POST /bzz` with a tar/multipart body) doesn't put a file at the
            // manifest root; instead it records a `website-index-document`
            // (e.g. "index.html") in the root metadata, and gateways resolve
            // the root to THAT entry. Honour it here so `--path /` (and the
            // gateway's empty-path candidate) resolve to the index document
            // the bee way, instead of failing with "no entry". (This is why a
            // site whose root has only an `index.html` fork — e.g. omnipin.eth
            // — returned "path / has no entry".)
            if !index_redirected {
                if let Some(idx) = extract_index_document(&node) {
                    index_redirected = true;
                    remaining = idx.into_bytes();
                    continue; // re-walk from the current node toward `idx`
                }
            }
            return Err(ClientError::Manifest(format!("path {path} has no entry")));
        }

        let first = remaining[0];
        let fork = node
            .forks
            .get(&first)
            .ok_or_else(|| ClientError::Manifest(format!("no fork for {path}")))?;
        if !remaining.starts_with(&fork.prefix) {
            return Err(ClientError::Manifest(format!(
                "path {path} doesn't match fork prefix"
            )));
        }
        if let Some(ct) = fork.metadata.get("Content-Type") {
            last_content_type = Some(ct.clone());
        }
        remaining = remaining[fork.prefix.len()..].to_vec();
        current = fork.reference;
    }
}

/// Walk the manifest rooted at `addr`, fanning out fork descents in
/// parallel. Each level's forks are independent chunk fetches; serial
/// descent was the dominant cost on deep manifests (every level adds an
/// RTT). The store's internal cache makes repeat visits free.
// The manifest-walk future must be `Send` on native so the daemon can run
// a list request inside `tokio::spawn` (a multi-thread-runtime task). On
// wasm the store is IndexedDB-backed (`Rc<Database>`, not `Send`), and there's
// no cross-thread spawn, so the bound is dropped. `MaybeSendWalk` gates the
// trait-object bound by target; the async body is identical either way (its
// actual Send-ness follows from the store type, which is Send on native and
// non-Send on wasm).
#[cfg(not(target_arch = "wasm32"))]
type MaybeSendWalk<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Vec<ManifestEntry>, ClientError>> + Send + 'a>,
>;
#[cfg(target_arch = "wasm32")]
type MaybeSendWalk<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Vec<ManifestEntry>, ClientError>> + 'a>,
>;

fn walk_manifest<'a>(
    store: &'a NetworkedStore<'a>,
    addr: ChunkAddress,
    path_so_far: Vec<u8>,
) -> MaybeSendWalk<'a> {
    Box::pin(async move {
        use crate::manifest::decode_node;

        let chunk = ChunkGet::<DEFAULT_BODY_SIZE>::get(store, &addr)
            .await
            .map_err(|e| ClientError::Manifest(format!("fetch node {addr}: {e}")))?;
        let node = decode_node(chunk.data()).map_err(|e| ClientError::Manifest(e.to_string()))?;

        let mut out = Vec::new();
        if let Some(entry_addr) = node.entry {
            let path = String::from_utf8_lossy(&path_so_far).into_owned();
            out.push(ManifestEntry {
                path,
                reference: hex::encode(entry_addr.as_bytes()),
                content_type: None,
            });
        }

        for fork in node.forks.values() {
            let mut next_path = path_so_far.clone();
            next_path.extend_from_slice(&fork.prefix);
            let r = fork.reference;
            out.extend(walk_manifest(store, r, next_path).await?);
        }
        Ok(out)
    })
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManifestEntry {
    pub path: String,
    pub reference: String,
    pub content_type: Option<String>,
}

/// Default number of peer sessions opened in parallel for upload.
pub const DEFAULT_UPLOAD_CONCURRENCY: usize = 8;

/// Upload a file's content plus a single-entry mantaray manifest pointing
/// `path` at the file root, with optional `Content-Type` metadata. Returns
/// the *manifest* root — fetchable via `fetch <manifest_root> --path <path>`.
#[allow(clippy::too_many_arguments)]
pub async fn upload_file_with_manifest(
    transport: &Transport,
    peers: &PeerStore,
    signer: &SwarmSigner,
    batch_id_hex: &str,
    depth: u8,
    immutable: bool,
    data: &[u8],
    path: &str,
    content_type: Option<&str>,
    redundancy: Level,
    max_retries_per_chunk: usize,
) -> Result<ChunkAddress, ClientError> {
    upload_file_with_manifest_ex(
        transport,
        peers,
        signer,
        batch_id_hex,
        depth,
        immutable,
        data,
        path,
        content_type,
        redundancy,
        max_retries_per_chunk,
        DEFAULT_UPLOAD_CONCURRENCY,
        None,
    )
    .await
}

/// Input to `upload_collection_ex`: one file's bytes and its in-manifest
/// path (matches bee's tar/multipart `dirUploadHandler`).
pub struct UploadFile {
    pub path: String,
    pub content_type: Option<String>,
    pub data: Vec<u8>,
}

/// Split + build the multi-entry manifest + stamp a collection, WITHOUT
/// pushing. Returns the manifest root and the stamped chunks ready for
/// the wire — the pure-CPU half of [`upload_collection`], shared with the
/// pusher relay path (the browser calls this via wasm, then ships the
/// frames to a relay). No network, no key beyond the stamp signer.
#[allow(clippy::too_many_arguments)]
pub fn prepare_upload_collection(
    signer: &SwarmSigner,
    batch_id_hex: &str,
    depth: u8,
    immutable: bool,
    files: &[UploadFile],
    index_document: Option<&str>,
    error_document: Option<&str>,
    redundancy: Level,
) -> Result<(ChunkAddress, Vec<StampedChunk>), ClientError> {
    use crate::manifest::CollectionEntry;

    if files.is_empty() {
        return Err(ClientError::Manifest("collection is empty".into()));
    }

    let batch_id = parse_batch_id(batch_id_hex)?;
    let mut stamper = build_stamper(signer, batch_id, depth, immutable)?;

    // Bee enforces `index < 2^(depth - bucketDepth)` per (batch, bucket).
    // Stamping the same chunk address twice burns two indices in the same
    // bucket and can overflow it, which bee rejects with `invalid stamp:
    // invalid index`. Across a tar full of small files there's huge
    // duplication (common headers, all-zero padding, identical assets),
    // so we deduplicate by chunk address before stamping.
    let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    let mut stamp_in: Vec<(ChunkAddress, Vec<u8>)> = Vec::new();
    let mut entries: Vec<CollectionEntry> = Vec::with_capacity(files.len());
    let mut total_bytes: usize = 0;
    let mut raw_chunks = 0usize;
    for f in files {
        let (file_root, file_chunks) = split_chunks(&f.data, redundancy)?;
        debug!(
            target: "hoverfly::upload",
            "collection: {} ({} bytes) -> {} chunks (root {})",
            f.path, f.data.len(), file_chunks.len(), file_root
        );
        total_bytes += f.data.len();
        for (addr, wire) in file_chunks {
            raw_chunks += 1;
            let mut addr_bytes = [0u8; 32];
            addr_bytes.copy_from_slice(addr.as_bytes());
            if !seen.insert(addr_bytes) {
                continue; // already stamped — bee dedupes on address anyway
            }
            stamp_in.push((addr, wire));
        }
        entries.push(CollectionEntry {
            path: f.path.clone(),
            reference: file_root,
            content_type: f.content_type.clone(),
        });
    }

    // Build the multi-entry manifest, then add its chunks (also deduped).
    let (manifest_root, manifest_chunks) =
        crate::manifest::build_collection_manifest(&entries, index_document, error_document)
            .map_err(|e| ClientError::Manifest(e.to_string()))?;
    let unique_data_chunks = stamp_in.len();
    for (addr, wire) in manifest_chunks.iter() {
        let mut addr_bytes = [0u8; 32];
        addr_bytes.copy_from_slice(addr.as_bytes());
        if !seen.insert(addr_bytes) {
            continue;
        }
        stamp_in.push((*addr, wire.to_vec()));
    }
    info!(
        target: "hoverfly::upload",
        "collection: {} files ({} bytes) -> {} unique file chunks ({} duplicates skipped) + {} manifest chunks (root {})",
        files.len(), total_bytes, unique_data_chunks,
        raw_chunks.saturating_sub(unique_data_chunks),
        manifest_chunks.len(), manifest_root,
    );

    let work = stamp_chunks_parallel(&mut stamper, stamp_in)?;
    Ok((manifest_root, work))
}

/// Upload a collection of files as a multi-entry mantaray manifest, the way
/// bee handles `POST /bzz` with `Content-Type: application/x-tar` or
/// `multipart/form-data`. Each file is split with BMT independently, and a
/// single manifest is built with one entry per file. Optional
/// `index_document` / `error_document` are written as website metadata at
/// the root path so that gateways serve `index.html` for `/<root>/` etc.
///
/// Returns the manifest root.
#[allow(clippy::too_many_arguments)]
pub async fn upload_collection(
    transport: &Transport,
    peers: &PeerStore,
    signer: &SwarmSigner,
    batch_id_hex: &str,
    depth: u8,
    immutable: bool,
    files: Vec<UploadFile>,
    index_document: Option<&str>,
    error_document: Option<&str>,
    redundancy: Level,
    max_retries_per_chunk: usize,
    concurrency: usize,
    progress: Option<&ProgressFn>,
) -> Result<ChunkAddress, ClientError> {
    let (manifest_root, work) = prepare_upload_collection(
        signer,
        batch_id_hex,
        depth,
        immutable,
        &files,
        index_document,
        error_document,
        redundancy,
    )?;
    push_chunks_concurrent(
        transport,
        peers,
        work,
        max_retries_per_chunk,
        concurrency,
        progress,
    )
    .await?;
    Ok(manifest_root)
}

#[allow(clippy::too_many_arguments)]
pub async fn upload_file_with_manifest_ex(
    transport: &Transport,
    peers: &PeerStore,
    signer: &SwarmSigner,
    batch_id_hex: &str,
    depth: u8,
    immutable: bool,
    data: &[u8],
    path: &str,
    content_type: Option<&str>,
    redundancy: Level,
    max_retries_per_chunk: usize,
    concurrency: usize,
    progress: Option<&ProgressFn>,
) -> Result<ChunkAddress, ClientError> {
    let (manifest_root, work) = prepare_upload_file_with_manifest(
        signer,
        batch_id_hex,
        depth,
        immutable,
        data,
        path,
        content_type,
        redundancy,
    )?;
    push_chunks_concurrent(
        transport,
        peers,
        work,
        max_retries_per_chunk,
        concurrency,
        progress,
    )
    .await?;
    Ok(manifest_root)
}

/// Daemon-mode single-file-with-manifest upload through a pre-built pool.
#[allow(clippy::too_many_arguments)]
pub async fn upload_file_with_manifest_with_pool(
    transport: &Transport,
    pool: &SessionPool,
    peers: &PeerStore,
    signer: &SwarmSigner,
    batch_id_hex: &str,
    depth: u8,
    immutable: bool,
    data: &[u8],
    path: &str,
    content_type: Option<&str>,
    redundancy: Level,
    max_retries_per_chunk: usize,
    cache: Option<&crate::cache::ChunkCache>,
    progress: Option<&ProgressFn>,
) -> Result<ChunkAddress, ClientError> {
    let (manifest_root, work) = prepare_upload_file_with_manifest(
        signer,
        batch_id_hex,
        depth,
        immutable,
        data,
        path,
        content_type,
        redundancy,
    )?;
    if let Some(c) = cache {
        populate_cache(c, &work);
    }
    push_chunks_with_pool(
        transport,
        pool,
        peers,
        work,
        max_retries_per_chunk,
        false, // daemon owns pool upkeep via its maintenance loop
        progress,
    )
    .await?;
    Ok(manifest_root)
}

/// Split + manifest-wrap + stamp a single file in one go. Like
/// [`prepare_upload_bytes`] but produces a mantaray-manifest root
/// rather than a raw BMT root: the returned chunks include both the
/// file's chunks and the manifest entry chunks. Used by the
/// multi-worker coordinator when uploading a single file with path
/// metadata.
#[allow(clippy::too_many_arguments)]
pub fn prepare_upload_file_with_manifest(
    signer: &SwarmSigner,
    batch_id_hex: &str,
    depth: u8,
    immutable: bool,
    data: &[u8],
    path: &str,
    content_type: Option<&str>,
    redundancy: Level,
) -> Result<(ChunkAddress, Vec<StampedChunk>), ClientError> {
    let batch_id = parse_batch_id(batch_id_hex)?;

    let (file_root, mut stamp_in) = split_chunks(data, redundancy)?;
    info!(target: "hoverfly::upload", "file: {} bytes -> {} chunks (root {})",
        data.len(), stamp_in.len(), file_root);

    let (manifest_root, manifest_chunks) =
        crate::manifest::build_single_entry_manifest(path, file_root, content_type)
            .map_err(|e| ClientError::Manifest(e.to_string()))?;
    info!(target: "hoverfly::upload", "manifest: {} chunks (root {})", manifest_chunks.len(), manifest_root);

    let mut stamper = build_stamper(signer, batch_id, depth, immutable)?;
    stamp_in.reserve(manifest_chunks.len());
    for (addr, wire) in manifest_chunks {
        stamp_in.push((addr, wire.to_vec()));
    }
    let work = stamp_chunks_parallel(&mut stamper, stamp_in)?;
    Ok((manifest_root, work))
}

/// Convert a nectar AnyChunk into the wire form `span_LE_8 || payload`.
fn wire_form(chunk: &AnyChunk<DEFAULT_BODY_SIZE>) -> Vec<u8> {
    let mut wire = Vec::with_capacity(8 + chunk.data().len());
    wire.extend_from_slice(&chunk.span().to_le_bytes());
    wire.extend_from_slice(chunk.data());
    wire
}

/// A split object: the content root plus every chunk in wire form
/// (`address`, `span_LE_8 || payload`), ready to be stamped and pushed.
type SplitChunks = (ChunkAddress, Vec<(ChunkAddress, Vec<u8>)>);

/// Split `data` into wire-ready chunks at redundancy `level`, returning the
/// content root and every chunk as `(address, span_LE_8 || payload)`.
///
/// The single splitting seam for **all** upload paths. At [`Level::None`] this
/// is nectar's plain BMT split; at any other level it is
/// [`crate::erasure::split_with_redundancy`], which additionally emits
/// Reed–Solomon parity chunks and level-encodes the intermediate nodes exactly
/// as bee's upload pipeline does. Both deduplicate by chunk address — stamping
/// one address twice burns two indices in the same postage bucket, which bee
/// rejects as `invalid stamp: invalid index`.
///
/// Note that the root **differs between levels** for the same bytes: the
/// redundancy level rides in the top byte of the root chunk's span, which is
/// part of the BMT preimage. Bee behaves identically (`POST /bytes` with
/// `Swarm-Redundancy-Level: 0` vs `: 1` returns different references).
fn split_chunks(data: &[u8], level: Level) -> Result<SplitChunks, ClientError> {
    if level == Level::None {
        let (root, store) = split::<DEFAULT_BODY_SIZE>(data)?;
        let chunks = store
            .into_chunks()
            .iter()
            .map(|(addr, chunk)| (*addr, wire_form(chunk)))
            .collect();
        return Ok((root, chunks));
    }
    let out = crate::erasure::split_with_redundancy(data, level)
        .map_err(|e| ClientError::File(e.to_string()))?;
    debug!(
        target: "hoverfly::upload",
        "erasure split ({level}): {} bytes -> {} chunks ({} parity), root {}",
        data.len(), out.chunks.len(), out.parity_chunks, out.root,
    );
    Ok((out.root, out.chunks))
}

/// A chunk pre-stamped and ready for the wire.
///
/// The three components are everything a pushsync substream needs:
/// - `addr` — the BMT root of the chunk (32 bytes); also the chunk's
///   network address.
/// - `wire` — the on-the-wire chunk body: `span (LE 8) || payload`
///   matching nectar's `ContentChunk::data()`. Bee will re-derive
///   `addr` from this on receipt.
/// - `stamp` — a postage stamp signed by the batch owner authorising
///   storage of this chunk against the batch. Validated on the
///   receiving bee in `pkg/postage.Stamp::Valid` (signature ↔ owner,
///   bucket match, index in range).
///
/// Stamping is decoupled from pushing: a `StampedChunk` carries
/// everything required to push it without access to the batch owner's
/// key. This is the unit of work shipped between a coordinator (which
/// holds the batch key and does the stamping) and worker processes
/// (which only hold their own libp2p overlay keys and do the pushing).
///
/// `Serialize`/`Deserialize` are derived so the type can travel over
/// IPC (currently used by the multi-worker upload subcommand, but the
/// type is intentionally generic and can be persisted to disk or sent
/// over any byte channel).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct StampedChunk {
    pub addr: [u8; 32],
    pub wire: Vec<u8>,
    pub stamp: Vec<u8>,
}

fn build_stamper(
    signer: &SwarmSigner,
    batch_id: BatchId,
    depth: u8,
    immutable: bool,
) -> Result<HoverflyStamper, ClientError> {
    let batch = Batch::new(
        batch_id,
        0u128,
        0u64,
        alloy_primitives::Address::from(*signer.eth_address()),
        depth,
        BUCKET_DEPTH,
        immutable,
    );
    // Immutable → fill-only `MemoryIssuer`; mutable → externally-tracked
    // `RingIssuer`. Each errors on the wrong batch kind, so gate on `immutable`.
    let issuer: Box<dyn StampIssuer + Send> = if immutable {
        Box::new(MemoryIssuer::from_batch(&batch).map_err(|e| ClientError::Stamp(e.to_string()))?)
    } else {
        Box::new(RingIssuer::external(&batch).map_err(|e| ClientError::Stamp(e.to_string()))?)
    };
    Ok(BatchStamper::new(issuer, signer.alloy_signer().clone()))
}

/// Current Unix time in **nanoseconds** for stamping, on wasm.
///
/// nectar's `current_timestamp()` (and `BatchStamper::stamp`, which calls it
/// internally) use `std::time::SystemTime::now()`, which **panics on wasm32**
/// ("time not implemented on this platform"). So on wasm we must source the
/// timestamp ourselves and feed it explicitly via `prepare_stamp` —
/// `js_sys::Date::now()` returns milliseconds since the epoch as `f64`; nectar
/// records the stamp timestamp in nanoseconds (`current_timestamp` returns
/// `duration.as_nanos()`), so scale by 1e6 to match.
#[cfg(target_arch = "wasm32")]
fn wasm_timestamp_nanos() -> u64 {
    (js_sys::Date::now() as u64).saturating_mul(1_000_000)
}

/// Stamp a batch of (address, wire) pairs, signing in parallel via rayon.
///
/// secp256k1 signing is ~ms per chunk and serial on `stamp_chunk` — for
/// big uploads (10 MB ≈ 2500 chunks) this can dominate a few seconds of
/// CPU. Split the operation: the issuer-side `prepare_stamp` (index
/// allocation, no crypto) stays serial because the issuer requires
/// `&mut`, then the digest signing fans out across cores.
///
/// Native-only: wasm32 is single-threaded so rayon has no thread pool
/// to spread work over; the serial path is just as fast there.
#[cfg(not(target_arch = "wasm32"))]
fn stamp_chunks_parallel(
    stamper: &mut HoverflyStamper,
    work: Vec<(ChunkAddress, Vec<u8>)>,
) -> Result<Vec<StampedChunk>, ClientError> {
    use nectar_postage::current_timestamp;
    use rayon::prelude::*;

    // Phase 1 (serial): allocate batch indices & build digests.
    let timestamp = current_timestamp();
    let mut prepared: Vec<(ChunkAddress, Vec<u8>, nectar_postage::StampDigest)> =
        Vec::with_capacity(work.len());
    for (addr, wire) in work {
        let digest = stamper
            .issuer_mut()
            .prepare_stamp(&addr, timestamp)
            .map_err(|e| ClientError::Stamp(e.to_string()))?;
        prepared.push((addr, wire, digest));
    }

    // Phase 2 (parallel): sign each digest. `PrivateKeySigner: Sync` so
    // the same instance can be shared across rayon worker threads.
    let signer: &alloy_signer_local::PrivateKeySigner = stamper.signer();
    let stamped: Result<Vec<StampedChunk>, ClientError> = prepared
        .into_par_iter()
        .map(|(addr, wire, digest)| {
            use alloy_signer::SignerSync;
            let prehash = digest.to_prehash();
            let sig = signer
                .sign_message_sync(prehash.as_slice())
                .map_err(|e| ClientError::Stamp(e.to_string()))?;
            let stamp = HoverflyStamper::stamp_from_signature(&digest, sig);
            let stamp_bytes = stamp.to_bytes().to_vec();
            let mut addr32 = [0u8; 32];
            addr32.copy_from_slice(addr.as_bytes());
            Ok(StampedChunk {
                addr: addr32,
                wire,
                stamp: stamp_bytes,
            })
        })
        .collect();
    stamped
}

/// wasm stamping: serial (single-threaded), and — crucially — uses an
/// explicit timestamp via `prepare_stamp` + `stamp_from_signature` rather than
/// `BatchStamper::stamp`, because the latter calls `SystemTime::now()` which
/// panics on wasm. Mirrors the native parallel path's two-phase shape (prepare
/// digest, then sign) minus rayon.
#[cfg(target_arch = "wasm32")]
fn stamp_chunks_parallel(
    stamper: &mut HoverflyStamper,
    work: Vec<(ChunkAddress, Vec<u8>)>,
) -> Result<Vec<StampedChunk>, ClientError> {
    use alloy_signer::SignerSync;

    let timestamp = wasm_timestamp_nanos();
    let mut out = Vec::with_capacity(work.len());
    for (addr, wire) in work {
        let digest = stamper
            .issuer_mut()
            .prepare_stamp(&addr, timestamp)
            .map_err(|e| ClientError::Stamp(e.to_string()))?;
        let prehash = digest.to_prehash();
        let sig = stamper
            .signer()
            .sign_message_sync(prehash.as_slice())
            .map_err(|e| ClientError::Stamp(e.to_string()))?;
        let stamp = HoverflyStamper::stamp_from_signature(&digest, sig);
        let mut addr32 = [0u8; 32];
        addr32.copy_from_slice(addr.as_bytes());
        out.push(StampedChunk {
            addr: addr32,
            wire,
            stamp: stamp.to_bytes().to_vec(),
        });
    }
    Ok(out)
}

/// Windowed, streaming upload: split + build the manifest once, then stamp
/// and yield the chunks a window at a time. Consumed chunks' wire data is
/// dropped as each window is taken, so peak memory stays ~one window of
/// frames instead of the whole file's frames at once — the difference
/// between a 500 MB upload OOMing the browser and completing.
///
/// The chunk order is not preserved (windows pop from the back); every
/// chunk is independent for pushsync, and the reference root is already
/// fixed by the full split, so order is irrelevant.
pub struct UploadStreamer {
    root: ChunkAddress,
    /// (addr, wire) still to stamp, in reverse push order (pop from back).
    remaining: Vec<(ChunkAddress, Vec<u8>)>,
    stamper: HoverflyStamper,
    total: usize,
}

impl UploadStreamer {
    fn from_parts(
        root: ChunkAddress,
        mut stamp_in: Vec<(ChunkAddress, Vec<u8>)>,
        stamper: HoverflyStamper,
    ) -> Self {
        let total = stamp_in.len();
        stamp_in.reverse();
        Self {
            root,
            remaining: stamp_in,
            stamper,
            total,
        }
    }

    /// Raw content (no manifest wrap).
    pub fn new_raw(
        signer: &SwarmSigner,
        batch_id_hex: &str,
        depth: u8,
        immutable: bool,
        data: &[u8],
        redundancy: Level,
    ) -> Result<Self, ClientError> {
        let batch_id = parse_batch_id(batch_id_hex)?;
        let (root, stamp_in) = split_chunks(data, redundancy)?;
        let stamper = build_stamper(signer, batch_id, depth, immutable)?;
        Ok(Self::from_parts(root, stamp_in, stamper))
    }

    /// Single file wrapped in a one-entry mantaray manifest.
    #[allow(clippy::too_many_arguments)]
    pub fn new_file(
        signer: &SwarmSigner,
        batch_id_hex: &str,
        depth: u8,
        immutable: bool,
        data: &[u8],
        path: &str,
        content_type: Option<&str>,
        redundancy: Level,
    ) -> Result<Self, ClientError> {
        let batch_id = parse_batch_id(batch_id_hex)?;
        let (file_root, mut stamp_in) = split_chunks(data, redundancy)?;
        let (manifest_root, manifest_chunks) =
            crate::manifest::build_single_entry_manifest(path, file_root, content_type)
                .map_err(|e| ClientError::Manifest(e.to_string()))?;
        let stamper = build_stamper(signer, batch_id, depth, immutable)?;
        stamp_in.reserve(manifest_chunks.len());
        for (addr, wire) in manifest_chunks {
            stamp_in.push((addr, wire.to_vec()));
        }
        Ok(Self::from_parts(manifest_root, stamp_in, stamper))
    }

    /// Collection (tar / directory) as a multi-entry manifest, deduped.
    #[allow(clippy::too_many_arguments)]
    pub fn new_collection(
        signer: &SwarmSigner,
        batch_id_hex: &str,
        depth: u8,
        immutable: bool,
        files: &[UploadFile],
        index_document: Option<&str>,
        error_document: Option<&str>,
        redundancy: Level,
    ) -> Result<Self, ClientError> {
        use crate::manifest::CollectionEntry;
        if files.is_empty() {
            return Err(ClientError::Manifest("collection is empty".into()));
        }
        let batch_id = parse_batch_id(batch_id_hex)?;
        let stamper = build_stamper(signer, batch_id, depth, immutable)?;
        let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        let mut stamp_in: Vec<(ChunkAddress, Vec<u8>)> = Vec::new();
        let mut entries: Vec<CollectionEntry> = Vec::with_capacity(files.len());
        for f in files {
            let (file_root, file_chunks) = split_chunks(&f.data, redundancy)?;
            for (addr, wire) in file_chunks {
                let mut ab = [0u8; 32];
                ab.copy_from_slice(addr.as_bytes());
                if seen.insert(ab) {
                    stamp_in.push((addr, wire));
                }
            }
            entries.push(CollectionEntry {
                path: f.path.clone(),
                reference: file_root,
                content_type: f.content_type.clone(),
            });
        }
        let (manifest_root, manifest_chunks) =
            crate::manifest::build_collection_manifest(&entries, index_document, error_document)
                .map_err(|e| ClientError::Manifest(e.to_string()))?;
        for (addr, wire) in manifest_chunks.iter() {
            let mut ab = [0u8; 32];
            ab.copy_from_slice(addr.as_bytes());
            if seen.insert(ab) {
                stamp_in.push((*addr, wire.to_vec()));
            }
        }
        Ok(Self::from_parts(manifest_root, stamp_in, stamper))
    }

    pub fn root(&self) -> ChunkAddress {
        self.root
    }
    pub fn total_chunks(&self) -> usize {
        self.total
    }
    pub fn remaining(&self) -> usize {
        self.remaining.len()
    }

    /// Stamp and return the next window of up to `batch_size` chunks (empty
    /// when done). The window's source data is consumed, so its wire bytes
    /// free once the returned `StampedChunk`s are dropped by the caller.
    pub fn next_batch(&mut self, batch_size: usize) -> Result<Vec<StampedChunk>, ClientError> {
        let n = batch_size.min(self.remaining.len());
        if n == 0 {
            return Ok(Vec::new());
        }
        let mut window: Vec<(ChunkAddress, Vec<u8>)> = Vec::with_capacity(n);
        for _ in 0..n {
            window.push(self.remaining.pop().expect("checked len"));
        }
        stamp_chunks_parallel(&mut self.stamper, window)
    }
}

/// Upload arbitrary-size content. Splits (erasure-coding at `redundancy`),
/// stamps each chunk with the supplied batch + signer, and pushes every chunk
/// via pushsync to the closest peer in the peerlist. Returns the root content
/// address.
#[allow(clippy::too_many_arguments)]
pub async fn upload_bytes(
    transport: &Transport,
    peers: &PeerStore,
    signer: &SwarmSigner,
    batch_id_hex: &str,
    depth: u8,
    immutable: bool,
    data: &[u8],
    redundancy: Level,
    max_retries_per_chunk: usize,
) -> Result<ChunkAddress, ClientError> {
    upload_bytes_ex(
        transport,
        peers,
        signer,
        batch_id_hex,
        depth,
        immutable,
        data,
        redundancy,
        max_retries_per_chunk,
        DEFAULT_UPLOAD_CONCURRENCY,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn upload_bytes_ex(
    transport: &Transport,
    peers: &PeerStore,
    signer: &SwarmSigner,
    batch_id_hex: &str,
    depth: u8,
    immutable: bool,
    data: &[u8],
    redundancy: Level,
    max_retries_per_chunk: usize,
    concurrency: usize,
    progress: Option<&ProgressFn>,
) -> Result<ChunkAddress, ClientError> {
    let (root, work) =
        prepare_upload_bytes(signer, batch_id_hex, depth, immutable, data, redundancy)?;
    push_chunks_concurrent(
        transport,
        peers,
        work,
        max_retries_per_chunk,
        concurrency,
        progress,
    )
    .await?;
    Ok(root)
}

/// Daemon-mode raw upload: split + stamp + push through a pre-built
/// session pool. Skips the per-request pool-fill dial parade.
#[allow(clippy::too_many_arguments)]
pub async fn upload_bytes_with_pool(
    transport: &Transport,
    pool: &SessionPool,
    peers: &PeerStore,
    signer: &SwarmSigner,
    batch_id_hex: &str,
    depth: u8,
    immutable: bool,
    data: &[u8],
    redundancy: Level,
    max_retries_per_chunk: usize,
    cache: Option<&crate::cache::ChunkCache>,
    progress: Option<&ProgressFn>,
) -> Result<ChunkAddress, ClientError> {
    let (root, work) =
        prepare_upload_bytes(signer, batch_id_hex, depth, immutable, data, redundancy)?;
    if let Some(c) = cache {
        populate_cache(c, &work);
    }
    push_chunks_with_pool(
        transport,
        pool,
        peers,
        work,
        max_retries_per_chunk,
        false, // daemon owns pool upkeep via its maintenance loop
        progress,
    )
    .await?;
    Ok(root)
}

/// Push locally-stamped chunks across one or more relays.
///
/// A thin driver over [`crate::pushsched::Scheduler`]: this function owns
/// only the HTTP (reqwest + tokio) and the clock. Every routing, failover,
/// hedging and lane-health decision lives in the scheduler, which is
/// sans-I/O and shared with the browser dApp — so both targets behave
/// identically and the behaviour is testable without a network.
///
/// The signing key never leaves this process; only pre-signed frames go
/// over the wire (docs/pusher-design.md §3).
#[cfg(not(target_arch = "wasm32"))]
pub async fn push_via_pushers(
    pusher_urls: &[String],
    chunks: Vec<StampedChunk>,
    progress: Option<&ProgressFn>,
) -> Result<(), ClientError> {
    let total = chunks.len();
    let mut once = Some(chunks);
    drive_pushers(
        pusher_urls,
        total,
        move |_| Ok(once.take().unwrap_or_default()),
        progress,
        None,
    )
    .await
}

/// Shared driver for every relay push, one-shot or streaming.
///
/// `produce(want)` yields up to `want` more stamped chunks; an empty result
/// means the source is exhausted. That indirection is what lets a windowed
/// upload stamp lazily — the scheduler is told about new work as it appears,
/// while earlier windows are still on the wire.
#[cfg(not(target_arch = "wasm32"))]
async fn drive_pushers<P>(
    pusher_urls: &[String],
    total_hint: usize,
    mut produce: P,
    progress: Option<&ProgressFn>,
    // Metered lanes only (`docs/pusher-incentives.md` §12). `None` means
    // pay nothing, which is correct for every `open` lane and is what all
    // callers pass until a lane actually advertises a price.
    payment: Option<&crate::payer::PaymentConfig>,
) -> Result<(), ClientError>
where
    P: FnMut(usize) -> Result<Vec<StampedChunk>, ClientError>,
{
    use crate::pushsched::{Config, LaneInfo, Scheduler};

    if pusher_urls.is_empty() {
        return Err(ClientError::Pusher("no pusher URLs given".into()));
    }
    if total_hint == 0 {
        return Ok(());
    }

    let http = std::sync::Arc::new(
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(|e| ClientError::Pusher(format!("http client: {e}")))?,
    );

    // Poll each lane's advertisement independently. A cold free-tier relay
    // (measured: 35 s to first byte on a sleeping instance) must only cost
    // *itself* a default-weighted start, never degrade routing for the
    // others — which is exactly what the previous all-or-nothing overlay
    // collection did.
    let infos: Vec<LaneInfo> = futures::future::join_all(pusher_urls.iter().map(|u| {
        // A lane quoting more than this is refused rather than paid.
        // Priced off the shipped default so a lane cannot quietly
        // charge an order of magnitude more than the design assumes.
        // Pins + chain come from the payment config when present: without a
        // pin the quote is TOFU-trusted for the run (warned inside).
        let (pin, chain) = match payment {
            Some(pc) => {
                let key = u.trim_end_matches('/').to_string();
                // `pins` is keyed by URL without trailing slash (see
                // `parse_lane_pins`); also try the raw form.
                let p = pc.pins.get(&key).or_else(|| pc.pins.get(u));
                (p, Some(pc.chain_id))
            }
            None => (None, None),
        };
        fetch_lane_info(&http, u, crate::meter::PRICE_PLUR_PER_KIB * 8, pin, chain)
    }))
    .await;
    for (i, (u, info)) in pusher_urls.iter().zip(&infos).enumerate() {
        info!(target: "hoverfly::upload",
            "lane {i} {u}: pool={:?} batch_max={:?} inflight_max={:?} budget_gb={:?}",
            info.pool_live, info.batch_max, info.inflight_max, info.budget_remaining_gb);
    }

    let mut cfg = Config::default();
    // A/B lever kept from Stage C's first cut, now inverted: proximity is
    // OFF unless asked for, because routing to a relay's own overlay is at
    // best a weak proxy for how deep a chunk lands (the relay pushes to the
    // closest peer in its own multi-thousand-entry peerstore). The `po`
    // field on `/v1/push` acks is the measurement that decides whether this
    // is ever worth enabling.
    if let Ok(v) = std::env::var("HOVERFLY_PUSH_PROXIMITY") {
        cfg.proximity_alpha = v.parse().unwrap_or(0.0);
    }
    let cfg_alpha = cfg.proximity_alpha;

    let lanes: Vec<std::sync::Arc<String>> = pusher_urls
        .iter()
        .map(|u| std::sync::Arc::new(format!("{}/v1/push", u.trim_end_matches('/'))))
        .collect();
    // One payer per metered lane. Lanes that quote no price get none, so an
    // `open` lane costs nothing and needs no special case below.
    let mut payers: Vec<Option<crate::payer::LanePayer>> = Vec::with_capacity(pusher_urls.len());
    for (i, url) in pusher_urls.iter().enumerate() {
        let quote = payment.and_then(|_| infos.get(i).and_then(|inf: &LaneInfo| inf.quote.clone()));
        payers.push(match (payment, quote) {
            (Some(pc), Some(q)) => {
                let key = crate::cheques::relay_key(&q.beneficiary);
                let cumulative = pc
                    .cheques
                    .lock()
                    .expect("cheque store poisoned")
                    .cumulative(&key);
                info!(target: "hoverfly::upload",
                    "lane {i} is metered at {} PLUR/KiB; resuming cumulative {cumulative}",
                    q.params.price_plur_per_kib);
                Some(crate::payer::LanePayer::new(url.clone(), q, cumulative))
            }
            _ => None,
        });
    }
    // Size POSTs to the credit line before scheduling anything (§7.2). A
    // body larger than the whole line can never be admitted however
    // promptly we settle, so building one guarantees a 402 the client
    // cannot pay its way out of — it would owe nothing, having had nothing
    // accepted.
    let mut infos = infos;
    // Paying is optional, so a lane that *requires* payment we cannot make is
    // simply not ours to use. Scheduling it anyway means every chunk sent
    // there is refused for a missing capability, and since that is not a 402
    // it counts against lane health — so the fleet spends one attempt per
    // chunk discovering, repeatedly, something the lane advertised up front.
    //
    // Soft-metered lanes are kept: they bill and serve, so an unpaying client
    // is served exactly like an `open` one.
    let unusable: Vec<usize> = (0..pusher_urls.len())
        .filter(|&i| {
            infos
                .get(i)
                .is_some_and(|inf: &LaneInfo| inf.hard_enforcement)
                && payers[i].is_none()
        })
        .collect();
    for &i in &unusable {
        warn!(target: "hoverfly::upload",
            "lane {i} {} enforces payment and this client has none configured; skipping it",
            pusher_urls[i]);
    }
    if !unusable.is_empty() && unusable.len() == pusher_urls.len() {
        return Err(ClientError::Pusher(
            "every lane requires payment and no chequebook is configured — \
             pass --chequebook, or use a fleet with free lanes"
                .into(),
        ));
    }
    let mut lane_frame_ceiling: Vec<usize> = vec![usize::MAX; infos.len()];
    if let Some(pc) = payment {
        for (i, payer) in payers.iter_mut().enumerate() {
            let Some(payer) = payer.as_mut() else {
                continue;
            };
            if let Err(e) = payer.header(&http, pc).await {
                warn!(target: "hoverfly::upload",
                    "lane {i}: no challenge ({e}); scheduling it unpaid");
                continue;
            }
            let fits = payer.max_frames();
            let before = infos[i].batch_max.unwrap_or(usize::MAX);
            if fits < before {
                info!(target: "hoverfly::upload",
                    "lane {i}: credit line allows {fits} frames/POST (was {before})");
                infos[i].batch_max = Some(fits);
            }
            // Remember the lane's own ceiling: the per-dispatch resize below
            // must clamp to it and never raise a lane above what it
            // advertised.
            lane_frame_ceiling[i] = fits.min(before);
            // Learn any debt carried from an earlier run *before* sizing the
            // first POST. The relay's ledger outlives ours (§17.1), so a
            // fresh process starts believing it owes nothing and builds a
            // body against the whole credit line — while the relay is
            // already holding part of it. The first POST is then refused,
            // and if the carried debt happens to sit below the dust floor
            // the refusal cannot be paid off either. Reconciling here costs
            // one GET per lane and makes every later size correct.
            match payer.reconcile(&http, pc).await {
                Ok(true) => info!(target: "hoverfly::upload",
                    "lane {i}: relay carries {} PLUR from an earlier run",
                    payer.account.owed()),
                Ok(false) => {}
                Err(e) => warn!(target: "hoverfly::upload",
                    "lane {i}: could not read carried debt ({e}); \
                     sizing may be optimistic until the first 402"),
            }
        }
    }
    // batch id -> (lane, body bytes), so a completed POST can be billed to
    // the lane that actually sent it. The relay bills what it *admits*, so
    // a refused POST must not become debt on this side either. Keyed by lane
    // because a multi-lane run strands POSTs on several lanes: attributing
    // every stranded body to the first payer with pending debt over-pays one
    // beneficiary and under-pays the other.
    let mut in_flight_bytes: HashMap<u64, (usize, u64)> = HashMap::new();
    let mut sched = Scheduler::new(infos, cfg);
    for &i in &unusable {
        sched.retire_lane(i);
    }
    // Frames are held by address, not by index: `admit` de-duplicates, so an
    // index-parallel Vec would silently skew. Keying by address also lets a
    // frame be dropped the moment its chunk is acked, which is what keeps a
    // streaming upload's memory flat.
    let mut frames: HashMap<[u8; 32], StampedChunk> = HashMap::new();
    let mut total = 0usize;
    let mut exhausted = false;
    let mut refill = |sched: &mut Scheduler,
                      frames: &mut HashMap<[u8; 32], StampedChunk>,
                      total: &mut usize,
                      exhausted: &mut bool|
     -> Result<(), ClientError> {
        if *exhausted {
            return Ok(());
        }
        let batch = produce(PUSH_WINDOW)?;
        if batch.is_empty() {
            *exhausted = true;
            return Ok(());
        }
        sched.admit(batch.iter().map(|c| (c.addr, c.wire.len() as u32)));
        for c in batch {
            frames.entry(c.addr).or_insert(c);
        }
        *total = sched.total();
        Ok(())
    };
    refill(&mut sched, &mut frames, &mut total, &mut exhausted)?;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<LaneEv>();
    let start = std::time::Instant::now();
    let now_ms = move || start.elapsed().as_millis() as u64;
    let mut done_count = 0usize;
    // Receipt-depth instrument (docs/pusher-design.md §7). Proximity routing
    // is off by default precisely because nobody had measured whether it
    // changes anything; this is the measurement. Compare mean/histogram
    // across `HOVERFLY_PUSH_PROXIMITY=0` and `=1` runs.
    let mut po_sum = 0u64;
    let mut po_n = 0u64;
    let mut po_hist = [0u32; 33];
    // Chunks the relay accepted on a shallow receipt: forwarded, but no
    // neighborhood storer confirmed storage. They count as pushed (there is
    // nothing more the relay can do) but they are the population that goes
    // on to 404 on retrieval, so the caller deserves to be told.
    let mut shallow_n = 0u64;
    // Best-available proximity at dispatch time, for the same acks. The gap
    // between this and the achieved PO is the dispatcher's own loss.
    let mut best_po_sum = 0u64;
    let mut best_po_n = 0u64;

    loop {
        // Keep the scheduler fed: stamp the next window once the backlog is
        // small enough that lanes could go idle waiting for it.
        while !exhausted && sched.total() - sched.acked() - sched.failed() < PUSH_WINDOW {
            refill(&mut sched, &mut frames, &mut total, &mut exhausted)?;
        }

        // Don't ask for work a metered lane cannot currently pay for.
        // Settling first is the way out; if nothing is owed yet, the debt is
        // still in flight and completing it is what frees the line. Taking
        // an assignment and returning it would cost every chunk a retry
        // attempt per bounce and fail the upload instead of pausing it.
        if let Some(pc) = payment {
            for (lane, payer) in payers.iter_mut().enumerate() {
                let Some(payer) = payer.as_mut() else {
                    continue;
                };
                if !payer.has_headroom()
                    && payer.account.owed() > 0
                    && let Err(e) = payer.settle(&http, pc).await
                {
                    warn!(target: "hoverfly::upload", "lane {lane}: settle failed: {e}");
                }
                // POST sizing happens per dispatch, in the loop below.
            }
        }
        // Hand out everything the scheduler is willing to dispatch, resizing
        // each metered lane to its *live* headroom immediately before every
        // single assignment.
        //
        // Both halves have to happen per dispatch, not per pass of the outer
        // loop. Each POST adds its body to `pending`, so one up-front answer
        // authorises a whole run of them against headroom only the first
        // actually had — and since the body is built from the lane's
        // `batch_max`, a stale ceiling means the second and third POSTs are
        // each sized as if they were alone on the lane. That is what earns a
        // 402 the client cannot pay: the bytes are in flight, so nothing is
        // owed yet and no cheque changes anything.
        while let Some(a) = {
            let mut anyone_can_take_work = payment.is_none();
            if payment.is_some() {
                for (lane, p) in payers.iter().enumerate() {
                    let Some(p) = p.as_ref() else {
                        // Unmetered lane in a metered run: nothing to size.
                        anyone_can_take_work = true;
                        continue;
                    };
                    // `cap == 0` means no challenge yet: sizing is unknown,
                    // so keep the relay's advertised ceiling rather than
                    // raising it to `MAX` (which would build an unbounded
                    // POST). `affordable_frames` returns `MAX` as the
                    // unknown sentinel — skip the clamp in that case.
                    if p.cap_known() {
                        let affordable = p.affordable_frames();
                        if affordable > 0 && affordable != usize::MAX {
                            sched
                                .set_lane_batch_max(lane, affordable.min(lane_frame_ceiling[lane]));
                        }
                    }
                    if p.has_headroom() {
                        anyone_can_take_work = true;
                    }
                }
            }
            if anyone_can_take_work {
                sched.next(now_ms())
            } else {
                None
            }
        } {
            // Per-lane headroom: the gate above is global, but the scheduler
            // picks the lane. If it picked a metered lane that cannot afford
            // even one frame, hand the assignment straight back (cheap now
            // that `PaymentRequired` no longer burns an attempt) and stop
            // dispatching until something completes — rather than building a
            // full-size POST the relay must refuse.
            if let (Some(_pc), Some(payer)) = (payment, payers[a.lane].as_ref()) {
                if payer.cap_known() && !payer.has_headroom() {
                    sched.on_batch_result(
                        a.batch,
                        crate::pushsched::BatchOutcome::PaymentRequired,
                        now_ms(),
                    );
                    break;
                }
                if payer.cap_known() {
                    let affordable = payer.affordable_frames();
                    if affordable == 0 {
                        sched.on_batch_result(
                            a.batch,
                            crate::pushsched::BatchOutcome::PaymentRequired,
                            now_ms(),
                        );
                        break;
                    }
                }
            }
            let batch: Vec<StampedChunk> = a
                .chunks
                .iter()
                .filter_map(|&i| frames.get(&sched.chunk_addr(i)).cloned())
                .collect();
            let http = http.clone();
            let url = lanes[a.lane].clone();
            let tx = tx.clone();
            let (batch_id, lane, hedge) = (a.batch, a.lane, a.hedge);
            if hedge {
                debug!(target: "hoverfly::upload",
                    "hedging {} straggler(s) onto lane {lane}", batch.len());
            }
            // Metered lane: attach the capability, and bill ourselves for
            // the body by the same arithmetic the relay uses (§8). We count
            // what we *send*; nothing the relay reports enters this number,
            // which is why the two sides can agree without exchanging
            // anything.
            let mut challenge: Option<String> = None;
            if let (Some(pc), Some(payer)) = (payment, payers[lane].as_mut()) {
                let body_bytes: u64 = batch
                    .iter()
                    .map(|c| (crate::pushframe::HEADER_LEN + c.wire.len()) as u64)
                    .sum();
                // Pay first if this body would not fit. Settling on the
                // window alone is not enough: several POSTs dispatch
                // concurrently, so the cap can be crossed before any of
                // them completes and reports back.
                if payer.would_exceed(body_bytes) {
                    if let Err(e) = payer.settle(&http, pc).await {
                        warn!(target: "hoverfly::upload",
                            "lane {lane}: pre-dispatch settle failed: {e}");
                    }
                    // Settling may not have helped: debt only exists for
                    // POSTs the relay has already admitted, so a client that
                    // has saturated its line with *in-flight* bytes has
                    // nothing to pay yet. Dispatching anyway earns a 402 and,
                    // if it keeps happening, fails the chunks outright.
                    // Hand the batch back instead and let it be re-dispatched
                    // once something completes — the same pause a 402 would
                    // cause, without the round trip.
                    if payer.would_exceed(body_bytes) {
                        sched.on_batch_result(
                            batch_id,
                            crate::pushsched::BatchOutcome::PaymentRequired,
                            now_ms(),
                        );
                        continue;
                    }
                }
                match payer.header(&http, pc).await {
                    Ok(h) => challenge = Some(h.to_string()),
                    Err(e) => {
                        warn!(target: "hoverfly::upload",
                            "lane {lane}: cannot obtain a challenge ({e}); pausing it");
                        sched.on_batch_result(
                            batch_id,
                            crate::pushsched::BatchOutcome::PaymentRequired,
                            now_ms(),
                        );
                        continue;
                    }
                }
                payer.account.record_sent(body_bytes);
                in_flight_bytes.insert(batch_id, (lane, body_bytes));
            }
            tokio::spawn(async move {
                post_batch_streaming(
                    &http,
                    url.as_str(),
                    batch_id,
                    lane,
                    &batch,
                    &tx,
                    challenge.as_deref(),
                )
                .await;
            });
        }

        if sched.done() && exhausted {
            break;
        }

        if sched.in_flight() == 0 {
            if sched.done() {
                // Everything admitted so far has landed; go stamp more.
                continue;
            }
            if let Some(reason) = sched.stalled(now_ms()) {
                let stats = sched.lane_stats();
                return Err(ClientError::Pusher(format!(
                    "push stalled ({reason:?}) with {}/{} acked; lanes: {}",
                    sched.acked(),
                    total,
                    stats
                        .iter()
                        .enumerate()
                        .map(|(i, s)| format!(
                            "{i}={:?} ok={} err={}",
                            s.health.expect("health"),
                            s.acked,
                            s.failed
                        ))
                        .collect::<Vec<_>>()
                        .join(" ")
                )));
            }
            // Nothing in flight and nothing dispatchable: every lane is
            // backing off. Sleep exactly until the earliest one is due.
            match sched.next_wake_ms(now_ms()) {
                Some(t) if t > now_ms() => {
                    tokio::time::sleep(std::time::Duration::from_millis(t - now_ms())).await;
                    continue;
                }
                _ => break,
            }
        }

        // Wait for the next event, but never past a pending hedge deadline.
        let wake = sched.next_wake_ms(now_ms());
        let sleep_for = wake
            .map(|t| std::time::Duration::from_millis(t.saturating_sub(now_ms())))
            .unwrap_or(std::time::Duration::from_secs(3600));
        let ev = tokio::select! {
            ev = rx.recv() => ev,
            _ = tokio::time::sleep(sleep_for) => continue,
        };
        let Some(ev) = ev else { break };
        match ev {
            LaneEv::Ack {
                lane,
                addr,
                ok,
                po,
                best_po,
                shallow,
            } => {
                let before = sched.acked();
                sched.on_ack(lane, &addr, ok, now_ms());
                if sched.acked() > before {
                    done_count += 1;
                    if shallow {
                        shallow_n += 1;
                    }
                    if po > 0 {
                        po_sum += u64::from(po);
                        po_n += 1;
                        po_hist[usize::from(po).min(po_hist.len() - 1)] += 1;
                    }
                    if best_po > 0 {
                        best_po_sum += u64::from(best_po);
                        best_po_n += 1;
                    }
                    // The frame is no longer needed by any lane: a Done
                    // chunk is never re-dispatched, and a hedged twin's
                    // later ack is dropped by the scheduler.
                    frames.remove(&addr);
                    if let Some(p) = progress {
                        let t = total_hint.max(sched.total());
                        p(done_count.min(t), t);
                    }
                }
            }
            LaneEv::Done {
                batch,
                lane,
                acked,
                elapsed_ms,
                outcome,
                dedup_bytes,
            } => {
                sched.on_batch_timing(lane, acked, elapsed_ms);
                let needs_payment =
                    matches!(outcome, crate::pushsched::BatchOutcome::PaymentRequired);
                // Turn the in-flight bytes into debt only if the relay
                // actually took them.
                if let Some((sent_lane, sent)) = in_flight_bytes.remove(&batch)
                    && let Some(payer) = payers[lane].as_mut()
                {
                    // Defensive: the Done event carries its lane, which must
                    // match where the bytes were recorded. On mismatch bill
                    // the recorded lane (the one that sent) — never a third
                    // lane.
                    debug_assert_eq!(sent_lane, lane);
                    let _ = sent_lane;
                    // The question is whether the relay *read the body*, not
                    // whether we got a clean answer back. A 402 is refused at
                    // admission, before a byte is read, so it costs nothing
                    // and is not billed by either side. Anything else means
                    // the bytes arrived and were billed — including a stream
                    // that broke halfway through, which is exactly §7.3's
                    // ack-tail case. Billing only clean answers made the
                    // client silently under-count every interrupted POST
                    // while the relay booked it.
                    let reached_relay =
                        !matches!(outcome, crate::pushsched::BatchOutcome::PaymentRequired);
                    payer.account.record_answered(sent, reached_relay);
                    if reached_relay && dedup_bytes > 0 {
                        payer.account.refund_dedup(dedup_bytes);
                    }
                }
                sched.on_batch_result(batch, outcome, now_ms());
                // Settle when the relay asks (402) or when we have crossed
                // the lane's own settlement window. Paying on the window
                // keeps an upload from ever reaching its cap in the first
                // place; paying on 402 is the recovery path when it does.
                if let (Some(pc), Some(payer)) = (payment, payers[lane].as_mut())
                    && (needs_payment || payer.account.should_settle())
                {
                    // A 401 arrives here as `PaymentRequired` (see
                    // `post_batch_streaming`): the cached capability is stale,
                    // so drop it — otherwise the same bad header is retried
                    // until expiry, charging pauses instead of recovering.
                    // Clearing on a 402 too costs one extra challenge GET per
                    // settlement, which is cheap and re-reads the live line.
                    if needs_payment {
                        payer.clear_header();
                    }
                    match payer.settle(&http, pc).await {
                        Ok(Some(c)) => {
                            info!(target: "hoverfly::upload",
                                "lane {lane}: paid, cumulative now {c}");
                            // Restores the lane to the health it had before
                            // it ran out of credit — a 402 never charged the
                            // failure streak, so this is not a re-warm.
                            sched.fund_lane(lane);
                        }
                        Ok(None) if needs_payment => {
                            // 402 with nothing owed above the dust floor
                            // means the two sides disagree about the
                            // ledger, and retrying the POST cannot fix it.
                            // Almost always this is debt carried from an
                            // earlier run: the relay's ledger is durable
                            // and ours is not, so it is still counting a
                            // residual we settled below the dust floor and
                            // then forgot. Ask what it thinks we owe and
                            // pay that.
                            match payer.reconcile(&http, pc).await {
                                Ok(true) => match payer.settle(&http, pc).await {
                                    Ok(Some(c)) => {
                                        info!(target: "hoverfly::upload",
                                            "lane {lane}: reconciled with relay ledger, \
                                             paid cumulative {c}");
                                        sched.fund_lane(lane);
                                    }
                                    Ok(None) => {
                                        unpayable_402(&mut sched, lane, payer);
                                    }
                                    Err(e) => {
                                        warn!(target: "hoverfly::upload",
                                            "lane {lane}: payment after reconcile failed: {e}");
                                    }
                                },
                                Ok(false) => {
                                    unpayable_402(&mut sched, lane, payer);
                                }
                                Err(e) => {
                                    warn!(target: "hoverfly::upload",
                                        "lane {lane}: reconcile failed: {e}");
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            warn!(target: "hoverfly::upload", "lane {lane}: payment failed: {e}");
                        }
                    }
                }
            }
        }
    }

    // Settle whatever is left before returning. Without this the relay is
    // left holding debt for work it did and the client walks away — and on
    // the next run that debt still counts against the credit line, so the
    // account starts closer to its cap for no reason. Only the residual
    // below the lane's dust floor is left over, which is a cheque the relay
    // would refuse anyway.
    // The run can finish with POSTs still draining: the loop exits once
    // every *chunk* is acked, which happens before every *response* has
    // closed. Those bodies were read by the relay and billed, so they are a
    // debt — leaving them in `pending` meant the final settlement saw
    // nothing to pay and the relay kept the balance forever.
    if payment.is_some() {
        // The loop exits once every *chunk* is acked, which happens before
        // every *response* has closed. Those bodies were read and billed, so
        // convert each stranded POST on the lane that sent it.
        for (_, (sent_lane, sent)) in in_flight_bytes.drain() {
            if let Some(payer) = payers.get_mut(sent_lane).and_then(|p| p.as_mut()) {
                payer.account.record_answered(sent, true);
            }
        }
    }
    if let Some(pc) = payment {
        for (lane, payer) in payers.iter_mut().enumerate() {
            let Some(payer) = payer.as_mut() else {
                continue;
            };
            match payer.settle(&http, pc).await {
                Ok(Some(c)) => info!(target: "hoverfly::upload",
                    "lane {lane}: final settlement, cumulative {c}"),
                Ok(None) => {
                    if payer.account.owed() > 0 {
                        info!(target: "hoverfly::upload",
                            "lane {lane}: {} PLUR left unsettled (below the lane's dust floor)",
                            payer.account.owed());
                    }
                }
                Err(e) => warn!(target: "hoverfly::upload",
                    "lane {lane}: final settlement failed: {e}"),
            }
        }
    }

    let total = sched.total();
    let stats = sched.lane_stats();
    info!(target: "hoverfly::upload",
        "pusher run: {}/{} acked ({} hedged) over {} lane(s): {}",
        sched.acked(), total, sched.hedges(), lanes.len(),
        stats.iter().enumerate()
            .map(|(i, s)| format!("{i}:{}ok/{}err@{:.1}/s", s.acked, s.failed, s.rate))
            .collect::<Vec<_>>().join(" "));
    if shallow_n > 0 {
        warn!(target: "hoverfly::upload",
            "{shallow_n}/{} chunk(s) landed on a SHALLOW receipt — forwarded but not \
             confirmed stored by a neighborhood peer; those may be unretrievable",
            sched.acked());
    }
    if po_n > 0 {
        let top: Vec<String> = po_hist
            .iter()
            .enumerate()
            .filter(|(_, n)| **n > 0)
            .map(|(po, n)| format!("{po}:{n}"))
            .collect();
        let best = if best_po_n > 0 {
            format!("{:.2}", best_po_sum as f64 / best_po_n as f64)
        } else {
            "n/a".into()
        };
        info!(target: "hoverfly::upload",
            "receipt depth: mean po {:.2} (best available {best}) over {po_n} receipt(s) \
             (alpha={}) — {}",
            po_sum as f64 / po_n as f64, cfg_alpha, top.join(" "));
    }

    if sched.acked() < total {
        return Err(ClientError::Pusher(format!(
            "{} of {total} chunks unacked across {} lane(s)",
            total - sched.acked(),
            lanes.len()
        )));
    }
    Ok(())
}

/// Chunks stamped per refill of the scheduler. Big enough to keep every
/// lane's pipeline full, small enough that a streaming upload's peak memory
/// is a window of frames rather than the whole file.
#[cfg(not(target_arch = "wasm32"))]
const PUSH_WINDOW: usize = 1024;

/// Push through a single relay. Same driver, one lane (so no hedging).
#[cfg(not(target_arch = "wasm32"))]
pub async fn push_via_pusher(
    pusher_url: &str,
    chunks: Vec<StampedChunk>,
    progress: Option<&ProgressFn>,
) -> Result<(), ClientError> {
    push_via_pushers(
        std::slice::from_ref(&pusher_url.to_string()),
        chunks,
        progress,
    )
    .await
}

/// Push a windowed [`UploadStreamer`] through relays.
///
/// Stamps one window at a time and admits it to the scheduler while earlier
/// windows are still on the wire, so peak memory is one window of frames
/// rather than the whole file. This is what the browser has been doing since
/// the streamer landed; the native `--pusher` path used the one-shot
/// prepare-everything-first route and would OOM on large files.
#[cfg(not(target_arch = "wasm32"))]
pub async fn push_stream_via_pushers(
    pusher_urls: &[String],
    streamer: UploadStreamer,
    progress: Option<&ProgressFn>,
) -> Result<ChunkAddress, ClientError> {
    push_stream_via_pushers_paid(pusher_urls, streamer, progress, None).await
}

/// A 402 arrived that no cheque can clear. Decide whether the lane is
/// merely busy or genuinely stuck.
///
/// The relay refuses on `owed + reserved`, and only `owed` is payable —
/// reservations are bodies it is still reading. So a lane can be over its
/// line with a debt below the dust floor, which is not a disagreement and
/// not something paying fixes: those bytes simply have to land. Leaving
/// the lane `Unfunded` in that case parks it for good, because only a
/// successful settle re-funds it and no settle is possible. That is an
/// upload that stops with chunks pending and the relay reporting no errors.
///
/// Re-funding is safe against a busy loop: `has_headroom` binds on
/// `outstanding`, so nothing is dispatched until the in-flight bytes
/// actually clear.
#[cfg(not(target_arch = "wasm32"))]
fn unpayable_402(
    sched: &mut crate::pushsched::Scheduler,
    lane: usize,
    payer: &crate::payer::LanePayer,
) {
    if payer.account.pending() > 0 {
        debug!(target: "hoverfly::upload",
            "lane {lane}: over its line on bytes in flight, not debt; \
             resuming once they land");
        sched.fund_lane(lane);
        return;
    }
    warn!(target: "hoverfly::upload",
        "lane {lane}: 402 with nothing in flight and nothing payable — \
         ledger disagreement");
}

/// As [`push_stream_via_pushers`], but able to pay metered lanes.
///
/// `payment` is `None` for every `open` lane, which is the default and the
/// only thing production runs today. When present, the driver fetches a
/// challenge per lane, bills itself by the same arithmetic the relay uses,
/// and settles with a cumulative cheque when the lane's window is crossed
/// or it answers 402 (`docs/pusher-incentives.md` §12).
#[cfg(not(target_arch = "wasm32"))]
pub async fn push_stream_via_pushers_paid(
    pusher_urls: &[String],
    mut streamer: UploadStreamer,
    progress: Option<&ProgressFn>,
    payment: Option<&crate::payer::PaymentConfig>,
) -> Result<ChunkAddress, ClientError> {
    let root = streamer.root();
    let total = streamer.total_chunks();
    drive_pushers(
        pusher_urls,
        total,
        move |want| streamer.next_batch(want),
        progress,
        payment,
    )
    .await?;
    Ok(root)
}

/// Event from an in-flight POST back to the scheduler driver.
#[cfg(not(target_arch = "wasm32"))]
enum LaneEv {
    Ack {
        lane: usize,
        addr: [u8; 32],
        ok: bool,
        /// Receipt proximity order reported by the relay — how deep into the
        /// chunk's own neighborhood it actually landed.
        po: u8,
        /// Best proximity the relay's dispatcher could reach for this chunk.
        best_po: u8,
        /// The relay accepted this chunk on a *shallow* receipt: forwarded
        /// into the network, but no neighborhood storer confirmed it.
        shallow: bool,
    },
    Done {
        batch: u64,
        lane: usize,
        acked: usize,
        elapsed_ms: u64,
        outcome: crate::pushsched::BatchOutcome,
        /// Body bytes the relay served from its recent-ack cache and billed
        /// at zero (§8.2), so the client can subtract them and stay in step.
        dedup_bytes: u64,
    },
}

/// POST one batch and forward each NDJSON ack to the driver as it arrives.
///
/// Acks are streamed rather than collected because the relay now resolves
/// chunks independently: waiting for the whole response before crediting
/// anything would put the tail of every batch back on the critical path and
/// blind the hedger to which chunks are actually stuck.
#[cfg(not(target_arch = "wasm32"))]
async fn post_batch_streaming(
    http: &reqwest::Client,
    push_url: &str,
    batch_id: u64,
    lane: usize,
    batch: &[StampedChunk],
    tx: &tokio::sync::mpsc::UnboundedSender<LaneEv>,
    // Metered lanes only: the signed admission capability
    // (`docs/pusher-incentives.md` §7.2). `None` on an `open` lane, which
    // is every production lane today.
    challenge: Option<&str>,
) {
    use crate::pushsched::BatchOutcome;
    use futures::StreamExt;

    let t0 = std::time::Instant::now();
    let body = crate::pushframe::encode_batch(batch);
    let mut acked = 0usize;

    let mut dedup_bytes: u64 = 0;
    let finish = |outcome: BatchOutcome, acked: usize, dedup_bytes: u64| {
        let _ = tx.send(LaneEv::Done {
            batch: batch_id,
            lane,
            acked,
            elapsed_ms: t0.elapsed().as_millis() as u64,
            outcome,
            dedup_bytes,
        });
    };

    let mut req = http.post(push_url).body(body);
    if let Some(c) = challenge {
        req = req.header(crate::challenge::CHALLENGE_HEADER, c);
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(target: "hoverfly::upload", "lane {push_url} POST failed: {e}");
            finish(BatchOutcome::Failed(e.to_string()), 0, 0);
            return;
        }
    };
    if !resp.status().is_success() {
        let code = resp.status();
        let txt = resp.text().await.unwrap_or_default();
        // A 402 is a bill, not a fault. Reporting it as `Failed` would
        // charge lane health for a routine settlement and retire a healthy
        // lane after five of them (§12); `PaymentRequired` pauses it
        // instead, and `Scheduler::fund_lane` restores it once a cheque
        // clears.
        if code == reqwest::StatusCode::PAYMENT_REQUIRED {
            info!(target: "hoverfly::upload",
                "lane {push_url} requires payment: {}", txt.trim());
            finish(BatchOutcome::PaymentRequired, 0, 0);
            return;
        }
        // A 401 is a stale/invalid capability (expired challenge, wrong
        // origin/account/batch) — not a fault in the lane. Pausing (not
        // failing) lets the driver drop the cached header, refetch, and
        // retry without charging lane health.
        if code == reqwest::StatusCode::UNAUTHORIZED {
            info!(target: "hoverfly::upload",
                "lane {push_url} rejected capability ({code}): {}", txt.trim());
            finish(BatchOutcome::PaymentRequired, 0, 0);
            return;
        }
        warn!(target: "hoverfly::upload",
            "lane {push_url} rejected batch ({code}): {}", txt.trim());
        finish(BatchOutcome::Failed(format!("http {code}")), 0, 0);
        return;
    }

    let mut stream = resp.bytes_stream();
    let mut buf = Vec::new();
    let handle = |line: &[u8], acked: &mut usize, dedup_bytes: &mut u64| {
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(line) else {
            return;
        };
        let Some(a) = v.get("a").and_then(|a| a.as_str()) else {
            return;
        };
        let Ok(raw) = hex::decode(a) else { return };
        if raw.len() != 32 {
            return;
        }
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&raw);
        let ok = v.get("s").and_then(|s| s.as_str()) == Some("ok");
        if ok {
            *acked += 1;
        }
        let po = v.get("po").and_then(|p| p.as_u64()).unwrap_or(0) as u8;
        let best_po = v.get("bpo").and_then(|p| p.as_u64()).unwrap_or(0) as u8;
        let shallow = v.get("shallow").and_then(|s| s.as_bool()).unwrap_or(false);
        // The relay served this from its recent-ack cache and billed zero
        // for it (§8.2). Subtract the same bytes here or our total drifts
        // above the relay's and the next cheque is refused.
        if v.get("dedup").and_then(|d| d.as_bool()).unwrap_or(false)
            && let Some(c) = batch.iter().find(|c| c.addr == addr)
        {
            *dedup_bytes += (crate::pushframe::HEADER_LEN + c.wire.len()) as u64;
        }
        let _ = tx.send(LaneEv::Ack {
            lane,
            addr,
            ok,
            po,
            best_po,
            shallow,
        });
    };

    while let Some(part) = stream.next().await {
        match part {
            Ok(bytes) => {
                buf.extend_from_slice(&bytes);
                while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = buf.drain(..=nl).collect();
                    handle(&line[..line.len() - 1], &mut acked, &mut dedup_bytes);
                }
            }
            Err(e) => {
                warn!(target: "hoverfly::upload", "lane {push_url} stream error: {e}");
                finish(BatchOutcome::Failed(e.to_string()), acked, dedup_bytes);
                return;
            }
        }
    }
    if !buf.is_empty() {
        handle(&buf, &mut acked, &mut dedup_bytes);
    }
    finish(BatchOutcome::Answered, acked, dedup_bytes);
}

/// Read a lane's `/v1/status` advertisement.
///
/// Every field is best-effort: a lane that is asleep, old, or simply terse
/// yields `LaneInfo::default()` and gets scheduled on priors rather than
/// being excluded.
#[cfg(not(target_arch = "wasm32"))]
async fn fetch_lane_info(
    http: &reqwest::Client,
    base_url: &str,
    price_ceiling: u128,
    pin: Option<&crate::payer::LanePin>,
    expected_chain_id: Option<u64>,
) -> crate::pushsched::LaneInfo {
    use crate::pushsched::LaneInfo;
    let url = format!("{}/v1/status", base_url.trim_end_matches('/'));
    // Generous: free-tier instances cold-start on the first request.
    let Ok(resp) = http
        .get(&url)
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await
    else {
        warn!(target: "hoverfly::upload", "lane {base_url}: /v1/status unreachable; using defaults");
        return LaneInfo::default();
    };
    let Ok(v) = resp.json::<serde_json::Value>().await else {
        return LaneInfo::default();
    };
    let overlay = v
        .get("overlay")
        .and_then(|s| s.as_str())
        .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
    // The signed price quote (§7.3). Verified, never merely parsed: an
    // unsigned or unverifiable price is repudiable in both directions, so a
    // quote that does not check out leaves the lane looking unmetered rather
    // than looking free.
    let (price_plur_per_kib, hard_enforcement, quote) = match v.get("payment") {
        Some(pay) if !pay.is_null() => {
            // The overlay cross-check is skipped here: it needs the
            // network id, which this driver does not carry, and it is the
            // *optional* half of verification. The signature and (where a
            // caller supplies one) the pin are what establish identity;
            // deriving the overlay only turns the lane's own `overlay`
            // field from an assertion into a check. A caller that pins
            // does the full version.
            match crate::payer::PaymentQuote::verify(pay, None, 0, pin, price_ceiling) {
                Ok(q) => {
                    if let Some(expected) = expected_chain_id
                        && q.chain_id != expected
                    {
                        warn!(target: "hoverfly::upload",
                            "lane {base_url}: quotes chain {} but client pays on chain {expected}; treating as unmetered",
                            q.chain_id);
                        (None, false, None)
                    } else {
                        if pin.is_none() {
                            warn!(target: "hoverfly::upload",
                                "lane {base_url}: metered but unpinned — trusting first-seen identity 0x{}/0x{} for this run (pass --lane-pin to pin)",
                                hex::encode(q.node_eth_address),
                                hex::encode(q.beneficiary));
                        }
                        (
                            Some(q.params.price_plur_per_kib),
                            q.hard_enforcement,
                            Some(q),
                        )
                    }
                }
                Err(e) => {
                    warn!(target: "hoverfly::upload",
                        "lane {base_url}: payment quote rejected ({e}); treating as unmetered");
                    (None, false, None)
                }
            }
        }
        _ => (None, false, None),
    };
    LaneInfo {
        overlay,
        price_plur_per_kib,
        hard_enforcement,
        quote,
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
    }
}

/// Populate the daemon's [`ChunkCache`] from a batch of stamped chunks
/// produced by `prepare_upload_*`. Called by the `_with_pool` variants
/// before they hand `work` over to `push_chunks_with_pool`, so the
/// cache is hot the moment our peers (or bzz.limo) start asking us
/// for these chunks via retrieval — they're served directly from RAM
/// without waiting for pushsync propagation.
fn populate_cache(cache: &crate::cache::ChunkCache, work: &[StampedChunk]) {
    use bytes::Bytes;
    cache.put_many(work.iter().map(|c| {
        (
            c.addr,
            Bytes::copy_from_slice(&c.wire),
            Bytes::copy_from_slice(&c.stamp),
        )
    }));
}

/// Split + stamp data, returning the root and the stamped chunks ready
/// for pushsync. Pure CPU; no network.
///
/// `signer` is used **only** for stamping — its eth address must be
/// the batch owner of `batch_id_hex`, and its alloy signer signs each
/// chunk's postage stamp. The returned [`StampedChunk`]s carry no
/// reference to the signer; they can be pushed by any libp2p overlay
/// (the network identity for pushing is supplied separately to
/// [`push_chunks_with_pool`] via its `Transport`). This decoupling is
/// what enables the multi-worker upload model: a coordinator with
/// the batch owner key stamps chunks, then ships them to N workers
/// with ephemeral overlay keys for pushing.
/// Compute the BMT/content root of `data` without stamping, pushing, or
/// any network or key access. This is the bare content-addressed root
/// produced by nectar's chunked-file split — identical to what
/// [`prepare_upload_bytes`] derives as its `root`, and to the
/// `file_root` that an `upload --raw` would yield.
///
/// Returns `(root, chunk_count)`. The chunk count is the total number of
/// content + intermediate chunks the file splits into (the same value
/// the upload path logs), which the caller can use to size a pool or
/// to compute the chunk-address set for proximity-targeted discovery.
///
/// Note: this is **not** the same hash `hoverfly upload` prints by
/// default — the default (non-`--raw`) upload wraps the file in a
/// single-entry mantaray manifest, whose root differs. Use
/// [`prepare_upload_file_with_manifest`] (or just split + manifest) to
/// derive that manifest root.
pub fn bmt_root(data: &[u8], redundancy: Level) -> Result<(ChunkAddress, usize), ClientError> {
    let (root, chunks) = split_chunks(data, redundancy)?;
    Ok((root, chunks.len()))
}

/// Compute the multi-entry mantaray manifest root of a collection
/// (e.g. the contents of a tar) without stamping, pushing, or any
/// network or key access. This is the exact root [`upload_collection`]
/// produces for the same `files` / `index_document` / `error_document`
/// inputs — split each file, build the collection manifest, return its
/// root. Use it to pre-compute the reference for a `*.tar` upload.
///
/// Returns `(manifest_root, unique_chunk_count)`. The chunk count is the
/// number of *unique* chunk addresses across all files plus the manifest
/// chunks (deduplicated exactly as `upload_collection` does before
/// stamping), so it reflects the real push workload rather than the raw
/// pre-dedup total.
pub fn collection_root(
    files: &[UploadFile],
    index_document: Option<&str>,
    error_document: Option<&str>,
    redundancy: Level,
) -> Result<(ChunkAddress, usize), ClientError> {
    use crate::manifest::CollectionEntry;

    if files.is_empty() {
        return Err(ClientError::Manifest("collection is empty".into()));
    }

    let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    let mut entries: Vec<CollectionEntry> = Vec::with_capacity(files.len());
    for f in files {
        let (file_root, file_chunks) = split_chunks(&f.data, redundancy)?;
        for (addr, _wire) in file_chunks {
            let mut addr_bytes = [0u8; 32];
            addr_bytes.copy_from_slice(addr.as_bytes());
            seen.insert(addr_bytes);
        }
        entries.push(CollectionEntry {
            path: f.path.clone(),
            reference: file_root,
            content_type: f.content_type.clone(),
        });
    }

    let (manifest_root, manifest_chunks) =
        crate::manifest::build_collection_manifest(&entries, index_document, error_document)
            .map_err(|e| ClientError::Manifest(e.to_string()))?;
    for (addr, _wire) in manifest_chunks.iter() {
        let mut addr_bytes = [0u8; 32];
        addr_bytes.copy_from_slice(addr.as_bytes());
        seen.insert(addr_bytes);
    }

    Ok((manifest_root, seen.len()))
}

pub fn prepare_upload_bytes(
    signer: &SwarmSigner,
    batch_id_hex: &str,
    depth: u8,
    immutable: bool,
    data: &[u8],
    redundancy: Level,
) -> Result<(ChunkAddress, Vec<StampedChunk>), ClientError> {
    let batch_id = parse_batch_id(batch_id_hex)?;

    let (root, stamp_in) = split_chunks(data, redundancy)?;
    info!(target: "hoverfly::upload", "split {} bytes into {} chunks (root {}, redundancy {})",
        data.len(), stamp_in.len(), root, redundancy);

    let mut stamper = build_stamper(signer, batch_id, depth, immutable)?;
    let work = stamp_chunks_parallel(&mut stamper, stamp_in)?;
    Ok((root, work))
}

/// A session and the peer overlay it talks to, kept together so we can
/// route each chunk to the session whose peer is closest to it. The
/// `PeerSession` inside is replaced on the fly when the driver retires
/// itself after accumulating too much client-side mirrored ghost balance;
/// a
/// brand-new libp2p connection is dialed to reset bee's `ghostBalance`.
struct SessionEntry {
    overlay: SwarmAddress,
    overlay_hex: String,
    underlay: libp2p::Multiaddr,
    session: std::sync::Mutex<PeerSession>,
    /// Pre-warmed replacement session. Populated by the upload loop
    /// once the active session crosses the ghost-balance pre-warm
    /// threshold; if present, `try_push_with_rotation` swaps it in
    /// instead of dialing synchronously. `bool` flags whether a pre-warm
    /// is already in flight (so we don't queue two for the same entry).
    pending: std::sync::Mutex<Option<PeerSession>>,
    prewarm_inflight: std::sync::atomic::AtomicBool,
    /// Consecutive rotation-dial failures observed on this entry. We
    /// only flag it dead once it crosses [`DEAD_STRIKES`]; a single
    /// transient peer hiccup shouldn't shrink the live pool.
    failure_strikes: std::sync::atomic::AtomicU32,
    /// Unix-seconds timestamp before which this entry is considered
    /// "dead" and skipped by the dispatcher. Default `0` = always-live.
    skip_until_unix: std::sync::atomic::AtomicU64,
    /// Storage radius advertised by this peer, learned from pushsync
    /// receipts. Bee's AOR rule: a chunk is in peer X's reserve iff
    /// `PO(chunk_addr, X.overlay) >= X.storage_radius`. Used by the
    /// per-chunk dispatcher to prefer peers that will actually store
    /// the chunk (full receipt) over peers that will only forward it
    /// (shallow receipt → bee re-routes, adds latency). `0` =
    /// unknown (default before any receipt); treated by the
    /// dispatcher as "might be in AOR" (optimistic).
    storage_radius: std::sync::atomic::AtomicU8,
    /// EWMA of observed push round-trip latency in microseconds.
    /// Updated after every push attempt (success OR failure — a
    /// failed-via-timeout attempt also signals a slow peer). The
    /// dispatcher's proximity sort uses this as a tie-breaker
    /// secondary key and applies a PO penalty to peers whose EWMA
    /// crosses thresholds, shifting load to faster peers within
    /// the same PO tier.
    ///
    /// Value `0` means "no samples yet" — treated as optimistic
    /// (no penalty) so newly-discovered peers aren't penalized
    /// before they have a chance to prove themselves.
    push_latency_ewma_us: std::sync::atomic::AtomicU64,
    /// Lifetime count of successful pushsync receipts on this
    /// session entry. Used by the daemon's auto-iteration loop
    /// to rank entries when picking new vanity-overlay anchor
    /// targets — peers that consistently deliver receipts are
    /// the ones we want to anchor to next time.
    push_success_count: std::sync::atomic::AtomicU64,
    /// Live count of in-flight pushes currently dispatched to this
    /// peer. Incremented before each push attempt, decremented when
    /// the push future completes (success or fail). The dispatcher
    /// skips entries whose `inflight_pushes >= IN_FLIGHT_CAP` from
    /// the candidate list, forcing load distribution across more
    /// peers instead of stacking many concurrent pushes on the top-
    /// PO subset.
    ///
    /// Why this matters: at our buffer=128 chunks × CHUNK_PEER_PARALLELISM=3
    /// fan-out, the same handful of "top-PO" peers gets 5-7 concurrent
    /// pushes during bursts. Each push debits the peer ~6.75K PLUR;
    /// bee's per-peer refresh rate (4.5M/s full, 450K/s light) is the
    /// natural rate-limit per peer. When concurrent pushes overshoot
    /// the per-peer refresh budget the peer's accounting goes into
    /// overdraft → bee returns Overdraft → dispatcher rotates → tail
    /// latency. Bee-light avoids this by routing each chunk to a
    /// single neighbor per its kademlia AOR rule, distributing load
    /// across all 131 connected peers. We don't have kademlia, but
    /// the cap is a cheap approximation: it caps concurrent debt
    /// per peer, forcing fan-out wider when a few peers saturate.
    inflight_pushes: std::sync::atomic::AtomicU32,
}

impl SessionEntry {
    fn snapshot(&self) -> PeerSession {
        self.session.lock().expect("session mutex poisoned").clone()
    }

    /// Replace the stored session with `new`. The previous session's
    /// `cmd_tx` is dropped, which signals its driver to shut down once
    /// any in-flight pushes finish.
    fn replace(&self, new: PeerSession) {
        let mut guard = self.session.lock().expect("session mutex poisoned");
        *guard = new;
    }

    /// Take a pre-warmed session if one is ready. Returns `None` if no
    /// pre-warm has completed yet — caller falls back to dialing sync.
    fn take_pending(&self) -> Option<PeerSession> {
        self.pending.lock().expect("pending mutex poisoned").take()
    }

    /// True if a pre-warmed session is already waiting in the slot.
    /// Used by the dispatcher's cooldown pre-filter to keep entries
    /// whose live session is dead but whose rotation path can swap in
    /// the pre-warm without paying a fresh dial (so the per-peer dial
    /// rate limit doesn't apply).
    fn has_pending(&self) -> bool {
        self.pending
            .lock()
            .expect("pending mutex poisoned")
            .is_some()
    }

    /// Store a freshly-dialed session as the pre-warmed replacement.
    fn store_pending(&self, session: PeerSession) {
        let mut guard = self.pending.lock().expect("pending mutex poisoned");
        *guard = Some(session);
    }

    /// True if the dispatcher should skip this entry for chunks
    /// dispatched right now (peer has been seen to fail recently).
    fn is_dead(&self) -> bool {
        let deadline = self
            .skip_until_unix
            .load(std::sync::atomic::Ordering::Relaxed);
        deadline > crate::peers::now_unix()
    }

    /// Reset the failure-strike counter on a successful push so a
    /// previously-flaky peer doesn't get marked dead by stale
    /// accumulated strikes after it recovers.
    fn clear_strikes(&self) {
        self.failure_strikes
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    /// Record one rotation-dial failure. Returns `true` (and arms the
    /// dead window) only once the entry crosses [`DEAD_STRIKES`] —
    /// a single transient failure no longer shrinks the live pool.
    fn record_failure(&self, secs: u64) -> bool {
        let strikes = self
            .failure_strikes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        if strikes >= DEAD_STRIKES {
            self.mark_dead(secs)
        } else {
            false
        }
    }

    /// Monotonically bump the recorded storage radius if `value`
    /// is higher than what's currently stored. Called whenever we
    /// learn something new about this peer's depth.
    fn observe_storage_radius(&self, value: u8) {
        let prev = self
            .storage_radius
            .load(std::sync::atomic::Ordering::Relaxed);
        if value > prev {
            self.storage_radius
                .store(value, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Record an observed push latency. Updates the EWMA with
    /// `alpha = 0.25` (fast adaptation — recent samples dominate
    /// after ~4 pushes). A push that ends in timeout / error counts
    /// as a 5s sample so the slow-peer penalty kicks in quickly.
    ///
    /// Empirical from the trace data: ~10 peers contribute >40% of
    /// the 5s tail. Without this signal the proximity sort sends
    /// them as much work as fast peers, since they have the same
    /// PO from any given chunk address.
    fn observe_push_latency(&self, observed_us: u64) {
        let prev = self
            .push_latency_ewma_us
            .load(std::sync::atomic::Ordering::Relaxed);
        // Integer EWMA: new = (prev*3 + observed) / 4 (alpha = 0.25)
        let new = if prev == 0 {
            observed_us
        } else {
            (prev.saturating_mul(3).saturating_add(observed_us)) / 4
        };
        self.push_latency_ewma_us
            .store(new, std::sync::atomic::Ordering::Relaxed);
    }

    /// Lifetime count of successful pushsync receipts on this entry.
    /// Read by the daemon's auto-iteration loop to identify the top
    /// peers across a session and propose them as new vanity-overlay
    /// anchors.
    pub fn push_success_count(&self) -> u64 {
        self.push_success_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Current in-flight push count on this entry. The dispatcher
    /// reads this to skip entries already at [`IN_FLIGHT_CAP`] when
    /// picking peers for a chunk, forcing load distribution across
    /// more peers (closer to bee's kademlia AOR routing).
    fn inflight_pushes(&self) -> u32 {
        self.inflight_pushes
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Penalty (in PO units) applied to this peer's effective PO
    /// during proximity sorting, based on its push-latency EWMA.
    /// Slow peers get demoted so faster peers within the same PO
    /// tier (or close to it) are preferred. `0` if no samples yet
    /// (newly-discovered peers aren't penalized until they fail).
    ///
    /// Thresholds chosen from the trace data: median push is ~60ms,
    /// p95 is ~5s. Anything above 1s is firmly in the tail.
    ///
    /// Currently unused — bee's per-entry skiplist (`record_failure`
    /// + DEAD_SKIP_SECS=15) is the primary mechanism for shifting
    /// load away from slow peers. Kept as a building block for a
    /// future "demote without parking" path that might be useful
    /// when the pool is too small to afford parking peers entirely.
    #[allow(dead_code)]
    fn latency_penalty(&self) -> u8 {
        let us = self
            .push_latency_ewma_us
            .load(std::sync::atomic::Ordering::Relaxed);
        match us {
            0 => 0,                  // unknown — give the benefit of the doubt
            n if n < 500_000 => 0,   // <500ms = fast, no penalty
            n if n < 1_500_000 => 1, // 500ms–1.5s = mildly slow
            n if n < 3_000_000 => 3, // 1.5–3s = noticeably slow
            _ => 6,                  // >3s = avoid unless no alternative
        }
    }

    /// Latency-aware per-peer in-flight cap. Fast peers (proven by
    /// their observed push EWMA) get a wider cap so they carry more
    /// of the upload's load; slow peers get a tighter cap so their
    /// tail latency doesn't drown the dispatcher.
    ///
    /// Buckets (EWMA push latency):
    /// - 0 (unknown / fresh peer): [`IN_FLIGHT_CAP`] = 4. Default
    ///   trust until proven otherwise.
    /// - < 200 ms (fast — at or near bee's 60 ms median): 2 ×
    ///   [`IN_FLIGHT_CAP`] = 8. Fast peers can handle more
    ///   concurrent substreams without yamux contention because
    ///   each push completes before the next stacks on.
    /// - 200 ms – 2 s (medium): [`IN_FLIGHT_CAP`] = 4. Base cap.
    /// - ≥ 2 s (slow tail — likely many retries, NAT'd, or
    ///   ghost-overdrawing): [`IN_FLIGHT_CAP`] / 2 = 2. Half the
    ///   base so the dispatcher walks past them faster when picking
    ///   fan-out targets.
    ///
    /// Why this works where uniform `cap = 8` failed (590 KiB/s
    /// median vs 665 at cap = 4): the regression was yamux substream
    /// contention per session — running 8 simultaneous pushsync
    /// substreams over a single connection competed for the same
    /// yamux flow-control window. Fast peers don't have this
    /// problem because their pushes complete quickly enough that the
    /// 8 substreams aren't all simultaneous in practice; slow peers
    /// do, and they're the ones we tighten here.
    fn inflight_cap(&self) -> u32 {
        let us = self
            .push_latency_ewma_us
            .load(std::sync::atomic::Ordering::Relaxed);
        match us {
            0 => IN_FLIGHT_CAP,
            n if n < 200_000 => IN_FLIGHT_CAP * 2,
            n if n < 2_000_000 => IN_FLIGHT_CAP,
            _ => (IN_FLIGHT_CAP / 2).max(1),
        }
    }

    /// Returns whether this peer is in the chunk's AOR per our latest
    /// radius observation. `None` if no observation yet — dispatcher
    /// treats unknown as "potentially yes" rather than excluding
    /// (a known-out-of-AOR peer is worse than an unknown one).
    fn in_aor(&self, chunk_po: u8) -> Option<bool> {
        let sr = self
            .storage_radius
            .load(std::sync::atomic::Ordering::Relaxed);
        if sr == 0 { None } else { Some(chunk_po >= sr) }
    }

    /// Mark this entry as dead for `secs` seconds. Subsequent chunks
    /// skip it during proximity ordering. Returns `true` only on the
    /// first call within a dead window — the caller can use this to
    /// log "peer marked dead" exactly once instead of once per
    /// concurrently-failing chunk dispatch.
    fn mark_dead(&self, secs: u64) -> bool {
        let now = crate::peers::now_unix();
        let was_alive = self
            .skip_until_unix
            .load(std::sync::atomic::Ordering::Relaxed)
            <= now;
        let until = now.saturating_add(secs);
        self.skip_until_unix
            .store(until, std::sync::atomic::Ordering::Relaxed);
        was_alive
    }
}

/// How long to skip a session after it crosses [`DEAD_STRIKES`]
/// consecutive rotation-dial failures. Sized to outlast both a
/// rotation-dial cluster (mass-correlated retirement on a large pool
/// at high `--concurrency`) and bee's typical ghost-overdraw blocklist
/// window (~20-60 s). Too short and a parked entry revives straight
/// into more strikes; too long and a transiently-down peer stays out
/// of rotation longer than necessary.
const DEAD_SKIP_SECS: u64 = 15;

/// Number of consecutive rotation-dial failures we tolerate on a
/// single entry before flagging it dead. A single transient hiccup
/// (peer ghost-balance-retired, brief network blip) shouldn't shrink
/// the live pool; a peer that errors three pushes in a row is
/// genuinely broken for the moment.
const DEAD_STRIKES: u32 = 3;

/// Maximum concurrent pushes per pool entry. Capped at 4: with our
/// CHUNK_PEER_PARALLELISM=3 fan-out and buffer=128 chunks in flight,
/// the dispatcher would otherwise stack 5-7 concurrent pushes on the
/// few top-PO peers per upload. At ~6.75K PLUR per chunk and 60ms
/// median push latency, that's ~675K PLUR/s of debt per saturated
/// peer — already overshooting bee's per-peer refresh rate (450K/s
/// for light nodes, 4.5M/s for full nodes), causing accounting
/// overdrafts and forcing dispatcher rotation.
///
/// Bee-light avoids this by routing each chunk to ONE peer per its
/// kademlia AOR rule, distributing load across all 131 connected
/// peers. We don't have kademlia, but capping per-peer in-flight
/// pushes forces our dispatcher to fan out wider when the top
/// candidates are busy. The cap value 4 is the empirical sweet
/// spot — bumping to 8 trades wait-for-cap dispatch failures for
/// yamux substream contention per session, and median throughput
/// regresses ~10% (515 → 590 with pool=64, 665 → 590 with pool=128).
///
/// Tradeoff: dispatcher may have to wait for a capped peer to drain
/// before retrying that peer, but the alternative was overdraft +
/// 500 ms retry penalty per failed dispatch, so the cap is a net
/// improvement for typical workloads.
const IN_FLIGHT_CAP: u32 = 4;

const PREWARM_GHOST_BALANCE_PLUR: u64 =
    GHOST_BALANCE_LIMIT_PLUR * GHOST_BALANCE_PREWARM_NUMERATOR / GHOST_BALANCE_PREWARM_DENOMINATOR;

/// A long-lived pool of peer sessions usable across multiple uploads.
/// Construct with [`SessionPool::open`]. Pre-warm rotation, mid-upload
/// session retirement, and accounting state are all handled internally —
/// once opened, a pool can be re-used (e.g. by the daemon) for many
/// upload requests without paying the dial-fill cost each time.
///
/// Internally the pool is a `Vec<Arc<SessionEntry>>` guarded by a
/// `RwLock`. Entries are added by [`SessionPool::open`]; the dispatcher
/// snapshots the current entry list once per chunk (under a brief read
/// lock) so dead-flag transitions and per-entry rotation state changes
/// propagate to subsequent dispatches without disturbing in-flight ones.
pub struct SessionPool {
    sessions: std::sync::Arc<std::sync::RwLock<Vec<std::sync::Arc<SessionEntry>>>>,
}

impl SessionPool {
    /// Open up to `target_size` sessions to peers selected by proximity
    /// to the zero address (a stable ordering). Skips recently-failed
    /// peers and dials wider than `target_size` in parallel to absorb
    /// the high failure rate of stale mainnet hive announcements.
    pub async fn open(
        transport: &Transport,
        peers: &PeerStore,
        target_size: usize,
    ) -> Result<Self, ClientError> {
        let sessions = open_session_pool(transport, peers, target_size).await?;
        if sessions.is_empty() {
            return Err(ClientError::NoPeers("no reachable ws peers".into()));
        }
        let wrapped: Vec<std::sync::Arc<SessionEntry>> =
            sessions.into_iter().map(std::sync::Arc::new).collect();
        Ok(Self {
            sessions: std::sync::Arc::new(std::sync::RwLock::new(wrapped)),
        })
    }

    /// An empty pool, to be filled incrementally via [`Self::top_up`].
    /// The daemon installs one of these in shared state *before* its
    /// eager fill so Status/uploads see the pool grow session-by-session
    /// instead of a `None` until the last dial completes.
    pub fn new() -> Self {
        Self {
            sessions: std::sync::Arc::new(std::sync::RwLock::new(Vec::new())),
        }
    }

    /// Append one entry (instantaneous write lock). Used by the live
    /// fill sink ([`PoolSink::Pool`]).
    fn push_entry(&self, entry: std::sync::Arc<SessionEntry>) {
        self.sessions
            .write()
            .expect("session pool rwlock poisoned")
            .push(entry);
    }

    pub fn len(&self) -> usize {
        self.sessions
            .read()
            .expect("session pool rwlock poisoned")
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions
            .read()
            .expect("session pool rwlock poisoned")
            .is_empty()
    }

    /// Take a cheap snapshot of the current entries. Each `Arc` is
    /// cloned (refcount bump only); the read lock is dropped before
    /// returning. Callers use the snapshot as a fixed-index view into
    /// the pool for the duration of one chunk's dispatch.
    fn snapshot(&self) -> Vec<std::sync::Arc<SessionEntry>> {
        self.sessions
            .read()
            .expect("session pool rwlock poisoned")
            .clone()
    }

    /// Count entries whose underlying session is currently alive
    /// (cmd_tx still open AND not in the dead-skip window). Used by
    /// the daemon's maintenance loop to decide whether to top up.
    pub fn live_count(&self) -> usize {
        self.sessions
            .read()
            .expect("session pool rwlock poisoned")
            .iter()
            .filter(|e| !e.is_dead() && e.snapshot().is_alive())
            .count()
    }

    /// Set of overlay hex strings currently in the pool — used as the
    /// dedup filter when topping up. Lower-cased for stable matching
    /// against `PeerStore` entries (overlays there are also stored as
    /// lower-case hex).
    pub fn entry_overlays(&self) -> std::collections::HashSet<String> {
        self.sessions
            .read()
            .expect("session pool rwlock poisoned")
            .iter()
            .map(|e| e.overlay_hex.to_lowercase())
            .collect()
    }

    /// Snapshot of (overlay_hex, push_success_count) for every entry
    /// currently in the pool, sorted descending by success count.
    /// Used by the daemon's auto-iteration loop to identify the best
    /// peers across a session and propose them as new vanity-overlay
    /// anchor targets.
    pub fn top_peers_by_success(&self, limit: usize) -> Vec<(String, u64)> {
        let mut stats: Vec<(String, u64)> = self
            .sessions
            .read()
            .expect("session pool rwlock poisoned")
            .iter()
            .map(|e| (e.overlay_hex.clone(), e.push_success_count()))
            .filter(|(_, n)| *n > 0)
            .collect();
        stats.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        stats.truncate(limit);
        stats
    }

    /// Garbage-collect dead entries from the pool. A session whose
    /// driver task has exited (cmd_tx closed, see [`PeerSession::is_alive`])
    /// or whose dead-skip window is active is unreachable for any
    /// future push — removing it keeps the live pool from being
    /// dominated by tombstones, and lets [`Self::top_up`] make
    /// useful headroom comparisons.
    ///
    /// Returns the number of entries removed.
    pub fn prune_dead(&self) -> usize {
        let mut guard = self.sessions.write().expect("session pool rwlock poisoned");
        let before = guard.len();
        guard.retain(|e| !e.is_dead() && e.snapshot().is_alive());
        before - guard.len()
    }

    /// Dial new sessions to fresh peers (overlays not already in the
    /// pool, not in `--healthcheck`-recorded recent-failure window) and
    /// append them to the pool. Used by the daemon's maintenance loop
    /// to keep the pool at `target_size` against steady-state churn.
    ///
    /// Returns the number of new sessions added.
    ///
    /// Callers should run [`Self::prune_dead`] first; otherwise dead
    /// entries are counted as occupants and `top_up` won't dial enough
    /// replacements.
    ///
    /// The dial concurrency mirrors `open_session_pool`'s heuristic
    /// (capped at `SESSION_DIAL_PARALLELISM`); the work is bounded by
    /// `additional` requested entries, not by walking the full
    /// peers.json. Peers that are reachable but oversaturated will
    /// time out at the libp2p layer; those failures are absorbed
    /// silently and the maintenance loop will retry next tick.
    pub async fn top_up(
        &self,
        transport: &Transport,
        peers: &PeerStore,
        target_size: usize,
    ) -> usize {
        let current = {
            let g = self.sessions.read().expect("session pool rwlock poisoned");
            g.len()
        };
        if current >= target_size {
            return 0;
        }
        let additional = target_size - current;
        let existing = self.entry_overlays();
        // Live sink: every session lands in the pool the moment its
        // dial succeeds, so concurrent readers (Status, dispatchers)
        // see the fill progress instead of an all-at-the-end append.
        open_session_pool_into(
            transport,
            peers,
            additional,
            &existing,
            PoolSink::Pool(self),
        )
        .await
        .unwrap_or(0)
    }
}

/// Build a one-shot pool sized for `work.len()` and push everything
/// through it. The pool is dropped on return; for daemon-style reuse,
/// build a [`SessionPool`] separately and call
/// [`push_chunks_with_pool`].
async fn push_chunks_concurrent(
    transport: &Transport,
    peers: &PeerStore,
    work: Vec<StampedChunk>,
    max_retries: usize,
    concurrency: usize,
    progress: Option<&ProgressFn>,
) -> Result<(), ClientError> {
    if work.is_empty() {
        return Ok(());
    }
    // Adaptive sizing. Two competing pressures:
    //
    //  - Don't open *far* more sessions than there are chunks: a 2-chunk
    //    file doesn't need 256 sessions, and every extra dial costs a
    //    (browser: 20 s) timeout budget when the peer is stale.
    //  - But the pool must be big enough to survive per-peer failure. Each
    //    chunk races `CHUNK_PEER_PARALLELISM` (=3) peers, chosen by proximity
    //    to *that chunk's* address, and browser `/wss` sessions die
    //    constantly (AutoTLS SNI rotation, low keepalive). With a pool of 4,
    //    a single upload where 3 peers drop into dial-cooldown leaves ONE
    //    eligible session and the tail chunk blocks on its full 30 s
    //    per-op timeout — exactly the "tiny file took 30 s" stall.
    //
    // So floor the pool at `MIN_UPLOAD_POOL` (enough live spread + churn
    // headroom for the 3-way race across distinct chunk addresses),
    // independent of chunk count, then cap by the requested concurrency and
    // by a small multiple of the chunk count so we still don't massively
    // over-dial a big-concurrency caller uploading a 2-chunk file.
    const MIN_UPLOAD_POOL: usize = 16;
    // Room to grow with the upload (4 sessions per chunk covers the 3-way
    // race plus a spare), floored at MIN_UPLOAD_POOL, then capped by the
    // caller's `concurrency`. README (3 chunks): min(48, max(16, 12)) = 16.
    // Large upload: min(48, max(16, huge)) = 48.
    let want = (work.len() * 4).max(MIN_UPLOAD_POOL);
    let target_sessions = concurrency.max(1).min(want);
    let pool = SessionPool::open(transport, peers, target_sessions).await?;
    info!(
        target: "hoverfly::upload",
        "opened {} peer session(s), pushing {} chunks",
        pool.len(),
        work.len()
    );
    // One-shot pool with no external maintainer → keep it topped up mid-push.
    push_chunks_with_pool(transport, &pool, peers, work, max_retries, true, progress).await
}

/// Push `work` through `session_pool`, keeping the pool topped up for the
/// duration of the push so the tail of a long upload doesn't stall on a
/// decayed pool.
///
/// The dispatcher ([`push_chunks_with_pool_inner`]) freezes its view of the
/// pool per chunk; over a multi-thousand-chunk upload sessions die (browser
/// `/wss` fast, native TCP slowly) and the live set shrinks, so the last few
/// chunks race a nearly-empty pool and grind retries — the classic
/// "stuck at N-1/N" tail. Bee never hits this because it pushes through the
/// continuously-maintained kademlia topology, not a per-upload pool. We mirror
/// that: a concurrent loop prunes dead entries and re-dials fresh peers from
/// `peers` back to the pool's opening size while the push runs.
///
/// `maintain` selects whether this call owns pool upkeep. The one-shot CLI /
/// browser path ([`push_chunks_concurrent`]) builds a throwaway pool with no
/// external maintainer and passes `true`. The daemon passes `false`: its own
/// maintenance loop already prunes + tops up the shared pool, and a second
/// top-up here would double-dial (the CPU-churn that starves uploads on small
/// hosts). `HOVERFLY_PUSH_TOPUP_SECS` sets the interval (default 2 s); `0`
/// disables it even when `maintain` is true (frozen-pool A/B on one binary).
///
/// Measured (2-core VPS, pool 16, 6 randomized paired 6 MB uploads): the
/// top-up wins 6/6 pairs, mean +74% throughput, 2-5 s slow-chunk bucket -34%.
pub async fn push_chunks_with_pool(
    transport: &Transport,
    session_pool: &SessionPool,
    peers: &PeerStore,
    work: Vec<StampedChunk>,
    max_retries: usize,
    maintain: bool,
    progress: Option<&ProgressFn>,
) -> Result<(), ClientError> {
    push_chunks_with_pool_ex(
        transport,
        session_pool,
        peers,
        work,
        max_retries,
        maintain,
        progress,
        None,
    )
    .await
}

/// [`push_chunks_with_pool`] plus a per-chunk completion hook.
///
/// `on_chunk` fires exactly once per chunk the dispatcher resolves, in
/// completion order, with the chunk's address and outcome. Chunks still
/// queued when a fatal error aborts the run never fire — the caller owns
/// deciding what to report for those (the pusher relay marks them failed).
///
/// This is what makes `/v1/push` stream honest per-chunk acks: the
/// dispatcher internally resolves chunks independently (each is its own
/// future in a `FuturesUnordered`), so collapsing that into a single
/// all-or-nothing `Result` at the end threw away information the client
/// scheduler needs — one lost chunk in 256 forced a re-push of all 256.
#[allow(clippy::too_many_arguments)]
pub async fn push_chunks_with_pool_ex(
    transport: &Transport,
    session_pool: &SessionPool,
    peers: &PeerStore,
    work: Vec<StampedChunk>,
    max_retries: usize,
    maintain: bool,
    progress: Option<&ProgressFn>,
    on_chunk: Option<&ChunkDoneFn>,
) -> Result<(), ClientError> {
    let topup_secs: u64 = std::env::var("HOVERFLY_PUSH_TOPUP_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    // Even when this call doesn't own upkeep (maintain=false, the daemon
    // path), the daemon's own maintenance loop refills the pool — so an
    // empty pool is still recoverable and the dispatcher should wait, not
    // abort. Only the explicit topup_secs=0 kill-switch restores the old
    // frozen-pool fail-fast (for A/B baselines).
    let pool_can_recover = topup_secs != 0;
    if !maintain || topup_secs == 0 {
        return push_chunks_with_pool_inner(
            transport,
            session_pool,
            peers,
            work,
            max_retries,
            pool_can_recover,
            progress,
            on_chunk,
        )
        .await;
    }
    // Restore the pool to the size it opened at: for a one-shot CLI/browser
    // pool that's the full opening size (all-live at open); for the daemon it
    // tracks its configured target via `len()`.
    let target = session_pool.len();
    let topup = async {
        loop {
            tokio::time::sleep(Duration::from_secs(topup_secs)).await;
            session_pool.prune_dead();
            let added = session_pool.top_up(transport, peers, target).await;
            if added > 0 {
                info!(
                    target: "hoverfly::upload",
                    "push top-up: +{} session(s), pool now {}",
                    added,
                    session_pool.len()
                );
            }
        }
    };
    tokio::select! {
        r = push_chunks_with_pool_inner(
            transport, session_pool, peers, work, max_retries, pool_can_recover, progress, on_chunk,
        ) => r,
        _ = topup => unreachable!("top-up loop only exits when the push future wins the select"),
    }
}

/// Push `work` through an existing pool. Used by the daemon to amortise
/// pool-fill cost across many upload requests; the CLI builds a fresh
/// pool per invocation via [`push_chunks_concurrent`].
///
/// The pushing path needs **no batch-owner key** — the stamps inside
/// `work` are already signed. The `transport` carries the libp2p
/// overlay identity (set at `Transport::new`); that's the only signing
/// surface this function uses (handshake on connection setup, receipt
/// verification on `is_shallow`). This is the entrypoint a multi-worker
/// pusher hits to push pre-stamped chunks under its own ephemeral
/// overlay key.
#[allow(clippy::too_many_arguments)]
async fn push_chunks_with_pool_inner(
    transport: &Transport,
    session_pool: &SessionPool,
    peers: &PeerStore,
    work: Vec<StampedChunk>,
    max_retries: usize,
    // True when SOMETHING refills this pool while we push — the wrapper's
    // top-up loop (maintain=true) or the daemon's maintenance loop. Makes
    // an empty pool a *recoverable outage* (wait for the maintainer,
    // bounded) instead of a 30-s death sentence: 60 × 500 ms of retries is
    // far shorter than a browser-wide wss churn spike, and aborting a
    // multi-thousand-chunk upload at 5% because the pool was briefly empty
    // wastes everything already pushed.
    pool_can_recover: bool,
    progress: Option<&ProgressFn>,
    on_chunk: Option<&ChunkDoneFn>,
) -> Result<(), ClientError> {
    use futures::stream::{FuturesUnordered, StreamExt};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    if work.is_empty() {
        return Ok(());
    }
    // `peers` is part of the public API for compatibility with earlier
    // callers; the pool is fixed at the size returned by
    // `SessionPool::open` and no longer mutated mid-upload.
    let _ = peers;
    // Initial pool snapshot — used for sizing decisions only. The
    // dispatcher takes a fresh snapshot per chunk so newly-revived
    // sessions (post-prewarm) and dead-flag changes propagate to
    // subsequent dispatches.
    let initial_pool = session_pool.snapshot();
    if initial_pool.is_empty() {
        return Err(ClientError::NoPeers("no reachable ws peers".into()));
    }
    let total = work.len();
    let pushed = Arc::new(AtomicUsize::new(0));

    // Sized to match bee's pusher `ConcurrentPushes = swarm.Branches
    // = 128` at workflow level. A wider buffer doesn't help once we're
    // past the number of pushes the session pool can run truly in
    // parallel — extra in-flight chunks just contend on the
    // per-session accounting mutex (try_reserve serialises) and
    // inflate dispatcher overhead. Earlier `pool × 16` produced
    // 1.5 k+ attempts in flight on a 32-peer pool and turned 6
    // chunks/s into 0.1 chunks/s.
    //
    // HOVERFLY_BUFFER_MULT (env var; same semantics as the
    // --buffer-multiplier CLI flag) multiplies the cap and the
    // pool-size floor. At default 1 the buffer is 128 chunks. Empirical
    // sweet spot on a 50 MiB random VPS upload is
    // `--concurrency 512 --buffer-multiplier 4` (= buffer 512 + pool
    // 512, ~3 in-flight per session at race=3), reaching ~1 MB/s.
    // Larger values overshoot into per-session yamux contention.
    let mult: usize = std::env::var("HOVERFLY_BUFFER_MULT")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|n: &usize| *n > 0)
        .unwrap_or(1);
    let buffer = (128 * mult).min(total).max(initial_pool.len());

    // Per-chunk peer racing: race N peers in parallel from the start
    // of each chunk's dispatch. Most random-addressed chunks on novel
    // uploads need to walk several peers before one inside (or close
    // to) the chunk's AOR returns a non-shallow receipt. Serial
    // walking adds N × RTT to every chunk; racing N collapses tail
    // latency to roughly one RTT for most chunks.
    //
    // The previous "no racing" comment cited session-mutex pressure
    // tripling and the tail slowing down. That was empirically true
    // with the older `buffer = pool × 16` regime (1.5k+ in flight on
    // a 32-peer pool) where accounting contention dominated.
    // Buffer is now hard-capped at 128 (see below), so `128 × 3 = 384`
    // in flight is well inside the mutex's hold-microseconds-only
    // contention zone.
    //
    // Accounting stays consistent under loser cancellation: every push
    // runs as a task inside SessionDriver.tasks polled by the driver,
    // not by the dispatcher. When the dispatcher accepts the first
    // non-shallow Receipt and drops the FuturesUnordered, the loser
    // tasks keep running in their driver, finish their accounting
    // (reserve_plur decrement, ghost-balance increment on Err) and
    // silently no-op on `reply.send`. do_pushsync is timeout-bounded
    // by `--timeout`, so no leaks.
    //
    // Cost: we pay bee credit for all N racers per chunk (each
    // forwarder debits us via PrepareDebit/Apply). 3× bandwidth for
    // ~2-3× throughput is the deliberate tradeoff.
    const CHUNK_PEER_PARALLELISM: usize = 3;
    // Preempt timer extends the race window if the initial seed used
    // fewer than N peers (small or attrited pool), and tops up the
    // race after an early shallow/error response if we haven't yet
    // received a receipt. Short enough to actually race on per-chunk
    // timescales — most mainnet pushsync RTTs are well under a
    // second.
    const PREEMPT_INTERVAL: Duration = Duration::from_secs(1);

    /// Per-chunk pusher-layer retry budget. Mirrors bee's
    /// `pusher.DefaultRetryCount = 6`: if a chunk exhausts its
    /// proximity-ordered candidate list with only `connection_dead` /
    /// timeout errors, we wait and retry the whole peer fan-out a
    /// few more times before giving up on the upload. Without this,
    /// a single chunk that hits a transient cluster-wide network
    /// blip (every session in the pool ghost-balance-retiring at
    /// once, brief peer routing churn) aborts an otherwise-successful
    /// 3 000-chunk upload.
    const MAX_CHUNK_RETRIES: u8 = 60;

    let dispatch = |chunk: Arc<StampedChunk>, attempts: u8| {
        let session_pool = session_pool;
        let pushed = pushed.clone();
        let transport = transport;
        let progress = progress.cloned();
        let chunk_for_result = chunk.clone();
        async move {
            // web_time::Instant (not std::time::Instant) — std's panics on
            // wasm ("time not implemented"); this push path runs on the wasm
            // upload path too.
            let t_chunk_start = web_time::Instant::now();
            // Inner result; the outer arm returns the chunk + retry
            // count alongside so the dispatch driver can re-queue
            // failed chunks for another round (bee's pusher does the
            // same when pushsync exits without a valid receipt).
            let result: Result<PushInfo, ClientError> = async move {
            use futures::stream::{FuturesUnordered, StreamExt};

            // Take a fresh snapshot of the pool for this dispatch so
            // dead-flag transitions and observed-storage-radius updates
            // from peer receipts are visible. The snapshot is an
            // `Arc<Vec<Arc<SessionEntry>>>`-equivalent (cheap clones of
            // entry Arcs) so the read lock is released immediately and
            // doesn't gate concurrent dispatches.
            let pool: Vec<Arc<SessionEntry>> = session_pool.snapshot();

            // Rank sessions by proximity to this chunk's address; closest
            // first. bee at that peer is then either inside its area of
            // responsibility (stores directly) or only a short hop away.
            // Skip entries currently flagged dead by a recent hard
            // failure — the dispatcher's per-chunk thundering-herd on a
            // single broken peer dominates the warning noise on
            // mainnet.
            let chunk_addr = SwarmAddress::new(chunk.addr);
            // Filter out entries that can't possibly serve this push
            // right now:
            //
            // - `is_dead()`: parked by the dead-skip window after
            //   DEAD_STRIKES failed dials.
            // - Cooldown pre-filter: the entry's current session is
            //   dead (driver task exited, cmd_tx closed) AND there's
            //   no pre-warmed replacement waiting AND the transport's
            //   per-peer dial rate limit would still park the redial
            //   (peek > 0). Without this, we burn a full chunk-dispatch
            //   attempt only for `try_push_with_rotation` to discover the
            //   session is dead, attempt the rotation dial, and stall on
            //   a park (or over `MAX_DIAL_PARK`, get `DialTooSoon`) back
            //   from `Transport::open_session`. Each one of those wastes
            //   one of the `cap` attempts and adds a retry penalty
            //   downstream. Trace data on a stalled
            //   upload showed all 8 chunk-fan-out attempts hitting
            //   this exact pattern simultaneously (every peer in the
            //   pool went into cooldown together after a maintenance
            //   burst).
            //
            // We keep entries whose session is alive even if cooldown
            // is active — those don't need to dial. We also keep
            // dead-session entries that have a pending pre-warm: the
            // rotation path will use it via `take_pending` without
            // calling `Transport::open_session`.
            // Per-chunk eligibility filter — count which reason kicks
            // out each pool entry so we can surface a useful error
            // when the candidate list ends up empty. Without this,
            // an "all 0 attempts failed" error is opaque about
            // whether the pool is genuinely saturated, full of dead
            // sessions, or stuck behind dial cooldowns.
            //
            // The filter is closed-over by `build_order` so we can
            // re-evaluate it after a brief wait if the pool was
            // momentarily saturated when the chunk first asked for
            // candidates. Without the rebuild, an early-burst chunk
            // would bubble up `Err(NoPeers)` with 0 attempts and
            // rely on the outer 500 ms retry, wasting that 500 ms
            // even when the pool drains in 50 ms.
            let mut filter_dead = 0usize;
            let mut filter_cap = 0usize;
            let mut filter_dead_session_cooldown = 0usize;
            let build_order = |
                filter_dead: &mut usize,
                filter_cap: &mut usize,
                filter_dead_session_cooldown: &mut usize,
            | -> Vec<usize> {
                *filter_dead = 0;
                *filter_cap = 0;
                *filter_dead_session_cooldown = 0;
                let mut order: Vec<usize> = (0..pool.len())
                    .filter(|i| {
                        let e = &pool[*i];
                        if e.is_dead() {
                            *filter_dead += 1;
                            return false;
                        }
                        // Per-peer in-flight push cap, latency-aware:
                        // fast peers carry more load (cap ×2), slow peers
                        // carry less (cap /2). Skip entries at their
                        // current cap; the dispatcher fans out to
                        // less-busy peers in the same PO tier. See
                        // `inflight_cap()` and `IN_FLIGHT_CAP` doc-comments.
                        if e.inflight_pushes() >= e.inflight_cap() {
                            *filter_cap += 1;
                            return false;
                        }
                        let session_alive = e.snapshot().is_alive();
                        if session_alive {
                            return true;
                        }
                        // Session dead. Keep only if a pending replacement
                        // is waiting OR the cooldown has burned off.
                        if e.has_pending() {
                            return true;
                        }
                        if transport.dial_cooldown_for_underlay(&e.underlay).is_none() {
                            true
                        } else {
                            *filter_dead_session_cooldown += 1;
                            false
                        }
                    })
                    .collect();
                // Storage-radius-aware sort (3 buckets, see long comment
                // below). Sort lives inside build_order so the rebuilt
                // candidate list is also PO-prioritised.
                order.sort_by(|&a, &b| {
                    let pa: u8 = chunk_addr.proximity(&pool[a].overlay).into();
                    let pb: u8 = chunk_addr.proximity(&pool[b].overlay).into();
                    let aor = |idx: usize, po: u8| -> u8 {
                        match pool[idx].in_aor(po) {
                            Some(true) => 0,
                            None => 1,
                            Some(false) => 2,
                        }
                    };
                    aor(a, pa).cmp(&aor(b, pb)).then(pb.cmp(&pa))
                });
                order
            };
            // Storage-radius-aware 3-bucket sort lives inside
            // `build_order` so a rebuild keeps the same PO priority.
            // The original comment block:
            //
            //   0 (front): in-AOR — peer's observed storage radius
            //              places this chunk inside its reserve, so
            //              bee at that peer stores directly and signs
            //              a real receipt with no forwarding hop.
            //   1:         unknown — no observation yet for this peer.
            //              Bee may forward or store; ambiguous.
            //   2 (back):  known-out — we got a shallow receipt from
            //              this peer for a chunk with similar PO, so
            //              this chunk will also forward. Wasted hop.
            //
            // Within each bucket, sort by proximity descending so the
            // closer peer wins the tiebreak.
            //
            // Earlier this 3-bucket design was reverted (~1.6× slower
            // on a 50 MiB VPS workload) because "unknown" was
            // systematically populated by slow/NATted/dead peers —
            // routing chunks to them over known-out forwarders pushed
            // chunks to far peers and stalled the upload.
            //
            // It's now safe to re-introduce because the dispatcher
            // pre-filters those problem peers out of `order` before
            // sorting:
            //   - `is_dead()` parks peers after DEAD_STRIKES dial
            //     failures.
            //   - Cooldown filter excludes peers whose dial cooldown
            //     hasn't burned off.
            //   - `inflight_pushes() >= inflight_cap()` excludes
            //     saturated peers, and the latency-aware cap tightens
            //     to 2 for slow-EWMA peers — so genuinely slow peers
            //     consume at most 2 push slots while we explore other
            //     candidates.
            //
            // So "unknown" is now a clean pool of peers we just
            // haven't talked to yet for THIS chunk's PO range,
            // dominated by fresh-session entries waiting for their
            // first receipt. Worth trying ahead of confirmed-forwarders.

            let mut order = build_order(
                &mut filter_dead,
                &mut filter_cap,
                &mut filter_dead_session_cooldown,
            );
            // Best proximity the dispatcher could actually reach for this
            // chunk, before any attempt. Reported alongside the receipt PO so
            // "chunks land far out" can be attributed to the pool or to the
            // eligibility filters rather than guessed at.
            let best_po = order
                .first()
                .map(|&i| u8::from(chunk_addr.proximity(&pool[i].overlay)))
                .unwrap_or(0);
            // Same, but over the *whole* pool ignoring eligibility filters.
            // `pool_po - best_po` is what the dead/cap/cooldown filters cost
            // us in depth; `best_po - po` is what the peer race costs.
            let pool_po = pool
                .iter()
                .map(|e| u8::from(chunk_addr.proximity(&e.overlay)))
                .max()
                .unwrap_or(0);
            crate::transport::diag::PUSH_POOL_PO_SUM
                .fetch_add(u64::from(pool_po), Ordering::Relaxed);
            crate::transport::diag::PUSH_POOL_PO_N.fetch_add(1, Ordering::Relaxed);

            // `cap` caps how many distinct peers a single chunk
            // attempts before giving up. With max_retries=DEFAULT=6
            // and a 100+ session pool, we'd otherwise dispatch to
            // every session — but most chunks land via the first 3-6
            // peers, so cap keeps the candidate window bounded.
            // Recomputed below if `order` is rebuilt after an empty
            // initial filter.
            let mut cap = max_retries.max(1).min(order.len());
            // Index-based candidate cursor instead of an iterator
            // borrow, so `order` can be reassigned in the
            // wait-for-capacity block below without fighting the
            // borrow checker. `next_candidate()` returns the next
            // usize in `order[..cap]`, or None when exhausted.
            let mut order_idx: usize = 0;
            let next_candidate = |order: &Vec<usize>, cap: usize, idx: &mut usize| -> Option<usize> {
                if *idx >= cap {
                    return None;
                }
                let v = order[*idx];
                *idx += 1;
                Some(v)
            };

            let attempt = |idx: usize, attempt_no: usize| {
                let entry = pool[idx].clone();
                let chunk = chunk.clone();
                async move {
                    let mut peer_overlay = [0u8; 32];
                    peer_overlay.copy_from_slice(entry.overlay.as_bytes());
                    let price = peer_price(&peer_overlay, &chunk.addr);
                    // The order_iter was built before this attempt was
                    // dispatched. A peer can be marked dead in the
                    // intervening interval (another in-flight chunk's
                    // rotation failed). Skip without burning a fresh
                    // network round-trip; the dispatcher's error arm
                    // advances order_iter to the next-closest peer.
                    if entry.is_dead() {
                        return (
                            idx,
                            attempt_no,
                            price,
                            Err(TransportError::ConnectionClosed),
                        );
                    }
                    // RAII counter: increment in-flight, decrement on
                    // drop (whether the push succeeds, errors, or the
                    // future is cancelled by the racing dispatcher).
                    // Keeps the per-peer cap honest under cancellation.
                    struct InFlightGuard<'a>(&'a SessionEntry);
                    impl<'a> Drop for InFlightGuard<'a> {
                        fn drop(&mut self) {
                            self.0
                                .inflight_pushes
                                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    entry
                        .inflight_pushes
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let _guard = InFlightGuard(&entry);
                    let outcome = try_push_with_rotation(&entry, &chunk, price, transport).await;
                    (idx, attempt_no, price, outcome)
                }
            };

            let mut inflight = FuturesUnordered::new();
            let mut attempt_no = 0usize;

            // Seed up to CHUNK_PEER_PARALLELISM peers from the start
            // so the chunk's race is wide immediately rather than
            // depending on the preempt timer to fan out gradually.
            for _ in 0..CHUNK_PEER_PARALLELISM {
                if let Some(idx) = next_candidate(&order, cap, &mut order_idx) {
                    attempt_no += 1;
                    inflight.push(attempt(idx, attempt_no));
                } else {
                    break;
                }
            }

            // If the initial order_iter was empty (every session in
            // the pool was filtered out: dead, at inflight_cap, or in
            // dial cooldown), spin-wait briefly and rebuild before
            // bubbling up `NoPeers`. The outer dispatcher's retry
            // already does this with a 500 ms backoff, but most often
            // the pool drains within 50-200 ms: another chunk's push
            // finishes and decrements `inflight_pushes`, or a dial
            // cooldown burns off. Polling locally avoids re-entering
            // the whole dispatch path for the chunk; we just refresh
            // `order` in place and seed the same FuturesUnordered.
            //
            // Cap at 30 × 100 ms = 3 s so a deeply-stuck chunk still
            // bubbles up and lets the outer loop apply its retry
            // counter / backoff strategy. If we get past the cap with
            // no eligible peer, the post-loop NoPeers error fires and
            // the chunk re-dispatches the normal way.
            if attempt_no == 0 {
                for _ in 0..30 {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    order = build_order(
                        &mut filter_dead,
                        &mut filter_cap,
                        &mut filter_dead_session_cooldown,
                    );
                    if order.is_empty() {
                        continue;
                    }
                    // Recompute cap now that order has entries
                    // (initial cap was clamped to 0 by .min(0)).
                    // Reset order_idx — the rebuilt order is a fresh
                    // candidate list, not a continuation.
                    cap = max_retries.max(1).min(order.len());
                    order_idx = 0;
                    for _ in 0..CHUNK_PEER_PARALLELISM {
                        if let Some(idx) = next_candidate(&order, cap, &mut order_idx) {
                            attempt_no += 1;
                            inflight.push(attempt(idx, attempt_no));
                        } else {
                            break;
                        }
                    }
                    break;
                }
            }

            // Two outer rounds: if every peer reports Overdraft on the first
            // pass we sleep briefly to let pseudosettle refresh free credit,
            // then retry. After that, treat as a hard failure.
            let mut last_err: Option<TransportError> = None;
            let mut overdrafts = 0usize;
            let mut errors = 0usize;
            let mut shallows = 0usize;
            // Track the deepest shallow receipt we've seen for this
            // chunk. After we've exhausted every peer in the pool with
            // shallow-only outcomes we accept the best (highest-PO)
            // one rather than failing the whole upload — bee does the
            // same via `maxPushErrors` + `errSkip` in pushsync.go.
            let mut best_shallow: Option<(usize, PushsyncReceipt)> = None;
            // Box-pinned sleep that we recreate on each fire / push-refill;
            // PREEMPT_INTERVAL then counts from the most recent push event.
            // (Native tokio has Sleep::reset, but tokio_with_wasm doesn't,
            // so a re-pin is the portable common subset.)
            let mut sleep: std::pin::Pin<Box<tokio::time::Sleep>> =
                Box::pin(tokio::time::sleep(PREEMPT_INTERVAL));

            loop {
                tokio::select! {
                    biased;

                    Some((idx, n, price, outcome)) = inflight.next(), if !inflight.is_empty() => {
                        let entry = &pool[idx];
                        match outcome {
                            Ok(PushOutcome::Receipt(_)) => {
                                let done = pushed.fetch_add(1, Ordering::Relaxed) + 1;
                                if let Some(p) = &progress {
                                    p(done, total);
                                }
                                if done % 25 == 0 || done == total {
                                    info!(target: "hoverfly::upload",
                                        "pushed {}/{} chunks (latest via {} po={})",
                                        done, total, entry.overlay_hex,
                                        chunk_addr.proximity(&entry.overlay));
                                } else {
                                    debug!(target: "hoverfly::upload",
                                        "push ok ({}/{}) via {} (po={}, price={})",
                                        done, total, entry.overlay_hex,
                                        chunk_addr.proximity(&entry.overlay), price);
                                }
                                // `ms` is stamped by the caller once the
                                // whole dispatch (including retries) unwinds.
                                return Ok::<_, ClientError>(PushInfo {
                                    po: u8::from(chunk_addr.proximity(&entry.overlay)),
                                    ms: 0,
                                    shallow: false,
                                    best_po,
                                });
                            }
                            Ok(PushOutcome::Overdraft) => {
                                overdrafts += 1;
                                debug!(target: "hoverfly::upload",
                                    "overdraft on {} (po={}); trying next peer",
                                    entry.overlay_hex,
                                    chunk_addr.proximity(&entry.overlay));
                            }
                            Ok(PushOutcome::Shallow(r)) => {
                                shallows += 1;
                                let po = usize::from(chunk_addr.proximity(&entry.overlay));
                                debug!(target: "hoverfly::upload",
                                    "shallow receipt on {} (po={}, storage_radius={}); trying next peer",
                                    entry.overlay_hex, po, r.storage_radius);
                                if best_shallow.as_ref().map(|(p, _)| po > *p).unwrap_or(true) {
                                    best_shallow = Some((po, r));
                                }
                            }
                            Err(e) => {
                                errors += 1;
                                // Demoted from `warn!`: a single failed push
                                // attempt is part of normal dispatcher work —
                                // the next peer in `order_iter` will be tried
                                // immediately and the chunk almost always
                                // lands on a subsequent retry. We surface the
                                // last error in the eventual `NoPeers`
                                // return-value if the entire fan-out fails.
                                debug!(target: "hoverfly::upload",
                                    "push attempt {} via {} (po={}) failed: {}",
                                    n, entry.overlay_hex,
                                    chunk_addr.proximity(&entry.overlay), e);
                                last_err = Some(e);
                            }
                        }
                        // Top up the in-flight window with the next-closest peer.
                        match next_candidate(&order, cap, &mut order_idx) {
                            Some(idx) => {
                                attempt_no += 1;
                                inflight.push(attempt(idx, attempt_no));
                            }
                            // Order exhausted *and* inflight is empty:
                            // there's nothing left to wait on. Bail out
                            // of the inner loop so the fallback paths
                            // (shallow-accept, retry-with-refresh) can
                            // run. Without this we'd spin forever on
                            // the preempt timer arm whose
                            // `inflight.len() < CHUNK_PEER_PARALLELISM`
                            // condition stays true once inflight is empty
                            // — the `else` arm never fires while sleep
                            // is enabled.
                            None if inflight.is_empty() => break,
                            None => {}
                        }
                        // Reset preempt timer: we just observed activity, so
                        // start the next PREEMPT_INTERVAL countdown fresh.
                        sleep = Box::pin(tokio::time::sleep(PREEMPT_INTERVAL));
                    }

                    _ = sleep.as_mut(), if inflight.len() < CHUNK_PEER_PARALLELISM => {
                        // Preemptive fanout: closest peer hasn't returned within
                        // `PREEMPT_INTERVAL`, so race another peer in parallel.
                        match next_candidate(&order, cap, &mut order_idx) {
                            Some(idx) => {
                                attempt_no += 1;
                                inflight.push(attempt(idx, attempt_no));
                                sleep = Box::pin(tokio::time::sleep(PREEMPT_INTERVAL));
                            }
                            // No more peers and nothing in flight — exit
                            // so the post-loop fallback can decide
                            // whether to accept a shallow receipt or
                            // surface the error.
                            None if inflight.is_empty() => break,
                            None => {
                                sleep = Box::pin(tokio::time::sleep(PREEMPT_INTERVAL));
                            }
                        }
                    }

                    else => break,
                }
            }

            // All candidates within `cap` exhausted. If everyone
            // overdrafted (no real errors), prefer trying more peers
            // beyond `cap` over sleeping — the pool has many peers, and
            // a fresh peer's credit ceiling is uncorrelated with our
            // already-attempted ones'. Only fall back to a 600 ms
            // refresh-wait + closest-N retry if there genuinely are no
            // more peers in the pool.
            //
            // 600ms matches bee's `overDraftRefresh` constant
            // (`pkg/pushsync/pushsync.go:51`).
            if errors == 0 && (overdrafts > 0 || shallows > 0) {
                let already_attempted = attempt_no;
                let extra: Vec<usize> = order.iter().skip(already_attempted).copied().collect();
                if !extra.is_empty() {
                    debug!(target: "hoverfly::upload",
                        "all {} attempted peers gave overdraft/shallow ({}+{}); trying {} more",
                        already_attempted, overdrafts, shallows, extra.len());
                    for idx in extra {
                        let entry = &pool[idx];
                        let mut peer_overlay = [0u8; 32];
                        peer_overlay.copy_from_slice(entry.overlay.as_bytes());
                        let price = peer_price(&peer_overlay, &chunk.addr);
                        match try_push_with_rotation(entry, &chunk, price, transport).await {
                            Ok(PushOutcome::Receipt(_)) => {
                                let done = pushed.fetch_add(1, Ordering::Relaxed) + 1;
                                if let Some(p) = &progress {
                                    p(done, total);
                                }
                                if done % 25 == 0 || done == total {
                                    info!(target: "hoverfly::upload",
                                        "pushed {}/{} chunks (latest via {} po={})",
                                        done, total, entry.overlay_hex,
                                        chunk_addr.proximity(&entry.overlay));
                                }
                                // `ms` is stamped by the caller once the
                                // whole dispatch (including retries) unwinds.
                                return Ok::<_, ClientError>(PushInfo {
                                    po: u8::from(chunk_addr.proximity(&entry.overlay)),
                                    ms: 0,
                                    shallow: false,
                                    best_po,
                                });
                            }
                            Ok(PushOutcome::Overdraft) | Ok(PushOutcome::Shallow(_)) => continue,
                            Err(e) => {
                                last_err = Some(e);
                                break;
                            }
                        }
                    }
                } else if overdrafts > 0 {
                    debug!(target: "hoverfly::upload",
                        "all peers overdrafted and no more candidates; waiting for refresh");
                    tokio::time::sleep(Duration::from_millis(600)).await;
                    for idx in order.iter().take(cap).copied() {
                        let entry = &pool[idx];
                        let mut peer_overlay = [0u8; 32];
                        peer_overlay.copy_from_slice(entry.overlay.as_bytes());
                        let price = peer_price(&peer_overlay, &chunk.addr);
                        match try_push_with_rotation(entry, &chunk, price, transport).await {
                            Ok(PushOutcome::Receipt(_)) => {
                                let done = pushed.fetch_add(1, Ordering::Relaxed) + 1;
                                if let Some(p) = &progress {
                                    p(done, total);
                                }
                                if done % 25 == 0 || done == total {
                                    info!(target: "hoverfly::upload",
                                        "pushed {}/{} chunks (latest via {} po={})",
                                        done, total, entry.overlay_hex,
                                        chunk_addr.proximity(&entry.overlay));
                                }
                                // `ms` is stamped by the caller once the
                                // whole dispatch (including retries) unwinds.
                                return Ok::<_, ClientError>(PushInfo {
                                    po: u8::from(chunk_addr.proximity(&entry.overlay)),
                                    ms: 0,
                                    shallow: false,
                                    best_po,
                                });
                            }
                            Ok(PushOutcome::Overdraft) | Ok(PushOutcome::Shallow(_)) => continue,
                            Err(e) => {
                                last_err = Some(e);
                                break;
                            }
                        }
                    }
                }
            }

            // If we've seen at least one shallow receipt but no full
            // (neighborhood) receipt, do NOT accept it here. A shallow
            // receipt only proves the chunk was forwarded to some hop —
            // not that a peer inside its neighborhood-of-responsibility
            // stored it — so a chunk that lands only shallow is silently
            // unretrievable later (manifest resolves, data 404/500s).
            // Surface a *retryable* `ShallowOnly` error so the outer
            // per-chunk loop re-dispatches across more peers / after pool
            // churn (the neighborhood peer may be reachable next time).
            // Only after the full `MAX_CHUNK_RETRIES` budget is spent does
            // that loop accept the deepest shallow as a last resort
            // (mirroring bee's `maxPushErrors` give-up) instead of aborting
            // the whole upload.
            if let Some((po, _r)) = best_shallow {
                debug!(target: "hoverfly::upload",
                    "chunk {} got only shallow receipts after {} attempts (deepest po={}, {} shallow / {} overdraft / {} err); will retry",
                    hex::encode(chunk.addr), attempt_no, po, shallows, overdrafts, errors);
                return Err(ClientError::ShallowOnly);
            }

            // Fast-fail when every peer rejects the batch. Bee peers
            // share a replicated batchstore (postage events from the
            // chain), so if ONE peer reports `invalid stamp: batchstore
            // get: ... storage: not found`, every other peer will too.
            // Bail out as a fatal `BatchNotFound` rather than burning
            // MAX_CHUNK_RETRIES × 500 ms × chunk_count on doomed
            // retries — the user gets a clear error in <1 s.
            if let Some(ref e) = last_err {
                if is_batch_not_found(e) {
                    return Err(ClientError::BatchNotFound(e.to_string()));
                }
            }
            // Include filter-rejection breakdown so cap=0 errors
            // become diagnosable. dead = sessions parked from 3+
            // dial failures; cap = sessions at their per-peer
            // inflight_pushes ceiling; dead_session_cd = sessions
            // whose libp2p connection died and whose underlay is
            // still in dial cooldown.
            Err(ClientError::NoPeers(format!(
                "all {} attempts failed ({} overdraft, {} shallow, {} err); \
                 pool={} eligible={} \
                 (filtered: dead={} cap={} dead_session_cd={}): {}",
                cap,
                overdrafts,
                shallows,
                errors,
                pool.len(),
                pool.len()
                    .saturating_sub(filter_dead + filter_cap + filter_dead_session_cooldown),
                filter_dead,
                filter_cap,
                filter_dead_session_cooldown,
                last_err.map(|e| e.to_string()).unwrap_or_else(|| {
                    // No attempt ever ran. Name the actual reason the
                    // candidate list came up empty instead of the old
                    // catch-all "all overdraft/shallow" (misleading when
                    // e.g. every session was merely at its inflight cap).
                    if pool.is_empty() {
                        "pool empty (all sessions died; top-up found no dialable candidates)"
                            .into()
                    } else if filter_cap > 0
                        && filter_dead == 0
                        && filter_dead_session_cooldown == 0
                    {
                        "all sessions at inflight cap".into()
                    } else if filter_dead + filter_cap + filter_dead_session_cooldown > 0 {
                        "all sessions filtered (dead/cap/cooldown)".into()
                    } else {
                        "all overdraft/shallow".into()
                    }
                })
            )))
            }.await;
            // Chunk-latency histogram — full wall time from dispatch
            // entry to receipt-or-give-up. Bucketed to be directly
            // comparable to bee's `bee_pusher_sync_time` histogram.
            let chunk_ms = t_chunk_start.elapsed().as_millis() as u64;
            let result = result.map(|i| PushInfo {
                ms: chunk_ms.min(u64::from(u32::MAX)) as u32,
                ..i
            });
            if chunk_ms < 500 {
                crate::transport::diag::CHUNK_LATENCY_LT_500MS.fetch_add(1, Ordering::Relaxed);
            } else if chunk_ms < 2000 {
                crate::transport::diag::CHUNK_LATENCY_500MS_2S.fetch_add(1, Ordering::Relaxed);
            } else if chunk_ms < 5000 {
                crate::transport::diag::CHUNK_LATENCY_2_5S.fetch_add(1, Ordering::Relaxed);
            } else if chunk_ms < 15000 {
                crate::transport::diag::CHUNK_LATENCY_5_15S.fetch_add(1, Ordering::Relaxed);
            } else {
                crate::transport::diag::CHUNK_LATENCY_GT_15S.fetch_add(1, Ordering::Relaxed);
            }
            (chunk_for_result, attempts, result)
        }
    };

    // Box-pin chunk dispatches so the retry path (which awaits an
    // inner sleep before delegating) and the initial path (no sleep)
    // unify on a single Future type that FuturesUnordered can hold.
    #[cfg(not(target_arch = "wasm32"))]
    type DispatchFut<'a> =
        futures::future::BoxFuture<'a, (Arc<StampedChunk>, u8, Result<PushInfo, ClientError>)>;
    #[cfg(target_arch = "wasm32")]
    type DispatchFut<'a> =
        futures::future::LocalBoxFuture<'a, (Arc<StampedChunk>, u8, Result<PushInfo, ClientError>)>;
    let mut inflight: FuturesUnordered<DispatchFut<'_>> = FuturesUnordered::new();
    let mut iter = work.into_iter().map(|c| Arc::new(c));

    for _ in 0..buffer {
        if let Some(c) = iter.next() {
            inflight.push(Box::pin(dispatch(c, 0)));
        } else {
            break;
        }
    }

    // Separate side-queue of background dials used to pre-warm session
    // replacements. Each dial runs concurrently with chunk pushes, so
    // when an active session retires on ghost-balance the
    // replacement is already open instead of forcing the chunk that
    // triggered the rotation to pay the dial cost synchronously.
    //
    // The future borrows `transport` for `'_`, so we use BoxFuture<'_>
    // from the futures crate (which carries an explicit lifetime),
    // not the more common +'static dyn pinning.
    // Pre-warm dial returns the SessionEntry it was dialed for (as an
    // Arc) so the result can update the right entry regardless of
    // snapshot index changes between dispatch and resolution.
    #[cfg(not(target_arch = "wasm32"))]
    let mut prewarm_dials: FuturesUnordered<
        futures::future::BoxFuture<'_, (Arc<SessionEntry>, Result<PeerSession, TransportError>)>,
    > = FuturesUnordered::new();
    #[cfg(target_arch = "wasm32")]
    let mut prewarm_dials: FuturesUnordered<
        futures::future::LocalBoxFuture<
            '_,
            (Arc<SessionEntry>, Result<PeerSession, TransportError>),
        >,
    > = FuturesUnordered::new();

    // Re-snapshot the pool every time we want to walk it for prewarm
    // candidates or heartbeat. The snapshot is cheap (Vec of Arc
    // clones); all entries are treated identically for ghost-balance
    // pre-warm purposes.
    let maybe_prewarm =
        |entries: &[Arc<SessionEntry>], idx: usize, prewarm_dials: &mut FuturesUnordered<_>| {
            let entry = &entries[idx];
            // Don't prewarm a parked entry — that's the path that gets us
            // rate-limited by bee in the first place (`record_failure` parks
            // the entry after 3 consecutive dial failures, almost always
            // because of bee's per-IP libp2p connection rate limit). Let
            // the dead window run out before we try again.
            if entry.is_dead() {
                return;
            }
            // Two triggers for a prewarm:
            // 1. Ghost balance has crossed the prewarm watermark — the
            //    session is on track to retire from accounting pressure.
            //    Get a replacement ready before the rotation point so the
            //    swap is instant.
            // 2. The session's driver has already exited (`is_alive` is
            //    false) for any reason. On mainnet the dominant retirement
            //    cause is `dead_low_ghost` — the libp2p connection dies for
            //    non-accounting reasons (NAT keepalive expiry, bee restart,
            //    yamux idle timeout, transient network blip) well before
            //    ghost balance approaches the prewarm watermark. Without
            //    this trigger the next push to this entry has to do a
            //    synchronous re-dial inside `try_push_with_rotation`,
            //    blocking the dispatcher for one full dial RTT
            //    (~500-1500 ms on mainnet). With the trigger, the prewarm
            //    happens in the background and the swap is instant.
            let session = entry.snapshot();
            let ghost = session.ghost_balance_plur();
            let dead = !session.is_alive();
            // The dead-trigger is speculative: we don't know yet whether
            // bee is willing to talk to us again. If a prior prewarm /
            // rotation dial already failed (strikes > 0), back off the
            // dead-trigger and let the dead-skip window run — repeatedly
            // re-dialing a peer that already refused us once burns bee's
            // per-IP libp2p rate limit (10 RPS / burst 40 per /32 — see
            // `pkg/p2p/libp2p/libp2p.go::connLimiter`) and contributes
            // nothing. The ghost-trigger still fires: that means the
            // existing connection is being retired due to local
            // accounting, which is independent of dial health.
            let strikes = entry
                .failure_strikes
                .load(std::sync::atomic::Ordering::Relaxed);
            let dead_trigger_ok = dead && strikes == 0;
            let trigger = ghost >= PREWARM_GHOST_BALANCE_PLUR || dead_trigger_ok;
            if trigger
                && entry
                    .prewarm_inflight
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            {
                // Attribute the trigger to the most-specific reason.
                // `dead_trigger_ok` (dead + strikes == 0) takes precedence
                // because that's the new path; ghost-only firings are the
                // pre-existing pre-warm cause.
                if dead_trigger_ok {
                    crate::transport::diag::PREWARM_ON_DEAD.fetch_add(1, Ordering::Relaxed);
                } else {
                    crate::transport::diag::PREWARM_ON_GHOST.fetch_add(1, Ordering::Relaxed);
                }
                let underlay = entry.underlay.clone();
                let entry = entry.clone();
                #[cfg(not(target_arch = "wasm32"))]
                prewarm_dials.push(Box::pin(async move {
                    let res = transport.open_session(&underlay).await;
                    (entry, res)
                }) as futures::future::BoxFuture<'_, _>);
                #[cfg(target_arch = "wasm32")]
                prewarm_dials.push(Box::pin(async move {
                    let res = transport.open_session(&underlay).await;
                    (entry, res)
                }) as futures::future::LocalBoxFuture<'_, _>);
            }
        };

    let mut first_err: Option<ClientError> = None;
    let mut more_chunks = true;
    let mut last_pushed_seen = 0usize;
    let mut heartbeat = Box::pin(tokio::time::sleep(Duration::from_secs(5)));
    loop {
        // Done: all chunks dispatched, every dispatch resolved. Don't
        // wait on prewarm_dials — those are opportunistic and a stuck
        // bee dial there (e.g. mid-Multistream-negotiation hang) would
        // otherwise block our return forever.
        if !more_chunks && inflight.is_empty() {
            break;
        }

        tokio::select! {
            biased;

            Some((chunk, attempts, res)) = inflight.next(), if !inflight.is_empty() => {
                // Opportunistically pre-warm any session that's
                // approaching its rotation limit OR has already had its
                // libp2p connection die (see `maybe_prewarm`'s second
                // trigger). compare_exchange ensures only one dial per
                // entry at a time. Run on every chunk completion, ok or
                // err, so a dead session detected via a failed push
                // here gets a prewarm queued before the next chunk
                // routes through this entry and pays a synchronous
                // re-dial in `try_push_with_rotation`.
                {
                    let entries = session_pool.snapshot();
                    for i in 0..entries.len() {
                        maybe_prewarm(&entries, i, &mut prewarm_dials);
                    }
                }
                match res {
                    Ok(info) => {
                        if let Some(cb) = on_chunk {
                            cb(&chunk.addr, Ok(info));
                        }
                        if let Some(c) = iter.next() {
                            inflight.push(Box::pin(dispatch(c, 0)));
                        } else {
                            more_chunks = false;
                        }
                    }
                    // Don't retry batch-not-found: the batch is either
                    // expired, never paid into the chain, or its
                    // per-chunk balance was drained by the price
                    // oracle. Every bee shares the same batchstore
                    // gossip, so retrying against more peers cannot
                    // change the answer. Surface the typed error so
                    // the upload caller can present it cleanly.
                    Err(e @ ClientError::BatchNotFound(_)) => {
                        warn!(target: "hoverfly::upload",
                            "batch not found on-chain — aborting upload after {}/{} chunks pushed: {}",
                            pushed.load(Ordering::Relaxed), total, e);
                        if let Some(cb) = on_chunk {
                            cb(&chunk.addr, Err(e.to_string()));
                        }
                        first_err = Some(e);
                        break;
                    }
                    Err(e) if attempts + 1 < MAX_CHUNK_RETRIES => {
                        // Per-chunk pusher-layer retry. The proximity-
                        // sorted candidate list was exhausted without a
                        // valid (or shallow) receipt. Most often this is
                        // a transient network blip on our end — every
                        // session in the pool ghost-balance-retiring at
                        // once, brief routing churn, or a small pool
                        // (sparse peerlist) that all timed out. Sleep
                        // with linear backoff and re-dispatch the chunk
                        // through the whole proximity list. Dead-marked
                        // entries will have expired their skip windows
                        // by the time we retry.
                        let next = attempts + 1;
                        // Flat 500 ms backoff. Total wait across
                        // MAX_CHUNK_RETRIES (=60) retries is ≈30 s in
                        // the common case, which outlasts both
                        // DEAD_SKIP_SECS (=15 s — a parked entry revives
                        // well within the budget) and bee's typical
                        // ghost-overdraw blocklist window. The earlier
                        // linear-backoff-to-10 s scheme aborted uploads
                        // inside the blocklist window at higher
                        // --concurrency; a longer flat budget is simpler
                        // and empirically more robust.
                        let backoff = Duration::from_millis(500);
                        info!(target: "hoverfly::upload",
                            "chunk {} dispatch failed ({}); retry {}/{} in {}ms",
                            hex::encode(chunk.addr), e, next, MAX_CHUNK_RETRIES,
                            backoff.as_millis());
                        let dispatch = &dispatch;
                        inflight.push(Box::pin(async move {
                            tokio::time::sleep(backoff).await;
                            // Maintained pool + zero entries = transient
                            // outage (all sessions died faster than the
                            // top-up's tick; browser wss does this in
                            // churn spikes). Spending 500-ms retries
                            // against a pool that CANNOT serve anything
                            // burns the whole 60-retry budget in 30 s and
                            // aborts the upload. Park this chunk until the
                            // maintainer restores a session (bounded by
                            // POOL_RECOVERY_WAIT), then retry for real.
                            // Many chunks waiting concurrently is fine —
                            // they're all just sleeping on the same
                            // recovery.
                            const POOL_RECOVERY_WAIT: Duration = Duration::from_secs(90);
                            if pool_can_recover && session_pool.is_empty() {
                                let wait_start = web_time::Instant::now();
                                while session_pool.is_empty()
                                    && wait_start.elapsed() < POOL_RECOVERY_WAIT
                                {
                                    tokio::time::sleep(Duration::from_millis(500)).await;
                                }
                            }
                            dispatch(chunk, next).await
                        }));
                    }
                    // Retry budget exhausted. A chunk that only ever got
                    // shallow receipts (no neighborhood storer reachable
                    // across all MAX_CHUNK_RETRIES attempts) is accepted as
                    // a last resort here rather than aborting the whole
                    // upload — it WAS forwarded into the network, and after
                    // 60 retries the neighborhood peer is genuinely
                    // unreachable from our pool. Mirrors bee's
                    // `maxPushErrors` give-up. Any other error is fatal.
                    Err(ClientError::ShallowOnly) => {
                        let done = pushed.fetch_add(1, Ordering::Relaxed) + 1;
                        if let Some(p) = &progress {
                            p(done, total);
                        }
                        // Reported as a *success* with `shallow: true`: the
                        // chunk is in the network, so re-dispatching it to
                        // another lane would only burn egress, but the
                        // caller can still see it never reached a
                        // neighborhood storer.
                        if let Some(cb) = on_chunk {
                            cb(
                                &chunk.addr,
                                Ok(PushInfo { po: 0, ms: 0, shallow: true, best_po: 0 }),
                            );
                        }
                        warn!(target: "hoverfly::upload",
                            "accepting shallow-only chunk {} as last resort after {} retries ({}/{} pushed) — may be slow/unretrievable",
                            hex::encode(chunk.addr), attempts, done, total);
                        if let Some(c) = iter.next() {
                            inflight.push(Box::pin(dispatch(c, 0)));
                        } else {
                            more_chunks = false;
                        }
                    }
                    Err(e) => {
                        if let Some(cb) = on_chunk {
                            cb(&chunk.addr, Err(e.to_string()));
                        }
                        first_err = Some(e);
                        break;
                    }
                }
            }

            Some((entry, res)) = prewarm_dials.next(), if !prewarm_dials.is_empty() && more_chunks => {
                entry.prewarm_inflight.store(false, Ordering::Release);
                match res {
                    Ok(session) => {
                        debug!(target: "hoverfly::upload",
                            "pre-warm dial for {} ready", entry.overlay_hex);
                        entry.clear_strikes();
                        entry.store_pending(session);
                    }
                    Err(e) => {
                        // Prewarm failure is most often bee rate-limiting
                        // us at the libp2p layer (10 RPS / burst 40 per
                        // /32 IP, see `pkg/p2p/libp2p/libp2p.go`). The
                        // popular high-PO peers in our pool get re-dialed
                        // every time their session retires, so a single
                        // upload typically dials each top-tier peer
                        // hundreds of times — well above the rate limit,
                        // and bee starts dropping us.
                        //
                        // Reuse the strike + dead-skip machinery used by
                        // the synchronous rotation path: after
                        // DEAD_STRIKES (=3) consecutive prewarm failures
                        // the entry is parked for DEAD_SKIP_SECS (=15 s),
                        // the dispatcher skips it during proximity
                        // ordering, and we stop hammering bee with
                        // doomed dials. Once the skip window expires
                        // the entry rejoins the rotation.
                        //
                        // `DialTooSoon` excluded: that's our own per-peer
                        // dial rate limit (`ratelimit::DialRateLimiter`,
                        // over `MAX_DIAL_PARK`), not a peer fault. Prewarm
                        // is opportunistic, so dropping the dial without
                        // striking is fine — the next chunk that wants
                        // this peer will trigger a fresh prewarm attempt
                        // once its bucket drains.
                        debug!(target: "hoverfly::upload",
                            "pre-warm dial for {} failed: {}", entry.overlay_hex, e);
                        if !matches!(&e, TransportError::DialTooSoon { .. })
                            && entry.record_failure(DEAD_SKIP_SECS)
                        {
                            debug!(target: "hoverfly::upload",
                                "marked {} dead for {DEAD_SKIP_SECS}s after {} consecutive prewarm failures",
                                entry.overlay_hex, DEAD_STRIKES);
                        }
                    }
                }
            }

            _ = heartbeat.as_mut() => {
                // Every 5 s, surface progress even when the main
                // throughput hasn't crossed the next 25-chunk
                // milestone — distinguishes a hang from a slow link.
                let now = pushed.load(Ordering::Relaxed);
                let entries = session_pool.snapshot();
                if now == last_pushed_seen {
                    // Recompute the eligibility breakdown so we can
                    // tell, on every stall, whether sessions are
                    // dead, saturated, or stuck in dial cooldown.
                    // This mirrors the filter inside the per-chunk
                    // dispatcher; the numbers should match what each
                    // chunk's order_iter sees.
                    let mut dead = 0usize;
                    let mut cap_full = 0usize;
                    let mut dead_cd = 0usize;
                    let mut eligible = 0usize;
                    for e in entries.iter() {
                        if e.is_dead() { dead += 1; continue; }
                        if e.inflight_pushes() >= e.inflight_cap() { cap_full += 1; continue; }
                        let alive = e.snapshot().is_alive();
                        if alive || e.has_pending() {
                            eligible += 1;
                            continue;
                        }
                        if transport.dial_cooldown_for_underlay(&e.underlay).is_none() {
                            eligible += 1;
                        } else {
                            dead_cd += 1;
                        }
                    }
                    info!(target: "hoverfly::upload",
                        "stalled at {}/{} chunks (inflight={}, pool={} \
                         eligible={} dead={} cap={} dead_cd={})",
                        now, total, inflight.len(), entries.len(),
                        eligible, dead, cap_full, dead_cd);
                } else {
                    info!(target: "hoverfly::upload",
                        "pushed {}/{} chunks (inflight={})",
                        now, total, inflight.len());
                    last_pushed_seen = now;
                }
                // Sweep for dead sessions on every heartbeat. Covers the
                // case where no chunk completion has fired the per-chunk
                // sweep recently — e.g. a stall where every inflight
                // chunk is blocked on the same dead-session
                // synchronous-redial path. Without this, a wave of
                // dead-low-ghost retirements that lands between chunk
                // completions can leave the pool effectively shrunk
                // until the next chunk finishes.
                for i in 0..entries.len() {
                    maybe_prewarm(&entries, i, &mut prewarm_dials);
                }
                heartbeat = Box::pin(tokio::time::sleep(Duration::from_secs(5)));
            }

            else => break,
        }
    }

    if let Some(e) = first_err {
        return Err(e);
    }
    Ok(())
}

/// Probe every session in a freshly-opened pool with the
/// status-protocol round-trip, measure response time, and park
/// sessions slower than the 40th percentile via
/// [`SessionEntry::mark_dead`].
///
/// Mirrors bee's `pkg/salud` pre-filter (see
/// `pkg/salud/salud.go::salud()`). Bee's `pkg/pushsync` only
/// considers `{Reachable: true, Healthy: true}` peers in
/// `ClosestPeer`; without this pre-filter we keep sending pushes
/// to slow peers and they dominate p95 latency.
///
/// **Currently unused — disabled in `SessionPool::open` because
/// in practice bee resets the status substream on most of our
/// outbound peers (likely because we're not in their kademlia
/// table at all by the time the probe runs, or because the
/// connections have already started dying from bee's bin-prune
/// before pool fill completes — see PERFORMANCE.md "Salud
/// pre-filter").**
///
/// Probes are independent of each other and any one peer that
/// hangs / errors out doesn't block the rest — we simply treat
/// it as "very slow" (above any threshold) and park it.
#[allow(dead_code)]
async fn salud_prefilter(entries: &[std::sync::Arc<SessionEntry>]) {
    use futures::stream::{FuturesUnordered, StreamExt};
    if entries.len() < 4 {
        // Tiny pools: nothing to filter against. Skip.
        return;
    }

    // Per-bee match: 40th percentile is the threshold for unhealthy.
    // Bee's salud uses `DefaultDurPercentile = 0.4` (i.e. peers with
    // RTT in the slowest 60% get marked unhealthy). That seems
    // aggressive but is what bee actually does.
    const HEALTH_PERCENTILE: f64 = 0.4;
    // Per-peer probe timeout — must be much shorter than the
    // upload's `--timeout` so the probe phase is bounded, but
    // long enough that an actually-fast peer with a one-off
    // ~500 ms hiccup still passes. 2 s mirrors bee's salud
    // `requestTimeout = 10 s` ÷ ~5 (we're more impatient than
    // a long-running daemon).
    const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

    let mut inflight: FuturesUnordered<_> = entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let entry = e.clone();
            async move {
                let session = entry.snapshot();
                let probe = session.status_probe();
                let result = tokio::time::timeout(PROBE_TIMEOUT, probe).await;
                let rtt = match result {
                    Ok(Ok(d)) => Some(d),
                    Ok(Err(e)) => {
                        debug!(target: "hoverfly::upload",
                            "salud: probe of {} failed: {}", entry.overlay_hex, e);
                        None
                    }
                    Err(_) => {
                        debug!(target: "hoverfly::upload",
                            "salud: probe of {} timed out", entry.overlay_hex);
                        None
                    }
                };
                (i, rtt)
            }
        })
        .collect();

    let mut rtts: Vec<(usize, Duration)> = Vec::with_capacity(entries.len());
    let mut failed: Vec<usize> = Vec::new();
    while let Some((i, rtt)) = inflight.next().await {
        match rtt {
            Some(d) => rtts.push((i, d)),
            None => failed.push(i),
        }
    }

    // A failed status probe is NOT a reliable health signal here:
    // sessions opened in the first half of pool-fill have been alive
    // for several minutes by the time salud runs, and many die from
    // bee's kademlia bin-prune in that window. Parking everyone who
    // fails the probe would gut the pool. So we only use the probe
    // as a *positive* health signal (peers that DO respond) and
    // leave the rest as the dispatcher's job to filter via
    // `is_dead()` from real push attempts.
    let _failed = failed; // observed for debug logging via per-probe trace

    if rtts.len() < 4 {
        // Not enough responding peers to compute a percentile.
        // Don't filter further — better to use the slow ones
        // than to have a tiny pool.
        info!(target: "hoverfly::upload",
            "salud: only {} of {} sessions responded — skipping percentile filter",
            rtts.len(), entries.len());
        return;
    }

    // Sort RTTs and pick the 40th percentile as the threshold.
    let mut sorted = rtts.clone();
    sorted.sort_by_key(|(_, d)| *d);
    let threshold_idx = ((sorted.len() as f64) * HEALTH_PERCENTILE) as usize;
    let threshold = sorted[threshold_idx.min(sorted.len() - 1)].1;

    let mut parked = 0usize;
    for (i, rtt) in rtts {
        if rtt > threshold {
            let entry = &entries[i];
            let _ = entry.mark_dead(DEAD_SKIP_SECS);
            parked += 1;
        }
    }

    info!(target: "hoverfly::upload",
        "salud: probed {} session(s), 40th-percentile RTT = {:?}, parked {} slow + {} unresponsive ({} healthy)",
        entries.len(),
        threshold,
        parked,
        entries.len() - sorted.len(),
        sorted.len() - parked);
}

/// Send one push, transparently rotating the underlying libp2p
/// connection when the driver retires. After a successful pushsync,
/// validates the receipt against the chunk's storage radius — a
/// shallow receipt (peer signed but isn't in the chunk's AOR) is
/// reported as [`PushOutcome::Shallow`] so the dispatcher can retry
/// against a different peer instead of trusting that the chunk has
/// landed.
async fn try_push_with_rotation(
    entry: &SessionEntry,
    chunk: &StampedChunk,
    price: u64,
    transport: &Transport,
) -> Result<PushOutcome, TransportError> {
    let session = entry.snapshot();
    let net = transport.config().network_id;
    let t_start = web_time::Instant::now();
    let result = match session
        .pushsync_chunk_priced(&chunk.addr, &chunk.wire, &chunk.stamp, price)
        .await
    {
        Ok(out) => Ok(out),
        Err(e) if !is_connection_dead(&e) => Err(e),
        Err(_) => {
            let fresh = match entry.take_pending() {
                Some(s) => {
                    debug!(target: "hoverfly::upload",
                        "rotated to pre-warmed session for {}", entry.overlay_hex);
                    s
                }
                None => match transport.open_session(&entry.underlay).await {
                    Ok(s) => {
                        debug!(target: "hoverfly::upload",
                            "rotated session to {} (sync dial)", entry.overlay_hex);
                        s
                    }
                    Err(e) => {
                        // Rotation-dial failure. Count a strike; only
                        // park the entry once it crosses DEAD_STRIKES
                        // so a single transient hiccup (peer's session
                        // ghost-balance-retiring + a slow redial,
                        // momentary routing churn) doesn't shrink the
                        // live pool. Log "marked dead" exactly once
                        // per dead-window event.
                        //
                        // `DialTooSoon` is excluded: that's our own
                        // per-peer cooldown saying "wait before dialing
                        // this peer again" (so bee's libp2p connection
                        // rate limiter doesn't blocklist us). The entry
                        // itself isn't broken — the dispatcher just
                        // picks the next-closest peer for this chunk
                        // and our cooldown burns off in the background.
                        if !matches!(&e, TransportError::DialTooSoon { .. })
                            && entry.record_failure(DEAD_SKIP_SECS)
                        {
                            debug!(target: "hoverfly::upload",
                                "marked {} dead for {DEAD_SKIP_SECS}s after {} consecutive dial failures",
                                entry.overlay_hex, DEAD_STRIKES);
                        }
                        return Err(e);
                    }
                },
            };
            entry.replace(fresh.clone());
            fresh
                .pushsync_chunk_priced(&chunk.addr, &chunk.wire, &chunk.stamp, price)
                .await
        }
    };
    // Update per-peer push-latency EWMA so the dispatcher's
    // proximity sort can demote slow peers via `latency_penalty()`.
    // Error / timeout counts as a 5 s sample — that's the empirical
    // p95 from the trace, and treating errors as "very slow" makes
    // the EWMA converge toward "avoid this peer" after a couple
    // failures. DialTooSoon is excluded: it's a fast-fail with no
    // signal about the peer's actual responsiveness.
    let elapsed_us = t_start.elapsed().as_micros() as u64;
    let sample_us = match &result {
        Ok(_) => elapsed_us,
        Err(TransportError::DialTooSoon { .. }) => {
            // Don't pollute EWMA with our own cooldown — fall
            // through without observing.
            0
        }
        Err(_) => elapsed_us.max(5_000_000),
    };
    if sample_us > 0 {
        entry.observe_push_latency(sample_us);
    }

    // Wire-level outcome diagnostics — mirrors bee's
    // `bee_pushsync_*` counters at /metrics. Bumped after the await inside
    // the racing future, so this counts *completions*, not dispatches: a
    // losing racer cancelled before it completes spent egress (its Delivery
    // is already on the wire) but never reaches this increment. Do NOT use
    // `attempts_per_frame` derived from these counters as §9.1's egress
    // multiplier — it floors near 1.0 by construction (see `meter.rs` and
    // `pusher.rs::stream_attempts`). Counting at dispatch, beside
    // `inflight_pushes`, is the fix.
    let result = result;
    match &result {
        Ok(PushOutcome::Overdraft) => {
            crate::transport::diag::PUSH_OUTCOME_OVERDRAFT
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Err(_) => {
            crate::transport::diag::PUSH_OUTCOME_ERROR
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        _ => {}
    }
    Ok(match result? {
        PushOutcome::Receipt(r) => {
            let storer = r.storer_overlay(net).unwrap_or([0u8; 32]);
            let po = crate::transport::proximity(&storer, &{
                let mut a = [0u8; 32];
                a.copy_from_slice(&r.address);
                a
            });
            // Update this peer's storage-radius observation so future
            // chunks can route around peers we know will only forward.
            // Two cases by who signed the receipt:
            //
            // 1. The peer we pushed to *is* the storer (`storer ==
            //    entry.overlay`): the receipt's `storage_radius`
            //    field is exactly their reserve depth.
            // 2. The peer forwarded to someone else. We only learn
            //    that this peer chose not to store, which means
            //    `storage_radius > PO(chunk, this_peer)`. Monotonic
            //    lower-bound bump.
            let mut entry_overlay = [0u8; 32];
            entry_overlay.copy_from_slice(entry.overlay.as_bytes());
            let chunk_po_to_entry = {
                let mut chunk_addr = [0u8; 32];
                chunk_addr.copy_from_slice(&r.address);
                crate::transport::proximity(&entry_overlay, &chunk_addr)
            };
            if storer == entry_overlay {
                let sr = r.storage_radius.min(u8::MAX as u32) as u8;
                entry.observe_storage_radius(sr);
            } else {
                entry.observe_storage_radius(chunk_po_to_entry.saturating_add(1));
            }
            if r.is_shallow(net) {
                crate::transport::diag::PUSH_OUTCOME_SHALLOW
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                debug!(target: "hoverfly::upload",
                    "shallow: chunk={} storer={} po={} storage_radius={}",
                    hex::encode(&r.address), hex::encode(storer), po, r.storage_radius);
                PushOutcome::Shallow(r)
            } else {
                crate::transport::diag::PUSH_OUTCOME_OK
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // Real receipt — peer is alive and serving. Clear any
                // accumulated failure strikes so a previously-flaky
                // peer fully re-enters rotation.
                entry.clear_strikes();
                entry
                    .push_success_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                debug!(target: "hoverfly::upload",
                    "receipt OK: chunk={} storer={} po={} storage_radius={}",
                    hex::encode(&r.address), hex::encode(storer), po, r.storage_radius);
                PushOutcome::Receipt(r)
            }
        }
        out => out,
    })
}

/// Open sessions to every reachable ws peer in the store, capped at
/// `max_sessions`. We want broad address-space coverage because per-chunk
/// dispatch uses proximity routing — the more peers we can reach, the
/// closer (on average) the picked session is to any given chunk address,
/// and the less bee has to forward.
/// How many session dials we keep in flight at once while filling the
/// session pool. Mainnet peerlists are heavy with unreachable peers
/// (NAT'd, gone offline since being announced, etc.) so we need a wide
/// in-flight window to find `max_sessions` reachable ones quickly. Bee's
/// per-incoming-connection cost is cheap, and these dials only run once
/// per upload.
/// How many session dials we keep in flight at once while filling
/// the session pool. Mainnet peerlists are heavy with unreachable
/// peers (NAT'd, gone offline since being announced, bin-saturated
/// against our overlay so handshake substream gets rejected — see
/// `daemon.rs`'s discover fallback handling). For a 1500-peer
/// peers.seed.json (harvested from swarmscan.io) where ~97% of
/// peers reject us, a wide window finds reachable ones quickly
/// without bottlenecking on dial timeouts.
///
/// Tuning history:
///   32   — was fine for ≤300-peer lists
///   128  — current, for cold-start with swarmscan-derived seeds
const SESSION_DIAL_PARALLELISM: usize = 128;

/// Reorder a candidate peer list so that consecutive picks cover
/// distinct proximity-order bins instead of clustering by overlay
/// prefix. Uses an "anti-prefix" bucket walk: for every PO bin (8-bit
/// high-byte group, 256 in total) we round-robin one peer at a time.
/// Cheap (O(N)) and deterministic; no RNG dep.
fn spread_across_address_space(peers: &mut Vec<(SwarmAddress, String, Multiaddr, u8, u32)>) {
    // 256 buckets by overlay's leading byte; cheap to compute, gives
    // even distribution across the first 8 PO bins for random overlays.
    let mut buckets: Vec<Vec<(SwarmAddress, String, Multiaddr, u8, u32)>> =
        (0..256).map(|_| Vec::new()).collect();
    for p in peers.drain(..) {
        let key = p.0.as_bytes()[0] as usize;
        buckets[key].push(p);
    }
    // Within each PO bin, order by dial quality so the round-robin hands
    // out each bin's best-known peer first. Field 3 is the reachability
    // rank (lower = better, see `Peer::dial_rank`); field 4 is last-seen
    // dial RTT in ms (lower = faster). Sort *descending* (worst first,
    // best last) because the round-robin `pop()`s from the back — so the
    // first peer taken from each bin is its lowest-rank, lowest-latency
    // candidate.
    for b in buckets.iter_mut() {
        b.sort_by(|a, c| c.3.cmp(&a.3).then(c.4.cmp(&a.4)));
    }
    // Round-robin pop. As long as any bucket has entries, take one
    // from each in sequence and append to `peers`.
    let mut nonempty = (0..256).filter(|i| !buckets[*i].is_empty()).count();
    while nonempty > 0 {
        for b in buckets.iter_mut() {
            if let Some(p) = b.pop() {
                peers.push(p);
                if b.is_empty() {
                    nonempty -= 1;
                }
            }
        }
    }
}

async fn open_session_pool(
    transport: &Transport,
    peers: &PeerStore,
    max_sessions: usize,
) -> Result<Vec<SessionEntry>, ClientError> {
    open_session_pool_filtered(
        transport,
        peers,
        max_sessions,
        &std::collections::HashSet::new(),
    )
    .await
}

/// Identical to [`open_session_pool`] but excludes peers whose overlay
/// (lowercase hex) is in `exclude`. Used by [`SessionPool::top_up`]
/// for the daemon's background maintenance loop — we want to dial
/// *new* peers, not re-dial the ones already in the pool.
/// Where a pool fill delivers each successfully-opened session.
///
/// `Collect` gathers into a Vec handed over only when the fill
/// completes — the one-shot upload path wants the full pool before it
/// starts pushing. `Pool` appends each entry to a live [`SessionPool`]
/// the moment its dial succeeds, so concurrent readers (the daemon's
/// Status IPC, an upload racing the eager fill) see the pool grow in
/// real time instead of a None/empty pool until the last dial lands.
enum PoolSink<'a> {
    Collect(&'a mut Vec<SessionEntry>),
    Pool(&'a SessionPool),
}

async fn open_session_pool_filtered(
    transport: &Transport,
    peers: &PeerStore,
    max_sessions: usize,
    exclude: &std::collections::HashSet<String>,
) -> Result<Vec<SessionEntry>, ClientError> {
    let mut out = Vec::with_capacity(max_sessions);
    open_session_pool_into(
        transport,
        peers,
        max_sessions,
        exclude,
        PoolSink::Collect(&mut out),
    )
    .await?;
    Ok(out)
}

/// Core dial-window fill. Returns the number of sessions opened;
/// entries land wherever `sink` points (see [`PoolSink`]).
async fn open_session_pool_into(
    transport: &Transport,
    peers: &PeerStore,
    max_sessions: usize,
    exclude: &std::collections::HashSet<String>,
    mut sink: PoolSink<'_>,
) -> Result<usize, ClientError> {
    let log = transport.reachability_log();
    use futures::stream::{FuturesUnordered, StreamExt};

    // Walk every peer in the peerstore in a stable (closest-to-zero)
    // order. We keep `dial_parallelism` dials in flight at once and take
    // the first `max_sessions` successful ones — most candidate addresses
    // on mainnet are stale, so a wide dial window finds reachable peers
    // ~order-of-magnitude faster than a `max_sessions`-wide window.
    //
    // Peers we've recently failed to dial (within RECENT_FAILURE_SECS)
    // are moved to the end of the candidate list rather than dropped:
    // they're still tried if no fresher peer answers, but won't burn
    // 10 s timeouts at the front of the dial parade.
    // Spread the pool across the swarm address space rather than
    // clustering around a single reference. The earlier "closest to
    // zero" ordering biased every session toward overlays starting
    // with `0x00..`, which means random chunk addresses always hit
    // far peers (proximity 0-1) — bee then has to forward 8+ hops
    // and many receipts come back shallow. Sampling peers across PO
    // bins ensures that for any random chunk, some peer in the pool
    // is reasonably close.
    //
    // Reachability still matters: recently-failed peers move to the
    // back so we don't burn dial timeouts on known-dead hosts first.
    let now = crate::peers::now_unix();
    let mut all: Vec<(SwarmAddress, String, Multiaddr, u8, u32)> = peers
        .closest(&ChunkAddress::new([0u8; 32]), usize::MAX)
        .into_iter()
        .filter(|p| !exclude.contains(&p.overlay.to_lowercase()))
        .filter_map(|p| {
            let underlay = p.first_dialable_underlay()?;
            let overlay = p.overlay_address()?;
            Some((
                overlay,
                p.overlay.clone(),
                underlay,
                p.dial_rank(now),
                p.last_dial_rtt_ms.unwrap_or(u32::MAX),
            ))
        })
        .collect();
    spread_across_address_space(&mut all);
    // Front-load by reachability rank, then keep the address-space spread
    // *within* each rank tier. `dial_rank` is: 0 = recent success,
    // 1 = never tried (or a stale failure past its backoff, worth a retry),
    // 2 = soft failure (in backoff), 3 = hard failure (>=3 consecutive).
    //
    // A *stable* sort by rank preserves the PO-bin round-robin order that
    // `spread_across_address_space` just produced, so each tier is still
    // spread across the address space — we just dial all known-live peers
    // before any never-tried one, never-tried before soft-failed, and
    // soft-failed before hard-failed. This is what lets a warm pool fill
    // hit its first N sessions almost entirely on recent-success peers
    // (fast RTT, no dial-timeout gambles) instead of interleaving cold
    // candidates into the initial dial window.
    //
    // Rank 0 additionally tiebreaks on last-seen RTT (field 4, ms, lower
    // is faster) so the very front of the parade is the fastest known-live
    // peers. The address spread within rank 0 is mostly preserved because
    // RTT rarely ties; if it ever fully sorted away the spread we'd lose
    // bin coverage, but rank-0 peers are by definition reachable, so any
    // of them opens a session quickly regardless of proximity.
    all.sort_by(|a, b| {
        a.3.cmp(&b.3) // primary: rank ascending (0 best)
            .then_with(|| {
                if a.3 == 0 {
                    a.4.cmp(&b.4) // rank 0 only: faster RTT first
                } else {
                    std::cmp::Ordering::Equal // keep spread order for other ranks
                }
            })
    });
    // Browser only: interleave the dial parade across distinct host IPs.
    // Firefox serializes WebSocket handshakes per resolved IP
    // (nsWSAdmissionManager keys CONNECTING on the IP address, RFC 6455
    // §4.1), so a dial window full of same-host overlays — common on
    // mainnet, where one operator runs dozens of bees behind one IP and
    // hive announcements re-flood them into the store — degenerates into
    // a single-file convoy: one dead entry at the front costs its full
    // dial timeout before anything behind it on that IP even starts.
    // Round-robin across IP groups (preserving the rank/RTT order within
    // each group) so consecutive dials hit distinct hosts and each IP's
    // serialized lane is only ever one-deep per pass. Native TCP has no
    // per-IP handshake serialization and benefits from redundancy, so
    // this reorder is wasm-only. (The CI ws seed already dedupes to one
    // overlay per IP; this brings the same discipline to the runtime
    // store that discovery keeps re-polluting.)
    #[cfg(target_arch = "wasm32")]
    {
        fn host_key(ma: &Multiaddr) -> String {
            use libp2p::multiaddr::Protocol;
            for p in ma.iter() {
                match p {
                    Protocol::Ip4(ip) => return ip.to_string(),
                    Protocol::Ip6(ip) => return ip.to_string(),
                    // AutoTLS SNI hostnames start with the dashed IP
                    // (`116-202-192-234.k2k4…libp2p.direct`) — the first
                    // label identifies the host even without resolving.
                    Protocol::Dns4(h) | Protocol::Dns(h) | Protocol::Dns6(h) => {
                        return h.split('.').next().unwrap_or(&h).to_string();
                    }
                    _ => {}
                }
            }
            ma.to_string()
        }
        let mut groups: Vec<(String, std::collections::VecDeque<_>)> = Vec::new();
        for entry in all.drain(..) {
            let key = host_key(&entry.2);
            match groups.iter_mut().find(|(k, _)| *k == key) {
                Some((_, g)) => g.push_back(entry),
                None => {
                    let mut g = std::collections::VecDeque::new();
                    g.push_back(entry);
                    groups.push((key, g));
                }
            }
        }
        // Groups are in first-seen order, i.e. still best-rank-first.
        // Round-robin pop until every group is drained.
        loop {
            let mut took = false;
            for (_, g) in groups.iter_mut() {
                if let Some(e) = g.pop_front() {
                    all.push(e);
                    took = true;
                }
            }
            if !took {
                break;
            }
        }
    }
    let candidates: Vec<(SwarmAddress, String, Multiaddr)> = all
        .into_iter()
        .map(|(o, hex, u, _, _)| (o, hex, u))
        .collect();
    if candidates.is_empty() {
        return Err(ClientError::NoPeers("peerlist empty".into()));
    }

    // HOVERFLY_CONNECTIONS_PER_PEER (default 1) replicates each
    // candidate M times in the dial list, so up to M successful dials
    // become M independent `SessionEntry`s pointing at the same peer.
    // Each entry owns its own libp2p connection (its own yamux pipe),
    // so per-chunk dispatchers and pushers see them as independent
    // sessions with independent flow control.
    //
    // Pool size (`max_sessions` ≈ user's `--concurrency`) is unchanged
    // — it splits between unique peers and connections-per-peer
    // rather than multiplying. With `M=2`, a 128-session pool covers
    // ~64 unique peers with 2 connections each (peer-side accounting
    // is per overlay, so bee treats all M as one logical client with
    // a fresh per-connection yamux pipe each).
    //
    // The motivation is the buffer-scaling negative result
    // (`HOVERFLY_BUFFER_MULT`): per-connection yamux flow control is
    // the throughput wall once stream_pool's substream-open
    // parallelism is unlocked. Each additional connection adds
    // an independent yamux pipe to the same peer, so push attempts
    // can actually run in parallel on a per-peer basis.
    let conn_per_peer: usize = std::env::var("HOVERFLY_CONNECTIONS_PER_PEER")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|n: &usize| *n > 0)
        .unwrap_or(1);
    let candidates = if conn_per_peer > 1 {
        // Interleave rounds: [A, B, C, A, B, C, …] not [A, A, B, B, C, C, …]
        // so peer A's second dial doesn't race its own first dial
        // through the initial `SESSION_DIAL_PARALLELISM` window.
        let mut expanded = Vec::with_capacity(candidates.len() * conn_per_peer);
        for _ in 0..conn_per_peer {
            for e in &candidates {
                expanded.push(e.clone());
            }
        }
        debug!(target: "hoverfly::upload",
            "multi-connection pool fill: {} unique peers x {} conns/peer = {} dial candidates",
            candidates.len(), conn_per_peer, expanded.len());
        expanded
    } else {
        candidates
    };

    // Dial-search width is deliberately DECOUPLED from `max_sessions`. We keep
    // only the first `max_sessions` successful dials, but we must *search* far
    // wider than that to find them: on mainnet ~50%+ of candidates are stale,
    // and in the browser the candidate set is only the `/wss` minority (no raw
    // TCP), whose AutoTLS SNI hostnames rotate every few hours — so a large
    // fraction of even the fresh seed is already dead. Clamping the in-flight
    // dial window to `max_sessions` (e.g. 4 for a tiny upload) meant crawling
    // through that dead list 4 at a time, each dial burning the full
    // dial-timeout before the next candidate is tried — the dominant cause of
    // slow browser uploads. Search up to `SESSION_DIAL_PARALLELISM` wide
    // regardless of how many sessions we ultimately keep, bounded only by the
    // candidate count.
    let dial_parallelism = SESSION_DIAL_PARALLELISM.min(candidates.len().max(1));
    let mut iter = candidates.into_iter();
    let mut dialing = FuturesUnordered::new();
    let dial = |overlay: SwarmAddress, overlay_hex: String, underlay: Multiaddr| async move {
        let started = web_time::Instant::now();
        let result = transport.open_session(&underlay).await;
        let rtt_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
        (overlay, overlay_hex, underlay, result, rtt_ms)
    };

    // Seed initial in-flight window — wider than max_sessions to absorb
    // the high failure rate of mainnet peer dials.
    for (overlay, overlay_hex, underlay) in iter.by_ref().take(dial_parallelism) {
        dialing.push(dial(overlay, overlay_hex, underlay));
    }

    let mut added = 0usize;
    while let Some((overlay, overlay_hex, underlay, res, rtt_ms)) = dialing.next().await {
        match res {
            Ok(session) => {
                debug!(target: "hoverfly::upload",
                    "session opened to {} ({}) in {} ms",
                    overlay_hex, underlay, rtt_ms);
                log.lock().unwrap().insert(
                    overlay_hex.to_lowercase(),
                    DialResult::Success {
                        rtt_ms,
                        full_node: Some(session.peer_full_node()),
                    },
                );
                let entry = SessionEntry {
                    overlay,
                    overlay_hex,
                    underlay,
                    session: std::sync::Mutex::new(session),
                    pending: std::sync::Mutex::new(None),
                    prewarm_inflight: std::sync::atomic::AtomicBool::new(false),
                    failure_strikes: std::sync::atomic::AtomicU32::new(0),
                    skip_until_unix: std::sync::atomic::AtomicU64::new(0),
                    storage_radius: std::sync::atomic::AtomicU8::new(0),
                    push_latency_ewma_us: std::sync::atomic::AtomicU64::new(0),
                    push_success_count: std::sync::atomic::AtomicU64::new(0),
                    inflight_pushes: std::sync::atomic::AtomicU32::new(0),
                };
                match &mut sink {
                    PoolSink::Collect(v) => v.push(entry),
                    // Live-append: the session is usable by concurrent
                    // pool readers the moment it lands.
                    PoolSink::Pool(p) => p.push_entry(std::sync::Arc::new(entry)),
                }
                added += 1;
                if added % 8 == 0 || added == max_sessions {
                    info!(target: "hoverfly::upload",
                        "pool fill: {}/{} sessions open", added, max_sessions);
                }
                if added >= max_sessions {
                    break;
                }
            }
            Err(e) => {
                // Per-peer dial failures during pool fill are expected
                // on mainnet (~50%+ peers are stale / NAT'd / running
                // an incompatible bee). Stay at debug so the user-visible
                // log shows only the successful pool size.
                debug!(target: "hoverfly::upload",
                    "session to {} failed: {}", overlay_hex, e);
                log.lock()
                    .unwrap()
                    .insert(overlay_hex.to_lowercase(), DialResult::Failure);
            }
        }
        // Keep the in-flight window full so we don't sit waiting on a few
        // remaining timeouts when many candidates remain.
        if let Some((overlay, overlay_hex, underlay)) = iter.next() {
            dialing.push(dial(overlay, overlay_hex, underlay));
        }
    }
    info!(target: "hoverfly::upload",
        "pool fill: done with {} session(s) ({} requested)",
        added, max_sessions);
    Ok(added)
}

/// Quick reachability probe: dial each peer in parallel, record success/
/// failure (with rtt) into the reachability log without keeping the
/// resulting sessions open. Called optionally by `discover` after a hive
/// round to pre-prune dead peers from `peers.json`.
pub async fn healthcheck_peers(transport: &Transport, peers: &PeerStore, concurrency: usize) {
    let log = transport.reachability_log();
    use futures::stream::{FuturesUnordered, StreamExt};

    let zero = ChunkAddress::new([0u8; 32]);
    let candidates: Vec<_> = peers
        .closest(&zero, usize::MAX)
        .into_iter()
        .filter_map(|p| {
            let underlay = p.first_dialable_underlay()?;
            Some((p.overlay.clone(), underlay))
        })
        .collect();
    let total = candidates.len();

    let concurrency = concurrency.max(1);
    let mut iter = candidates.into_iter();
    let mut inflight = FuturesUnordered::new();
    let probe = |overlay_hex: String, underlay: Multiaddr| async move {
        let started = web_time::Instant::now();
        let res = transport.open_session(&underlay).await;
        let rtt_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
        // Capture the peer's node mode from the handshake before dropping it.
        let full_node = res.as_ref().ok().map(|s| s.peer_full_node());
        (overlay_hex, full_node, rtt_ms)
    };
    for (overlay_hex, underlay) in iter.by_ref().take(concurrency) {
        inflight.push(probe(overlay_hex, underlay));
    }
    let mut reached = 0usize;
    while let Some((overlay_hex, full_node, rtt_ms)) = inflight.next().await {
        let ok = full_node.is_some();
        if ok {
            reached += 1;
        }
        log.lock().unwrap().insert(
            overlay_hex.to_lowercase(),
            if ok {
                DialResult::Success { rtt_ms, full_node }
            } else {
                DialResult::Failure
            },
        );
        if let Some((overlay_hex, underlay)) = iter.next() {
            inflight.push(probe(overlay_hex, underlay));
        }
    }
    info!(target: "hoverfly::discover",
        "healthcheck: {}/{} peers reachable", reached, total);
}

fn parse_root(hex_str: &str) -> Result<ChunkAddress, ClientError> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x"))?;
    if bytes.len() != 32 {
        return Err(ClientError::BadHashLen(bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(ChunkAddress::new(arr))
}

fn parse_batch_id(hex_str: &str) -> Result<BatchId, ClientError> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x"))?;
    if bytes.len() != 32 {
        return Err(ClientError::BadBatchLen(bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(BatchId::from(arr))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod streamer_tests {
    use super::*;

    fn signer() -> SwarmSigner {
        SwarmSigner::from_hex_with_nonce(
            "0x2cfe73bcd53cc2708a35f6f2238e2aeeb0448b65339f43d398e736102a211569",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            1,
        )
        .unwrap()
    }

    const BATCH: &str = "0x2c18bcb885649cb468732c98d70d9cb0280aaffb30ffd0c882fccd8e22cd7408";

    /// UploadStreamer windows must yield exactly the same chunk set (by
    /// address) as the one-shot prepare, every stamp must validate to the
    /// signer, and the root must match — across several window sizes, at both
    /// redundancy levels (erasure adds parity chunks to the same stream).
    #[test]
    fn streamer_raw_matches_oneshot() {
        let s = signer();
        // ~40 KiB → many content chunks + intermediate chunks.
        let data: Vec<u8> = (0..40_000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();

        for level in [Level::None, Level::Medium] {
            let (root_oneshot, work) =
                prepare_upload_bytes(&s, BATCH, 19, false, &data, level).unwrap();
            let expected: std::collections::HashSet<[u8; 32]> =
                work.iter().map(|c| c.addr).collect();

            for window in [1usize, 7, 256, 100_000] {
                let mut stream =
                    UploadStreamer::new_raw(&s, BATCH, 19, false, &data, level).unwrap();
                assert_eq!(
                    stream.total_chunks(),
                    work.len(),
                    "chunk count ({level}, window={window})"
                );
                assert_eq!(
                    hex::encode(stream.root().as_bytes()),
                    hex::encode(root_oneshot.as_bytes()),
                    "root ({level}, window={window})"
                );
                let mut got: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
                loop {
                    let batch = stream.next_batch(window).unwrap();
                    if batch.is_empty() {
                        break;
                    }
                    for c in &batch {
                        let vs =
                            crate::stamp::validate(&c.addr, &c.stamp).expect("stamp validates");
                        assert_eq!(vs.signer, *s.eth_address(), "stamp signer");
                        got.insert(c.addr);
                    }
                }
                assert_eq!(got, expected, "chunk set ({level}, window={window})");
                assert_eq!(stream.remaining(), 0);
            }
        }
    }

    /// Erasure coding must reach the stamped output: a MEDIUM upload of the
    /// same bytes carries strictly more chunks than a plain one, and a
    /// different root (the level rides in the root chunk's span).
    #[test]
    fn erasure_upload_adds_parity_and_changes_root() {
        let s = signer();
        let data: Vec<u8> = (0..40_000u32)
            .map(|i| (i.wrapping_mul(0x9E37_79B1) >> 11) as u8)
            .collect();
        let (plain_root, plain) =
            prepare_upload_bytes(&s, BATCH, 19, false, &data, Level::None).expect("plain prepare");
        let (ec_root, ec) = prepare_upload_bytes(&s, BATCH, 19, false, &data, Level::Medium)
            .expect("erasure prepare");
        assert_ne!(plain_root, ec_root);
        assert!(ec.len() > plain.len(), "{} !> {}", ec.len(), plain.len());
        // Every erasure chunk is still a validly stamped, correctly addressed
        // chunk. `validate_delivery` is the exact check the retrieval path
        // applies on the wire, and it has to pass for all three kinds this
        // produces: content chunks, parity chunks (whose spans are RS output,
        // not lengths) and the dispersed root replicas (single-owner chunks,
        // addressed by `keccak256(id || owner)` rather than a BMT root).
        let mut socs = 0usize;
        for c in &ec {
            let vs = crate::stamp::validate(&c.addr, &c.stamp).expect("stamp validates");
            assert_eq!(vs.signer, *s.eth_address());
            let addr = ChunkAddress::from(c.addr);
            assert!(
                validate_delivery(&c.wire, &addr),
                "chunk must validate as a content or single-owner chunk"
            );
            if crate::erasure::wire_address(&c.wire) != Some(addr) {
                socs += 1;
            }
        }
        // MEDIUM stores two dispersed replicas of the root.
        assert_eq!(socs, 2, "expected exactly the two root replicas as SOCs");
    }

    /// The manifest (single-file) streamer root must equal the one-shot
    /// manifest root.
    #[test]
    fn streamer_file_root_matches_oneshot() {
        let s = signer();
        let data = b"hoverfly streaming upload manifest root check".repeat(50);
        let (root_oneshot, _) = prepare_upload_file_with_manifest(
            &s,
            BATCH,
            19,
            false,
            &data,
            "f.bin",
            None,
            Level::Medium,
        )
        .unwrap();
        let stream =
            UploadStreamer::new_file(&s, BATCH, 19, false, &data, "f.bin", None, Level::Medium)
                .unwrap();
        assert_eq!(
            hex::encode(stream.root().as_bytes()),
            hex::encode(root_oneshot.as_bytes())
        );
    }
}
