// Static configuration for the Swarm upload dApp.

// ---- Pusher relays ----
/**
 * Pusher relay URLs (`hoverfly pusher` nodes, docs/pusher-design.md). When
 * non-empty, uploads go through these relays instead of dialing bees in the
 * browser over wss: the browser stamps chunks locally (BMT + EIP-191, pure
 * CPU in wasm) and POSTs pre-signed frames to a relay, which pushes them into
 * the swarm over real TCP libp2p. This escapes the browser's wss-sliver
 * problem — reach becomes the relay's (all ~2,800 bees over TCP) instead of
 * the ~7 flaky wss AutoTLS hosts a browser can dial. The signing key never
 * leaves the browser. Set to `[]` to fall back to the legacy in-browser p2p
 * push path.
 *
 * Chunks are sharded across the lanes (rendezvous hashing) and pushed
 * concurrently; a chunk unacked by one lane fails over to the next.
 *
 * Payment is per lane and optional (docs/pusher-incentives.md). A lane
 * advertising `enforcement: "hard"` in its `/v1/status` is dropped from
 * rotation at startup by `setLaneStatus`, because this dApp only stamps —
 * the chequebook lives in the native client. Such a lane is listed anyway so
 * a native `--chequebook` run of the same fleet picks it up.
 */
export const PUSHER_URLS: string[] = [
  'https://hoverfly-pusher.onrender.com',
  'https://hoverfly-pusher-2.onrender.com',
  'https://hoverfly-pusher-3.onrender.com',
  // Hugging Face Space — a different provider/IP-range from Render (probed:
  // HF permits outbound TCP to bee nodes), for cross-provider lane diversity.
  'https://ivam5567-hoverfly.hf.space',
  // A self-hosted VPS lane, and the first metered one: it runs `--meter` with
  // hard enforcement, so it serves paying native clients and is skipped by
  // the browser. Unlike the free tiers above it doesn't cold-start.
  'https://pusher.browserbzz.link'
]
/**
 * How long to wait for a relay's `/v1/status` before scheduling it on
 * defaults. Free-tier instances cold-start (measured: 35 s to first byte on a
 * sleeping Render container), but a slow advertisement must not hold up the
 * upload — the lane simply starts on priors and corrects itself from observed
 * throughput.
 */
export const STATUS_TIMEOUT_MS = 8_000
/** True when the dApp should push through relays rather than in-browser p2p. */
export function usePushers (): boolean { return PUSHER_URLS.length > 0 }

// ---- Swarm network ----
/** 1 = mainnet, 10 = testnet/sepolia. Stamps + overlay derivation use this. */
export const NETWORK_ID = 1
export const DEFAULT_BOOTSTRAP = '/dnsaddr/mainnet.ethswarm.org'
/** Seconds to wait for hive announcements per dialed underlay during discover. */
export const DISCOVER_WAIT_SECS = 8
/** Per-chunk peer-attempt cap during push (0 = try every candidate). */
export const UPLOAD_RETRIES = 24
/**
 * Target size of the warm push-session pool. The gateway uses 0 (UNLIMITED) but
 * it runs in a SharedWorker, off the main thread. This dApp runs hoverfly in the
 * FOREGROUND, so an unlimited pool — hundreds of live wss connections + buffers
 * driven on the main thread — janks the page and eats RAM. A small bounded pool
 * is enough to start an upload (push opens more sessions on demand) and keeps the
 * UI responsive.
 */
export const WARM_POOL = 8
/**
 * Background maintenance interval (seconds) for hoverfly's discover/re-warm loop.
 * For a one-shot upload tool we don't need aggressive upkeep, so keep it large to
 * minimise ongoing main-thread churn. (A standing pool matters far less here than
 * for a long-lived fetch gateway.)
 */
export const MAINTENANCE_SECS = 300
/** How often (seconds) the worker re-reads + posts the connected-peer count. */
export const STATUS_POLL_SECS = 5

// ---- on-chain (Swarm sits on Gnosis) ----
// Mirrors src/batch.rs constants verbatim (the native CLI's `batch create`).
export const GNOSIS_CHAIN_ID = 100
/** PostageStamp contract (go-storage-incentives-abi v0.9.4). */
export const POSTAGE_STAMP = '0x45a1502382541Cd610CC9068e88727426b696293' as const
/** BZZ ERC-20 token. 16 decimals — 1 BZZ = 1e16 PLUR. */
export const BZZ_TOKEN = '0xdBF3Ea6F5beE45c02255B2c26a16F300502F68da' as const
/** Bee hard-codes bucketDepth = 16; the contract rejects anything else. */
export const BUCKET_DEPTH = 16
/**
 * How long (ms) to wait after buying a NEW batch before allowing uploads to it.
 *
 * A batch only becomes stampable once bee nodes have ingested its on-chain
 * `BatchCreated` event into their replicated batchstore. We used to poll
 * swarmscan until it returned the batch, but that put a third-party indexer on
 * the critical path — if it's down or lagging, the upload stalls. A fixed short
 * wait is simpler and has no external dependency: bees typically ingest the
 * event within a few seconds. Reused/imported batches skip this wait entirely.
 */
export const BATCH_READY_WAIT_MS = 10_000
/** Gnosis block time (seconds), stable since launch — used for duration math. */
export const GNOSIS_BLOCK_TIME_SECS = 5
/** A public Gnosis RPC, used only for read calls if the wallet chain differs. */
export const GNOSIS_RPC = 'https://rpc.gnosischain.com'

// ---- wasm asset ----
export const ASSET_PREFIX = '/__up__/'
/** wasm-bindgen `--target web` entry, vendored from the repo's pkg/. */
export const HOVERFLY_JS = `${ASSET_PREFIX}hoverfly/hoverfly.js`
/** The hoverfly node Worker bundle (built by esbuild as a separate entry). */
export const WORKER_JS = `${ASSET_PREFIX}worker.js`

// ---- peer seed (cold-start) ----
/**
 * Cold-start peer seed: browser-dialable (/ws[s]) peers harvested from mainnet.
 * Fetched fresh from the GitHub raw CDN (the repo's `refresh-peers` workflow
 * re-derives it hourly) so discovery starts warm instead of cold-dialing the
 * bootnode. mainnet /ws underlays go stale within ~2-3h (AutoTLS SNI rotation),
 * so the hourly CDN copy beats the build-time bundled copy. The bundled copy
 * (vendored into dist/__up__/peers.ws.json by build.js) is the fallback when the
 * CDN is unreachable. Set to undefined to use only the bundled copy.
 */
export const PEERS_SEED_URL: string | undefined =
  'https://raw.githubusercontent.com/omnipin/hoverfly/main/peers.ws.json'
/** Bundled fallback seed, relative to the app assets. */
export const PEERS_SEED_BUNDLED = `${ASSET_PREFIX}peers.ws.json`

// ---- persistence ----
export const LS_SESSION_KEY = 'hoverfly-upload:session-key-hex'
export const LS_BATCHES = 'hoverfly-upload:batches'
/** IndexedDB for the warm peer set persisted across reloads (like the gateway). */
export const IDB_NAME = 'hoverfly-upload'
export const IDB_STORE = 'kv'
export const IDB_PEERS_KEY = 'peerstore-json'

// ---- public gateway (for verifying the resulting reference) ----
export const PUBLIC_GATEWAY = 'https://bzz.limo/bzz/'

// ---- batch discovery (Swarmscan) ----
/**
 * Swarmscan indexes PostageStamp events (it's what batch-explorer.github.io
 * uses). There's no owner-filtered query — `owner` isn't an indexed topic — but
 * the `batch-created` feed exposes `data.owner` per event, so we fetch it and
 * filter by the session key client-side. The feed only exposes the latest ~100
 * events (its `next` cursor doesn't advance), which is fine: a freshly-minted
 * session key's batches are recent and land in that window. CORS is open.
 */
export const SWARMSCAN_BATCH_CREATED =
  'https://api.swarmscan.io/v1/events/postage-stamp/batch-created'
