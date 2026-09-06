# AGENTS.md

hoverfly is a Rust crate: a minimal, WASM-portable **Swarm (Ethereum Swarm)
light client**. It speaks the real Bee wire protocols (handshake, hive,
pricing, pseudosettle, pushsync, retrieval, swap, status) directly over
libp2p, so it participates in the mainnet network as a first-class light
peer — it dials bees, gets dialled back, accounts/settles, uploads and
retrieves chunks — without running a full Bee node or storing the network's
chunks. It is *not* a thin HTTP wrapper around a gateway and not a full node.

User-facing operations: `discover`, `fetch` (incl. mantaray manifest path
resolution and mutable **feed**/ENS resolution), `upload` (raw / manifest /
collection, Reed–Solomon `--redundancy`, optional `--pusher` relay lanes),
a long-running `daemon` (plus `status`, `save-peers`), on-chain helpers
(`batch create`, `chequebook deploy`/`fund`/`status`, `bridge`, relay
`cashout`), offline hashing (`bmt`), `vanity-overlay`, and the `pusher`
relay server itself.

`README.md` is the repo readme (brand mark: `logo.svg` above the title).
`README.npm.md` is the published-package readme for `@omnipin/hoverfly`.
There is no `package.json` / `index.ts` / `bun.lock` / `node_modules` at the
root anymore (those old `bun init` leftovers are gone; a root `tsconfig.json`
with bun types is still lying around — harmless, each app carries its own
tsconfig). Other top-level entries: `install.sh`, `Cargo.toml` /
`Cargo.lock`, `proto/` (+ `build.rs`), `vendor/futures-bounded`, `scripts/`,
`examples/` (`regen-protos.rs`, `upload.yml`), `tests/`
(`attack_vectors.rs`), `docs/` (`pusher-design.md`, `pusher-incentives.md`,
`deck/`), `PERFORMANCE.md`, `apps/`, `.cargo/config.toml`, `Dockerfile`.

## Transport

Native (`cfg(not(target_arch = "wasm32"))`) and WASM differ:

- **Native** speaks plain TCP **and** TCP-over-WebSocket, combined via
  `or_transport` in `src/transport.rs::build_swarm_from`. libp2p picks the
  right inner transport from the multiaddr's protocol stack. Mainnet bees
  publish plain `/ip4/.../tcp/.../p2p/...` underlays (no `/ws`), so on a
  native CLI run almost every dial is raw TCP; only WASM is WS-only
  (browsers can't open raw TCP sockets, so `src/transport.rs::build_swarm`
  uses `libp2p::websocket_websys` only, via the vendored `src/wsws/`).
- Dialability is gated at peerlist-ingestion time by
  `src/dnsaddr.rs::is_dialable_multiaddr`: requires `/ip4/` (no DNS resolver,
  no v6) and either `/ws[s]` or plain `/tcp/` on native, `/ws[s]` only on
  wasm. The peers.json store reuses the same predicate via
  `peers.rs::is_dialable_str` in `PeerStore::upsert`.
- Outbound dials are paced by `src/ratelimit.rs` (per-peer GCRA, mirrors bee's
  ~10/s + burst-40 `/32` conn limiter): over-budget dials park on a delay
  instead of failing; only past the reservation bound does it return
  `DialTooSoon` so the chunk fails over to another peer.
- DNS is **DoH-only** (`src/doh.rs`, `src/dnsaddr.rs`) — no system resolver.
  `/dnsaddr/mainnet.ethswarm.org` is resolved over HTTPS the same way in CLI,
  daemon and browser.

### Concurrent substream opens (vendored `stream_pool`)

`src/protocols/stream_pool/` is a **vendored, patched copy of
`libp2p_stream`** (upstream `protocols/stream`). The one change: upstream
serialises outbound substream upgrades behind a singular `pending_upgrade:
Option<…>`, so every pushsync chunk's substream open blocks on the previous
one — this dominated per-chunk wall time. Our `Handler` replaces that slot
with a `HashMap<UpgradeId, …>` keyed by a monotonic `u64`, so many upgrades
are in flight at once. Public API (`Behaviour`, `Control`, `IncomingStreams`,
`OpenStreamError`, `AlreadyRegistered`) is identical to upstream. Cap is
`DEFAULT_MAX_CONCURRENT_OUTBOUND_UPGRADES = 64`
(`stream_pool/handler.rs`), tunable via the CLI `--substream-upgrade-cap` /
`TransportConfig::max_concurrent_substream_upgrades`. There is **no external
`libp2p-stream` dependency** anymore.

## Build

- Native: `cargo build` / `cargo build --release`. Release is ~2-5× faster on
  crypto paths but only ~10-15% end-to-end (network dominates).
- Edition **2024**; crate version tracked in `Cargo.toml` (`0.x`, currently
  `0.2.0`).
- Default features are `cli`, `bridge`, `pusher`. `--no-default-features
  --features cli` drops both the bridge and the relay server (native-only
  code is compiled out entirely).
- WASM: **nightly + `build-std` + `--no-default-features`** (the `cli`
  feature pulls non-wasm deps). `.cargo/config.toml` already sets the
  atomics/bulk-memory rustflags. After any lib change:

  ```
  RUSTUP_TOOLCHAIN=nightly cargo check --target wasm32-unknown-unknown --no-default-features
  ```

  **Threaded vs. threadless wasm (`wasm-threads` feature).** `wasm-threads`
  (default-OFF) forwards to `nectar-primitives/wasm-threads`, the only thing
  that pulls `wasm-bindgen-rayon` — whose presence forces wasm-bindgen's threads
  transform and a *shared* (`SharedArrayBuffer`) memory, requiring COOP/COEP
  cross-origin isolation on the hosting page. Two intended builds:
  - **Gateway (threaded):** `--no-default-features --features wasm-threads`,
    with the atomics/`--shared-memory` rustflags from `.cargo/config.toml`.
    Faster BMT hashing; must be served cross-origin-isolated. This is what
    `apps/gateway` builds. It calls `initThreadPool` and polls retrieval
    futures across Web Worker threads (see `idb_chunk_store` threading note).
  - **Upload dApp (threadless, no shared memory):** `--no-default-features`
    (omit `wasm-threads`) **and** override the rustflags with empty `RUSTFLAGS`
    so `--shared-memory`/`+atomics` aren't applied → a plain non-shared linear
    memory, no `SharedArrayBuffer`, no COOP/COEP. Runs on hosts that can't set
    those headers (e.g. the eth.limo ENS gateway). See `apps/upload/build-wasm.sh`.
    Single-threaded: **do not** call `initThreadPool` on this build, and nectar's
    `split` rayon paths run inline with no pool. (The upload path also must never
    hit `std::time::{SystemTime,Instant}::now()` — use `web_time`/`js_sys::Date`
    — and must avoid rayon contention on `parking_lot` locks, which can't park
    a thread on wasm.)

  Nectar crates are pulled from **upstream 0.4.0** (crates.io). The old
  `[patch.crates-io]` omnipin fork and its bespoke `wasm-threads` gate are
  gone — upstream has `MaybeSend`/`MaybeSync` (Send/Sync relaxed on
  wasm) and `web_time` natively. API notes vs the pre-0.3.0 shape:
  - `sync_split` → `split` (free function, same signature)
  - `SyncChunkGet`/`SyncChunkPut` → removed (use async `ChunkGet`/`ChunkPut`)
  - `ChunkStoreError::Other(String)` → `ChunkStoreError::Other(Box<dyn Error + Send + Sync>)`
  - `MemoryIssuer::from_batch` returns `Result<_, IssuerError>`

  (Caveat: `src/manifest.rs` docs still cite nectar-mantaray's
  `SyncChunkGet`-bounded public walk as one reason for the hand-rolled
  decoder — that describes nectar-mantaray's API surface, not our store,
  which only ever implements async `ChunkGet`. The `Cargo.toml` comments
  name-dropping nectar 0.1.0 / alloy-primitives 1.5.x are likewise stale;
  the tree is on nectar 0.4.0 / alloy-primitives 1.6.)

  There **is** one active `[patch.crates-io]`: `futures-bounded` →
  `vendor/futures-bounded`, whose `Delay::tokio` falls back to
  `futures-timer` on wasm32 (real tokio's timer panics in the browser). This
  fixes libp2p-identify's (and any other) `futures_bounded::Delay::tokio`
  usage on wasm.

  First-time setup:
  ```
  rustup target add wasm32-unknown-unknown --toolchain nightly
  rustup component add rust-src --toolchain nightly
  ```

- `build.rs` runs `prost-build` over every file in `proto/`. New wire types
  go in `proto/` and are re-exported under `src/lib.rs::proto`. Regenerate the
  committed `src/proto/*.rs` with `scripts/regen-protos.sh` (uses the
  `regen-protos` example + `prost-build` dev-dep; not part of a normal build).

## Binaries

- `hoverfly` (`src/bin/hoverfly.rs`) — the CLI. Always available:
  `discover`, `fetch`, `upload`, `bmt` (compute a BMT/collection root
  offline), `vanity-overlay`. `#[cfg(unix)]` only: `daemon`, `save-peers`,
  `status` (pool live-vs-target + peerlist candidates), `batch create`
  (on-chain postage batch), `chequebook deploy`/`fund`/`status` (SimpleSwap
  chequebook lifecycle). Feature-gated: `pusher` (HTTP chunk-push relay;
  `#[cfg(feature = "pusher")]`), `cashout` (bank metered-relay cheques from
  `ledger.json`; `#[cfg(all(unix, feature = "pusher"))]`), `bridge`
  (`#[cfg(feature = "bridge")]`, default-on). The `fetch`/`upload --daemon`
  client flags are `#[cfg(unix)]` too.
- `sigcheck` (`src/bin/sigcheck.rs`) — signer/handshake reference comparison
  tool, not user-facing.

`hoverfly` requires `--features cli` (default). The `cli` feature gates `clap`,
`tracing-subscriber`, `tar`, and `indicatif`.

The `bridge` feature (default-on) gates the `hoverfly bridge` subcommand and
`src/bridge.rs`. Compile it out with `--no-default-features --features cli`.
It adds no new dependencies (reuses the reqwest + alloy signing stack already
pulled in for `batch.rs`) and is native-only
(`#[cfg(all(not(target_arch = "wasm32"), feature = "bridge"))]`).

The `pusher` feature (default-on) gates the `hoverfly pusher` relay server
plus the relay-side ledger/metering (`src/pusher.rs`, `src/ledger.rs`,
`src/metered.rs`, `src/inbound_limit.rs`). Compile it out with
`--no-default-features --features cli`. It pulls `hyper`/`hyper-util`/
`http-body-util` and is native-only
(`#[cfg(all(feature = "pusher", not(target_arch = "wasm32")))]`). The
*client* half of paid relaying (`src/challenge.rs`, `src/meter.rs`,
`src/payer.rs`) is `#[cfg(not(target_arch = "wasm32"))]` but deliberately
**not** `pusher`-gated: `client.rs` reaches for it on every relay push, so
gating it would break `--no-default-features --features cli` builds (see the
comment atop those modules in `src/lib.rs`).

## Apps (browser front-ends embedding the wasm)

- `apps/gateway/` — browser-only Swarm **subdomain gateway** (like the IPFS
  service-worker-gateway). One `SharedWorker` runs a single hoverfly node for
  the whole gateway (warm peers + warm session cache); a broker iframe bridges
  the daemon MessagePort to each `<cid>.bzz.*` content origin; a service
  worker resolves paths against the mantaray manifest and returns `Response`s.
  Uses the **threaded** wasm build → requires COOP/COEP (its `serve.js`
  sets them). esbuild + pnpm.
- `apps/upload/` — prototype in-browser **upload dApp**. Connect an EIP-1193
  wallet (Gnosis/chain 100) → buy a postage batch → upload a file via an
  embedded hoverfly wasm node running in a Worker. Foreground-only (no
  SharedWorker). Uses the **threadless** wasm build (`build-wasm.sh`) → no
  `SharedArrayBuffer`, no COOP/COEP, so it can be hosted on the eth.limo /
  eth.link ENS gateway (which only send `Cross-Origin-Resource-Policy`).
  Key design: to avoid ~thousands of per-chunk wallet popups it mints an
  ephemeral in-browser secp256k1 **session key**, sets it as the `createBatch`
  owner, and signs all stamps locally (session-key.ts / wallet.ts isolate the
  signer so AA/7702/7579 can drop in later).

## Tests / verification

~260 unit tests live next to the code (`#[test]` almost everywhere;
`#[tokio::test]` only in `src/daemon.rs` and `src/feed.rs`), plus
`tests/attack_vectors.rs` (adversarial pure-logic tests for the
`docs/pusher-incentives.md` threat model — challenge MACs, ledger
monotonicity, cheque decoding, quote/credit/scheduler accounting; run with
`cargo test --test attack_vectors`). Heaviest suites: `src/payer.rs`,
`src/pushsched/tests.rs` (deterministic mock-lane + virtual-clock simulation,
no network/clock/threads), `src/meter.rs`, `src/metered.rs`, `src/ledger.rs`,
`src/erasure/encoder.rs`. `dev-dependencies = tokio-test` still exists but is
near-unused (one `block_on` in `src/protocols/pushsync.rs`). Verify changes by:

1. `cargo test` (native) + `cargo build` + the wasm check above. All must pass.
2. End-to-end against mainnet:
   `discover --healthcheck` → `upload` → cross-verify via
   `https://api.gateway.ethswarm.org/bzz/<root>/<path>` or `https://bzz.limo/bzz/<root>/`.
   The public gateway is flaky/rate-limited; an HTTP 500 typically means
   the chunk neighborhood isn't yet retrievable from that gateway's view,
   not a correctness bug. Bee dedupes by chunk address — re-uploading the
   same bytes is a no-op, so always use a fresh random file for perf work.

## WASM constraints (will bite you)

- `tokio_with_wasm::time::{Sleep, Timeout, Interval}` are **not `Send`**.
  Upstream nectar uses `MaybeSend`/`MaybeSync` on wasm, relaxing the
  `+ Send` bound on ChunkGet. Both `ChunkGet` impls in `client.rs`
  (native + wasm) are now identical plain `async fn` bodies — the old
  `SendWrapper` workaround on the retrieval path is gone. `send_wrapper` is
  still used by `src/wsws/mod.rs` to make the WebSocket `Connection` struct
  `Send` (libp2p's transport trait requires it).
- Per-target `impl` blocks gated by
  `#[cfg(target_arch = "wasm32")]` / `#[cfg(not(target_arch = "wasm32"))]`.
- The manifest walk keeps one async body and gates only the trait-object
  bound per target (`MaybeSendWalk` in client.rs: `+ Send` on native so the
  daemon can `tokio::spawn` a list request, dropped on wasm where the store
  is IndexedDB-backed and `!Send`). Fetch paths use `FuturesUnordered` on
  both targets.
- `tokio_with_wasm` is missing: `runtime::Handle`, `time::Instant`,
  `time::interval_at`, `Sleep::reset`. For sleep-resets, re-pin a fresh
  `Box::pin(tokio::time::sleep(d))`. On the upload/wasm path never call
  `std::time::{SystemTime,Instant}::now()` — use `web_time::Instant` or
  `js_sys::Date`.
- `Cargo.toml` deliberately pulls three `getrandom` package versions
  (0.2, 0.3, 0.4) on wasm — alloy-primitives 1.x pulls 0.4 transitively.
  Do not "clean up" these duplicates without checking the transitive graph.
- `futures-timer` is pulled with the `wasm-bindgen` (gloo-timers) feature so
  libp2p-swarm/ping's `Delay` doesn't panic in-browser.

## Architecture map

- `src/transport.rs` — libp2p transport (dual TCP + WS on native, WS-only on
  wasm), per-peer `PeerSession` with a single swarm-driver task + concurrent
  pushes via `Arc<SessionState>` + cloned stream-pool `Control`.
  Accounting (`reserve_plur`, `balance_plur`, pseudosettle) lives here,
  guarded by `tokio::sync::Mutex`. Client-side ghost-balance mirror retires
  the session at `GHOST_BALANCE_LIMIT_PLUR`; `MAX_PUSHES_PER_SESSION` is the
  defence-in-depth ceiling. Hosts `TransportConfig`
  (incl. `max_concurrent_substream_upgrades`).
- `src/client.rs` — high-level `discover`/`fetch`/`upload`. `NetworkedStore`
  implements nectar's `ChunkGet`; cache is shared via `Clone`. Fetch resolves
  mantaray manifest paths and mutable **feeds** (`resolve_feed_root`,
  delegating to `src/feed.rs`). Upload uses an adaptive session pool with
  pre-warmed rotation, proximity-sorted per-chunk peer ordering, and an
  in-flight buffer capped at 128. Public `SessionPool` lets the daemon reuse a
  warm pool across requests; `*_with_pool` variants of `upload_bytes` /
  `upload_file_with_manifest` call `push_chunks_with_pool` directly.
  Collections still go through the one-shot `upload_collection`. Only the
  `DEFAULT_*` concurrency consts are `pub`; the tuning consts
  (`CHUNK_PEER_PARALLELISM`, `PREEMPT_INTERVAL`, `MAX_CHUNK_RETRIES`,
  `DEAD_SKIP_SECS`/`DEAD_STRIKES`, `SESSION_DIAL_PARALLELISM`) are private.
- `src/feed.rs` — Swarm **feed retrieval** (read-only). Resolves the latest
  update of a sequence-indexed feed (single-owner chunks) via a concurrent
  exponential-probe + k-ary search, then extracts the content reference. Feed
  params come from a feed manifest's root-entry metadata (`swarm-feed-owner`
  / `-topic` / `-type`); this is how feed-backed ENS sites stay updatable.
  Publishing feeds is out of scope. Mirrors bee `pkg/feeds`.
- `src/daemon.rs` — `#[cfg(unix)]` only. Long-running daemon that owns a
  `Transport` + in-memory `PeerStore` + lazy `Arc<SessionPool>` reused across
  requests. Unix-socket IPC, `u32-LE length` + JSON wire protocol. File
  contents pass by absolute path (not inline). **Not a security boundary** —
  anyone with socket access can read/write the daemon's filesystem and sign
  uploads with whatever key they send.
- `src/inbound.rs` — `#[cfg(not(target_arch = "wasm32"))]` only. Optional
  daemon listener for serving retrieval requests from the local upload cache
  (default `/ip4/0.0.0.0/tcp/1634/ws`; needs `--advertise .../p2p/<id>` for
  kademlia insertion, else it stays local-only). Serves handshake / pricing /
  retrieval responders so fresh roots resolve via `bzz.limo` pre-pushsync.
  No pullsync responder by design (we store no chunks).
- `src/inbound_limit.rs` — `#[cfg(all(feature = "pusher",
  not(target_arch = "wasm32")))]`. Inbound token-buckets for the relay HTTP
  surface (per-IP `/v1/challenge`, per-account `/v1/pay|push`). Refuses
  immediately instead of parking (a parking limiter would be a memory
  amplifier); fail-closed eviction. Cannot reuse `ratelimit.rs` for this
  reason.
- `src/protocols/` — bee wire protocols. Current on-wire ids:
  `handshake` `15.0.0` (+ `14.0.0` fallback), `hive` `2.0.0` (+ `1.1.0`),
  `pricing` `1.0.0`, `pseudosettle` `1.0.0`, `pushsync` `1.3.1`,
  `retrieval` `1.4.0`, `swap` `1.0.0`, `status` `1.1.3`; plus `framing`
  and the vendored `stream_pool`. `handshake` and `hive` support two
  versions concurrently (bee 2.8.0 raised handshake `14→15` and hive
  `1.1→2.0` as a network-wide upgrade, May 2026): outbound tries v15/v2
  first and falls back on `UnsupportedProtocol`; inbound accepts both ids in
  parallel. The `Version` enum on each module disambiguates downstream. The
  `status` responder is inbound-only; bee's `pkg/salud` probes us to decide
  whether to mark us Healthy in its kademlia metrics collector.
- `src/bridge.rs` — `#[cfg(all(not(target_arch = "wasm32"), feature =
  "bridge"))]`. The *second* RPC-touching module (alongside `batch.rs`),
  feature-gated and native-only. Funds the signer's Gnosis address with
  xDAI + BZZ from another chain via the permissionless Relay REST API
  (`POST /quote/v2` → broadcast the returned origin-chain deposit tx(s) →
  poll `/intents/status/v3` until the solver fills on Gnosis). Signs
  **type-2 (EIP-1559)** origin txs (`sign_eip1559_tx`), unlike `batch.rs`'
  legacy type-0 — the L2 origins return 1559 fee fields. `--to both` uses
  the Beeport pattern: conditional xDAI gas top-up (only when the
  recipient is below threshold) followed by a BZZ swap, so it's one origin
  swap in the common case and two when a top-up is needed. No API key
  required (Relay is permissionless). `--from-token` accepts a bare symbol
  (e.g. `USDC`), resolved to the canonical address + decimals via Relay's
  `/chains` token list (`resolve_token`); a raw `0x` address is used
  verbatim with `--from-decimals`; omitted = native gas token. Verified
  end-to-end on Base→Gnosis mainnet (both address and symbol forms).
- `src/batch.rs` — `#[cfg(not(target_arch = "wasm32"))]`. On-chain postage
  batch creation on Gnosis (mirrors bee `postagecontract.CreateBatch`):
  approve BZZ → `createBatch(...)` (legacy EIP-155 type-0 tx via `alloy-rlp`)
  → parse the `BatchCreated` event. Depth/amount math is mirrored by
  `apps/upload`.
- `src/cheques.rs` — `#[cfg(not(target_arch = "wasm32"))]`. JSON-backed
  per-peer cumulative-payout sidecar (`cheques.json`). Required to
  persist across CLI runs because bee rejects non-strictly-increasing
  `CumulativePayout` (`chequestore.go::ErrChequeNotIncreasing`). Loaded
  by the CLI at startup when `--chequebook` is set, mutated under
  `SessionState::settle_lock`, flushed on upload completion.
- `src/peers.rs` — JSON-backed peer store. Each `Peer` carries a
  reachability cache (`last_dial_success_unix`, `last_dial_failure_unix`,
  `consecutive_failures`, `last_dial_rtt_ms`). `RECENT_FAILURE_SECS = 300`
  defines the deprioritization window. `upsert` filters underlays via
  `is_dialable_str` (same predicate as the transport), so non-`/ip4/` and
  non-dialable entries are silently dropped on ingestion.
- `src/stamp.rs` — postage-stamp wire validator (113-byte
  `[batch32|index8|ts8|sig65]` shape + EIP-191 owner recovery). Signature-only:
  does NOT verify on-chain batch ownership (no-RPC rule) — safe only because
  the stamp path is upload-only; there is no pullsync ingestion to forge
  against.
- `src/manifest.rs` — hand-rolled mantaray v0.1/v0.2 decoder + walker (the
  *decode* side; the *encode* side already uses `nectar-mantaray`). Kept
  because nectar's public walk is sync-bound and its `Node` fork/metadata
  fields aren't public — see the module docs and upstream nectar#37.
- `src/pusher.rs` — `#[cfg(all(feature = "pusher",
  not(target_arch = "wasm32")))]`. HTTP chunk-push relay (`POST /v1/push`
  takes pre-signed frames, streams NDJSON acks; `GET /v1/status`;
  flag-gated `POST /v1/probe` + `/v1/tcpcheck` experiment endpoints). Open
  mode admits a frame iff its stamp recovers to a live batch owner
  (`remainingBalance > 0`, cached RPC); key material never crosses the wire
  (the probe's env-key signing is the sole exception, off by default). See
  `docs/pusher-design.md`.
- `src/pushframe.rs` — ungated (native + wasm). The push-body codec both
  sides share: `addr(32) | stamp(113) | wire_len(u16LE) | wire(≤4104)`.
  `encode_*` asserts on bad stamp/wire instead of returning `Err` — callers
  must come from `prepare_upload_*`.
- `src/meter.rs` — `#[cfg(not(target_arch = "wasm32"))]`. Stage-0 shadow
  metering: counts what billing *would* be (served via `/v1/meter`), no wire
  change and no refusals; gates stage-1 rollout on volume. In-memory only —
  restarts reset the window.
- `src/metered.rs` — `#[cfg(all(feature = "pusher",
  not(target_arch = "wasm32")))]`. Relay-side stages 1–2: soft meters and
  serves, hard flips to 402 with shared over-cap arithmetic. No challenge on
  file in soft mode means unmetered (rollout state); a present-but-invalid
  challenge is refused in both modes.
- `src/payer.rs` — `#[cfg(not(target_arch = "wasm32"))]`. Client half of
  stage-1: verify + pin the relay quote → challenge + header → split POST
  capped at `cap_plur` → cumulative cheque every `settle_every`. Bills from
  bytes *sent*, never from relay reports (on dispute: don't pay). The account
  key is the batch stamp key — no extra wallet prompt.
- `src/ledger.rs` — `#[cfg(all(feature = "pusher",
  not(target_arch = "wasm32")))]`. Relay billing ledger
  (`owed + reserved + last_cumulative + chequebook→account` under one lock,
  atomically persisted). `reserved` intentionally resets to zero at boot;
  losing `last_cumulative` alone replays a full cumulative cheque — guard the
  state dir accordingly.
- `src/challenge.rs` — `#[cfg(not(target_arch = "wasm32"))]`. Stateless relay
  admission capability: relay MAC (no nonce table) + client EIP-712 signature
  binding `origin/account/batch/cap` (`TTL = 300 s`). Verify `origin` against
  configured hostnames, never the `Host` header.
- `src/ratelimit.rs` — ungated. Per-peer outbound dial GCRA pacer (see
  "Transport"). Parks instead of refusing; `reserve_bounded` still returns
  `DialTooSoon` past budget so the chunk fails over.
- `src/cache.rs` — `ChunkCache = Arc<RwLock<HashMap<…>>>`, clone-cheap,
  mirrors bee's uploadstore. In-memory and unbounded (~4 KiB/entry) — no
  disk, no LRU.
- `src/cid.rs` — ref32 → CIDv1 (`b` + base32-nopad over the
  `0x01/0xfa/0x1b` prefix) for `bzz.limo` / ENS `contenthash`. CID path only.
- `src/mime.rs` — `mime_guess` wrapper for collection-manifest
  `Content-Type` (appends `charset=utf-8` to text JS/JSON/XML; `None` lets
  the gateway fall back to `application/octet-stream`).
- `src/erasure/` — **Reed–Solomon erasure coding, both directions**
  (shipped in `v0.1.11`). Since ~bee v2.8.1 gateway uploads are RS erasure
  coded by default, so a fresh upload's data chunks can be unretrievable
  for a forwarding-dependent light client while parity chunks let the file
  be reconstructed (ethersphere/bee #5541). `reedsolomon.rs` is a byte-exact
  port of klauspost's default matrix + GF(2^8) encode/reconstruct
  (golden-vector tested); `mod.rs` has the bee span/level decode, per-level
  erasure tables, and `ReferenceCount`/`ChunkAddresses` helpers.
  - **Download** — `joiner.rs` is a bee-compatible tree-walking joiner that
    fetches each intermediate node's data children and RS-reconstructs any that
    time out from the node's parity siblings. `client::join_target` detects a
    level-encoded root span and routes to it, else falls back to nectar's plain
    `GenericJoiner`. All download entry points (CLI/daemon/wasm) funnel through
    it.
  - **Upload** — `encoder.rs` is a port of bee's `hashtrie` writer +
    `redundancy.Params`: it emits the parity chunks and the level-encoded
    intermediate nodes, so a hoverfly upload is byte-identical to a bee gateway
    upload at the same level — same reference *and* same chunk set. Verified:
    it reproduces the bee#5541 reference
    `f9af765e…d1a478` (mfsbsd-mini-14.2 ISO, 40,491,008 B) exactly, and matches
    bee's own `hashtrie.TestRedundancy` expectations for the carrier-chunk case.
    Every upload path splits through `client::split_chunks`; `Level::None`
    delegates to nectar and is unit-tested to be chunk-for-chunk identical.
    **The default is MEDIUM**, matching bee's `DefaultUploadLevel` — so the
    same bytes yield a *different* reference than a pre-erasure hoverfly (the
    level rides in the root chunk's span). `--redundancy none` restores it.
  - **Dispersed root replicas** — `replicas.rs` ports bee `pkg/replicas`. The
    root is the one chunk no parity covers (it has no parent), so bee also
    stores it as `GetReplicaCount(level)` single-owner chunks — 0/2/4/8/16 —
    under the fixed public owner `dc5b2084…` (the address of private key
    `0x01`+31 zeros), with `id = root_addr` but `id[0]` set to a *mined* byte,
    so any retriever can derive the addresses from the root reference alone.
    Dispersal is a search, not a count: candidate bytes are tried in order and
    kept only when the resulting address falls in a neighbourhood (top `d` bits,
    d = 1..4) no earlier replica occupies, claimed at the **coarsest** free
    depth. Emitted for every non-NONE level, including objects too small to
    carry parity (a one-chunk file at MEDIUM = 1 chunk + 2 replicas). nectar's
    `SingleOwnerChunk::new_dispersed_replica` does the SOC construction and
    signing; only the selection is ported here. Differential-tested against
    `cmd/ecref -replicas` over 5 roots × 4 levels.
    **Read side** (`recover_root`) is wired into `client::join_target` and, like
    bee, applies to the root *only* — it is the only chunk that has replicas.
    Two things differ from bee deliberately: (1) it is a **fallback**, run after
    the direct root fetch fails, where bee races replicas alongside every root
    fetch on a 300 ms timer — extra concurrent chunk requests are exactly what
    the `joiner_concurrency` work showed we cannot afford here; (2) a replica is
    accepted only if the chunk it wraps BMT-hashes to the root, because the
    replica key is **public** and anyone can sign a valid SOC at a replica
    address wrapping arbitrary content (bee's getter does not re-check this).
    The download level is unknowable before you hold the root, so the search
    assumes PARANOID; `narrower_levels_are_prefixes_of_wider_ones` verifies (64
    roots) that a narrower upload's replicas are exactly the first entries of
    the wider search, so they come up in the first batch.
  - **Gotcha — parity chunks are not nectar chunks.** A parity shard's first
    eight bytes are RS output over the data shards' *spans*, not a length, so
    nectar's `ContentChunk` (which enforces `span == data.len()` below the body
    size) rejects ~5% of them. Both directions therefore hash and carry raw wire
    bytes: `erasure::wire_address` for addressing, `erasure::WireGet` (impl'd by
    `NetworkedStore`) for retrieval. `NetworkedStore` caches wire bytes and
    validates deliveries by BMT hash; `ChunkGet` is a parsing façade over that.
    Before this, retrieval silently dropped those parity chunks as "address
    mismatch" — losing exactly the parity the joiner needs.
- `src/pushsched.rs` — **sans-I/O multi-lane push scheduler** (relay lanes,
  docs/pusher-design.md §7). No clock, no network, no env: the caller passes
  `now_ms`, does the HTTP, feeds acks back — so the native CLI (reqwest) and
  the browser (wasm `UploadSession` + `fetch`) run the *same* scheduler, and
  lane pathologies are tested against mock lanes on a virtual clock
  (`pushsched/tests.rs`) instead of against real free-tier relays. Weighted
  rendezvous hashing (`w / -ln u`) for assignment — weight = observed rate ×
  budget headroom × concurrency; rank #2 is the deterministic hedge target.
  Lane health is `Warming → Live → Backoff(exp) → Retired` with half-open
  probes, because free-tier relays cold-start rather than die. Proximity
  routing is present but **off** (`proximity_alpha = 0`): measured against
  production overlays it starved two of four lanes, and the receipt-`po`
  histogram shows relay-overlay proximity doesn't change how deep chunks land.
  `CompletionPolicy::Group` is the seam for erasure-coded upload — a codeword
  completes at `need` acks, the same rule `erasure::joiner` uses on read.
- `src/signer.rs` — `SwarmSigner`: overlay derivation, handshake signing
  (v14 + cached v15), eth-address recovery. See "Bee 2.8.0 protocol support".
- `src/wasm.rs` — `wasm-bindgen` façade (`HoverflyClient`): `start`/`stop`,
  peer load/merge/export, `prewarmSessions`, `enableChunkStore`,
  `discover`/`fetch`/`fetchManifestPath`/`listManifest`,
  `upload`/`uploadFile`/`uploadCollection` (+ streaming `begin_upload` /
  `begin_collection` for the pusher path), upload progress/diagnostics, and
  feed-hint import/export. WASM-only.
- `src/idb_chunk_store.rs` — persistent IndexedDB-backed L2 chunk cache
  (browser only). Immutable content-addressed chunks survive reloads on top
  of the per-fetch in-memory cache in `client::NetworkedStore`. **Threading
  gotcha:** the threaded (gateway) build polls futures across rayon Web
  Worker threads, and the `indexed-db` handle (`Rc<Database>`) is `!Send` /
  thread-affine — so only the database *name* is process-global; each thread
  lazily opens + caches its own `Database` handle via `thread_local`. Uses
  the `indexed-db` crate specifically because it's the only binding that
  works under wasm-bindgen's multi-threaded futures executor.
- `src/wsws/` — vendored libp2p-websocket-websys, patched so
  `WebSocket.send()` gets a non-shared buffer (the wasm memory is a
  `SharedArrayBuffer` in the atomics build and Chrome rejects shared views).
- `src/doh.rs`, `src/dnsaddr.rs` — DoH client + `/dnsaddr/` resolution and
  the dialability predicate shared with the peer store.
- `src/lib.rs` — public re-exports; canonical view of what's stable API
  (gates: `batch`/`cheques`/`inbound`/`challenge`/`meter`/`payer` are
  `not(wasm)`; `daemon` is `unix`; `bridge` is `not(wasm)+bridge`;
  `inbound_limit`/`ledger`/`metered`/`pusher` are `pusher+not(wasm)`;
  `wasm`/`idb_chunk_store`/`wsws` are wasm-only). Also hosts
  `MAINNET_BOOTNODE`, `DEFAULT_DOH_URL`, `VERSION`.

## Repo conventions

- Upstream is `omnipin/hoverfly` on GitHub. Push targets are explicit —
  check `git remote -v` in your clone and pick the remote you mean (a clone
  may carry extra Radicle / VPS-daemon remotes); there is no shared default.
- Runtime artifacts are gitignored — never commit them: `peers.json`
  (reachability observations, written back on every operation; respect
  existing fields on read), `overlay-nonce` (default `--nonce-file`), and
  `cheques.json` (**money state**: per-peer cumulative payouts — committing
  it publishes who was paid what, and restoring a stale copy re-issues
  cheques the counterparty already banked). Stray `blob*.bin` / `hello.tar`
  at root are local upload-test leftovers.
- **`peers.seed.json`** (committed, ~800 IPs) and **`peers.ws.json`**
  (committed, WS-dialable subset for the browser builds) are IP-diverse
  cold-start seeds harvested from a long-running daemon. CI copies a seed to
  `peers.json` before starting the daemon so a fresh runner doesn't discover
  from scratch. Regenerate via `hoverfly save-peers --socket <sock>` against a
  daemon that's been running a few hours.
- Hard constants worth knowing before tuning (names are stable, lines drift —
  grep before trusting a line number):
  - `transport.rs  MAX_PUSHES_PER_SESSION = 10_000` — defence-in-depth
    safety net; normal rotation is driven by ghost balance, not this.
  - `transport.rs  GHOST_BALANCE_LIMIT_PLUR = 12_000_000` — client-side
    mirror of bee's `ghostBalance` disconnect threshold (~16.875M PLUR on
    bee, with headroom for in-flight pushes). Session retires when crossed.
  - `transport.rs  GHOST_BALANCE_PREWARM_{NUMERATOR,DENOMINATOR} = 1/2`
    — fraction of the limit at which a replacement session is pre-dialed.
  - `transport.rs  REFRESH_RATE_PLUR = 4_500_000`,
    `SAFE_PEER_THRESHOLD_PLUR = REFRESH_RATE_PLUR * 2` — pseudosettle math,
    mirrors bee's `pkg/node/node.go::refreshRate`.
  - `stream_pool/handler.rs  DEFAULT_MAX_CONCURRENT_OUTBOUND_UPGRADES = 64`
    — per-connection concurrent substream-upgrade cap (`--substream-upgrade-cap`).
  - `client.rs  DEFAULT_FETCH_CONCURRENCY = 5`,
    `DEFAULT_DISCOVER_CONCURRENCY = 16`, `DEFAULT_UPLOAD_CONCURRENCY = 8`
    (the only `pub` tuning consts — the rest below are private).
  - `client.rs  CHUNK_PEER_PARALLELISM = 3` — each chunk races up to 3
    proximity-ordered peers (≈2-3× throughput for ≈3× bandwidth).
    `PREEMPT_INTERVAL = 1s` extends/tops-up that race window when the initial
    seed used fewer peers or after an early shallow/error reply — short enough
    to race on per-chunk RTT timescales.
  - `client.rs  DEAD_SKIP_SECS = 15`, `DEAD_STRIKES = 3` — how long to park a
    session entry, and how many rotation-dial failures trigger parking.
  - `client.rs  MAX_CHUNK_RETRIES = 60` with 500ms retry penalty per failed
    dispatch — outer pusher-layer retry budget per chunk (mirrors bee's
    `pusher.DefaultRetryCount` philosophy). Independent of `--max-retries`.
  - `transport.rs  is_connection_dead` deliberately excludes `Timeout` — a
    single slow op shouldn't retire a whole session with many in-flight pushes.
  - `client.rs  SESSION_DIAL_PARALLELISM = 128` — in-flight window while
    filling the session pool (absorbs the high mainnet dial-rejection rate).
- Global CLI flags worth knowing: `--nonce-file` (default `overlay-nonce`),
  `--chequebook` + `--chequebook-chain-id`, `--cheques-file` (default
  `cheques.json`), `--lane-pin` (repeatable relay pin, else TOFU),
  `--buffer-multiplier`, `--substream-upgrade-cap`. Upload: `--redundancy`
  (default `medium`), `--pusher` (repeatable relay URL, bypasses peerlist).
  Daemon: `--pool-size` (default 256), `--discover-rounds` (default 1),
  `--listen` / `--identity` / `--advertise` (inbound experiment).
- Network IDs: `1` = mainnet (default), `10` = testnet/sepolia. Bootnode:
  `/dnsaddr/mainnet.ethswarm.org`. **EVM chain id** is separate from
  network id (it's the `chainID` in the cheque's EIP-712 domain): 100
  for Gnosis / Swarm mainnet, 11155111 for Sepolia. Set via
  `--chequebook-chain-id`.
- **Bee-citizenship features** (May 2026) for long-term kademlia presence
  growth: stable overlay across runs (persist nonce via `--nonce-file`,
  default `overlay-nonce` in CWD; see `signer::from_bytes_with_nonce`),
  outbound hive self-announce on every session connect
  (`protocols::hive::announce_self`, invoked from `transport::do_hive_announce`
  after the bee handshake), inbound status responder (`protocols::status`).
  Slow-burn lever: bees that learn about us via gossip add us to `knownPeers`
  and may dial us back later, growing our kademlia presence beyond a single
  session. A pullsync inbound responder was tried and dropped (constant probe
  noise, no reciprocal benefit — we store no chunks). See PERFORMANCE.md
  "Bee-citizenship".
- **Bee 2.8.0 protocol support** (May 2026). Handshake v15 + hive v2 carry a
  signed `timestamp` + `chequebook_address` in the `BzzAddress`.
  `SwarmSigner::sign_handshake_v15_cached` caches the `(timestamp, signature)`
  pair per `(underlay, chequebook)` so reconnects to the same peer replay an
  **identical** record. Bee 2.8's gossip path rejects updates within
  `MinimumUpdateInterval = 300 s` of the existing record, so re-issuing a
  fresh signature every reconnect would age our addressbook entry out across
  the network. (Bee itself later adopted the same "sign once, reuse until the
  advertised data changes" approach in v2.8.1 — hoverfly already did this by
  construction; nothing to change.) Also added `libp2p::ping::Behaviour`
  because bee 2.8's reacher uses `/ipfs/ping/1.0.0` to verify reachability;
  failed pings mark us private and the kademlia prune loop kicks us. See
  PERFORMANCE.md "Bee 2.8.0 protocol migration".
- **SWAP / chequebook** has grown past issuance-only: peer sessions still
  advertise the beneficiary in a one-shot `/swarm/swap/1.0.0/swap` handshake
  and `try_settle_once` emits a cheque for the PLUR remainder after
  pseudosettle (exchange-rate fallback is abort→pseudosettle-only — no
  hardcoded rate; trust bee's per-stream `exchange`+`deduction` headers),
  but the CLI now also manages the chequebook lifecycle itself
  (`chequebook deploy`/`fund`/`status` on Gnosis via alloy) and banks
  metered-relay cheques (`cashout` reads the relay `ledger.json` — an
  off-box operation). What still doesn't exist: on-chain verification in the
  stamp path (`src/stamp.rs` is signature-shape + owner recovery only, no
  RPC) and cashout of peer-issued cheques. Correct but no measured throughput
  benefit at one-shot upload workloads. See PERFORMANCE.md "SWAP / chequebook".
- **Metered relay (pusher,** `docs/pusher-design.md`,
  `docs/pusher-incentives.md`). Stages: 0 = shadow metering (`/v1/meter`,
  no refusals), 1–2 = challenge + quote + cumulative-cheque settlement
  (`challenge.rs` / `payer.rs` client-side, `metered.rs` / `ledger.rs`
  relay-side, `cashout` to bank). Threat model and attack-vector tests live
  in `tests/attack_vectors.rs`. Billing is always computed from bytes the
  *client* sent, never from relay reports.
- **Diagnostics** (May 2026): `diag::CONN_CLOSED_IO_DETAIL` buckets
  `ConnectionClosed.cause` (empirically ~100% ECONNRESET from bee's kademlia
  bin-prune of non-public peers — mitigate with `daemon + --listen +
  --advertise`); per-stream/per-chunk latency histograms
  (`diag::PUSH_LATENCY_*`, `OPEN_STREAM_*`, `PUSH_OUTCOME_*`,
  `CHUNK_LATENCY_*`) printed at upload end, shaped to match bee's Prometheus
  metrics for direct A/B. See PERFORMANCE.md.
- CLI has split timeouts: `--timeout` (per-operation, default 10 s, applies
  to pushsync / retrieval / pseudosettle substreams) ≠ `--dial-timeout`
  (session open: dial + identify + handshake + pricing, default 3 s). Don't
  conflate them. Bee's internal `pushsync.defaultTTL` is 30 s; setting
  `--timeout` below ~10-15 s on slow links causes spurious timeouts that
  bee then logs as ghost-balance overdraw on our overlay.
- CLI `--max-retries` per chunk: see `client.rs`
  `cap = max_retries.max(1).min(order.len())`. `0` is silently promoted to
  `1`; the value is also capped by the live pool size, so on a small/attrited
  pool the user-supplied number is the upper bound, not the guarantee.

## When changing this code

- After any `transport.rs`, `client.rs`, or trait-bound change, run `cargo
  test` plus both the native build and the wasm check. `Send`-bound
  regressions on wasm are by far the most common breakage (nectar 0.4.0
  `MaybeSend` relaxes this for ChunkGet and the manifest walk gates its
  bound via `MaybeSendWalk`, but other paths like `tokio::spawn` still
  require Send).
- Network behaviour is empirical. If you change defaults or the constants
  above, measure against mainnet with a freshly randomised file (bee
  dedupes by chunk address: identical bytes re-upload in O(stamp) and tell
  you nothing about real throughput).
- The reference Bee implementation lives at
  `~/Coding/forks/bee/pkg/{pushsync,pusher,accounting,node,p2p,bzz,hive,topology,feeds,salud}`.
  When in doubt about protocol semantics — pushsync receipts, accounting,
  pseudosettle wall-second rule, ghostBalance/blocklist windows, the v15
  handshake / v2 hive wire format, feed derivation, kademlia
  saturation/prune behavior — read Bee directly; the upstream docs lag the
  code. Check out the tag running on mainnet
  (`git -C ~/Coding/forks/bee checkout v2.8.1`) when you need exact code.
