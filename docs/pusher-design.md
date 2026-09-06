# Pusher: chunk-push relays on free compute

Status: **stages A+B implemented and deployed** (`src/pusher.rs`,
`src/pushframe.rs`, `client::push_via_pusher(s)`, the dApp relay path in
`apps/upload/`); stage C is partially there (client-side address-sharding with
failover exists; weighted rendezvous + budget accounting do not). This doc is
the single source of truth for the pusher subsystem; it captures decisions made
during the browser-performance investigation (mid-2026).

## 1. Why

The browser build of hoverfly is structurally capped on push throughput and no
amount of client-side tuning fixes it:

- Browsers can only dial bees exposing **wss AutoTLS** underlays — a sliver of
  mainnet (~7 usable hosts of the 48 that front all ~2,800 bees). Many of those
  underlays are stale or refuse connections.
- Browsers serialize/limit same-IP WebSocket opens (Firefox admission manager
  per resolved IP, global `network.websocket.max-connections=200`; Chrome
  per-IP:port endpoint lock), and mainnet bees cluster behind few IPs.
- Result: pools of 5–25 live sessions, 1–3 chunks/s, retry storms and tail
  stalls — versus 500 KB–1.1 MB/s for the same code natively.

A **pusher** is a small relay that accepts pre-signed chunks over HTTPS and
pushes them into the swarm over real TCP libp2p, restoring native reach to
browser (and constrained-network) clients. Pushers are deliberately shaped to
run on **free serverless/container tiers**, so anyone can host lanes at $0.

What a pusher is *not*:

- **Not a gateway.** It serves no retrieval over HTTP and opens no IPC socket.
  It pushes chunks; it never serves content to the web. (Serving cached chunks
  to *peer bees* over libp2p retrieval — `src/inbound.rs` — is normal protocol
  citizenship and stays as-is.)
- **Not a signer.** Keys never cross the wire. The client does all chunking,
  BMT hashing, and stamp signing locally (dApp session key or native wallet);
  the pusher only ever sees pre-signed material. There is nothing secret on a
  pusher to steal.
- **Not a store.** Its `ChunkCache` is a local dedupe/serving cache, same as
  the daemon's.

## 2. CLI surface

```
hoverfly pusher --listen 0.0.0.0:8550 [flags]        # new subcommand
hoverfly upload --peerlist peers.json …              # one-shot (existing)
hoverfly upload --daemon /tmp/hoverfly.sock …        # via daemon IPC (existing)
hoverfly upload --pusher https://a.example --pusher https://b.example …
                                                     # via pusher lanes (new, repeatable)
```

`pusher` flags (all optional; defaults = open mode, generous):

| Flag | Default | Meaning |
|---|---|---|
| `--push-allow 0xA,0xB` | off | Allowlist mode: recovered stamp signer must be listed. No RPC needed. |
| `--rpc-url` | required unless `--push-allow` | Gnosis RPC for batch-alive checks (cached per batchID). |
| `--push-quota` | off | Per-batch capacity quota: ≤ batch effective volume per TTL (see §6). |
| `--push-challenge` | off | Require a signed nonce per upload session (replay hardening, §6). |
| `--push-max-mbps` | off | Global egress cap — the "worst day" bound on free tiers. |
| `--push-verify-sample N` | 1 (verify all) | Verify 1-in-N stamp signatures (CPU lever for Workers, §9). |
| `--pool-size` | profile default | Sessions toward bees (16 persistent, 5 workerd). |

## 3. Wire protocol: streamable HTTP

One transport, three endpoints. Chosen over WebSocket and WebTransport after
dedicated research — rationale recorded in §4.

### Frame format

A push body is a concatenation of frames:

```
addr(32) | stamp(113) | wire_len(u16 LE) | wire(≤ 4104)
```

- `addr` — chunk address (BMT root of the wire content).
- `stamp` — bee wire stamp, `[batchID:32][index:8][timestamp:8][sig:65]`
  (see `src/stamp.rs`).
- `wire` — span(8) + data(≤4096), exactly what goes into pushsync.

The frame format is transport-agnostic on purpose: WS or WT could later carry
the same frames as additional bindings if a need materializes.

### Endpoints

**`POST /v1/push[?receipts=1]`** — body = frames, `Content-Type:
application/x-hoverfly-frames`. Response is **streamed NDJSON**, one line per
chunk as its push resolves (not end-of-batch):

```json
{"a":"<hex addr>","s":"ok","po":5,"ms":812}
{"a":"<hex addr>","s":"ok","po":0,"ms":0}          // recent-ack cache hit, not re-pushed
{"a":"<hex addr>","s":"ok","po":0,"shallow":true}  // forwarded, no neighborhood storer
{"a":"<hex addr>","s":"err","e":"overdraft"}
{"done":{"pushed":254,"total":256,"dedup":3}}      // terminator
```

`po` is the proximity order of the peer whose receipt was accepted — how deep
into its own neighborhood the chunk actually landed — and `ms` its push
latency. Together they are the receipt-quality signal the client scheduler
needs to decide whether routing choices matter at all (§7); without them that
question can only be guessed at.

Client sends ~`batch_max` chunks per POST with 2–4 POSTs in flight per lane.
Retry = re-POST unacked frames; the protocol is connectionless, nothing to
resume.

**`GET /v1/status`** — JSON advertisement the client scheduler consumes:

```json
{
  "version": "…",
  "profile": "persistent | request-scoped | workerd",
  "batch_max": 512,
  "inflight_max": 8,              // derived from pool occupancy
  "budget_remaining_gb": 61.4,    // HOVERFLY_PUSH_BUDGET_GB minus pushed (null = unmetered)
  "overlay": "0x…",               // Kademlia overlay
  "pool": {"live": 128, "target": 128},
  "peers_known": 2819
}
```

**`GET /v1/challenge`** — only when `--push-challenge`: returns a nonce; the
client signs `(nonce ‖ batchID)` with the same session key that signs stamps
and presents it as a header on subsequent POSTs.

### HTTP hygiene (table stakes)

Body-size cap (`batch_max × 4249` + slack), per-request timeout, connection
limits, `429` with `Retry-After` when saturated or quota-drained.

## 4. Transport decision record

**Streamable HTTP (batched POST up, incrementally-flushed NDJSON down) is the
sole v1 transport.** The same pattern MCP standardized. Why the alternatives
lost (research as of mid-2026):

**WebTransport — ruled out for v1:**
- Baseline "newly available" only since Safari 26.4 (March 2026); installed
  base ≈ 75%, "widely available" not until ~late 2028.
- Firefox `serverCertificateHashes` broken (bug 1873263) → no certless WT.
- QUIC is UDP/443; corporate/hotel networks silently drop it → an HTTP
  fallback is mandatory anyway, so WT-only was never on the table.
- Cloudflare can neither run WT in workerd (workerd#6451: no QUIC stack, "not
  on the roadmap") nor even proxy WT to origins — the very edge that was
  supposed to guarantee modern transport can't carry it.

**WebSocket — examined, rejected:**
- Duplex is wasted: downstream is only acks, and a streamed POST response
  delivers those live per chunk.
- Browsers speak WS over HTTP/1.1 in practice (RFC 8441/9220 support patchy) →
  forfeits the H3 edge leg; CF proxy idle timeout (~100 s) forces
  ping/keepalive/reconnect state machines the protocol doesn't need.
- Stateless per-frame stamp auth means there is no session worth keeping
  alive. AWS API Gateway WS (128 KB messages, per-message billing) is the
  wrong shape for MB/s bulk push.

**The HTTP/3 story:** put any pusher behind plain orange-cloud Cloudflare DNS
and the browser→edge leg of every POST rides H3/QUIC automatically — 0-RTT, no
head-of-line blocking — with zero protocol work. Parallel POSTs sidestep
single-connection HoL on the fallback path too. And the whole thing is
curl-able (`curl --no-buffer`) and survives every proxy that mangles WS
upgrades.

## 5. Auth: the stamps are the credential

No bearer tokens. Every stamp is a secp256k1 signature over
`keccak(addr ‖ batchID ‖ index ‖ ts)` by the **batch owner key**, and the
pusher parses stamps anyway — `ecrecover` yields the pusher's notion of
identity for free (~80 µs/chunk native).

**Default (open mode): "the batch is alive" is the auth.** Stamp signature
must recover to the on-chain owner of its `batchID` (that *is* stamp validity
— a stamp can't be detached and reused on a different chunk, the address is
under the signature), and the batch must be alive (`remainingBalance > 0`).
One cached Gnosis RPC call per new batchID.

**Optional hardening, all mechanism-ready but off by default:**

- `--push-allow` — allowlist of signer addresses; zero-RPC private pusher.
- `--push-quota` — per-batch capacity quota (§6).
- `--push-challenge` — proof-of-liveness nonce (§6).

Multi-pusher benefit: N pushers authenticate the same client statelessly from
the same signatures — no token distribution, no shared config.

## 6. Threat model (open mode)

| Threat | Reality | Mitigation |
|---|---|---|
| **Quota drain via dust batch** | A funded batch does **not** bound bytes: a ~$0.02 mutable batch signs unlimited stamps, so batch-alive-only prices *identity*, not *traffic*. | Accepted for free tiers: worst case = the platform's free egress for the month (~70–100 GB) burned, $0 lost. The escalation knob exists: `--push-quota` caps each batch at its **own effective volume per TTL** (depth 18 ≈ 6.5 MB, depth 20 ≈ 670 MB) — the pusher's pricing becomes Swarm's pricing. **Do not run batch-alive-only on metered/paid deployments.** |
| **Stamp replay (quota-griefing)** | Stamps are public; anyone who saw your chunks holds valid `(addr, stamp, wire)` triples. | Re-pushing known chunks is idempotent; `ChunkCache` dedupe answers `dup` for free. If quotas are on, `--push-challenge`: replayers can't sign a fresh nonce with the session key. |
| **Garbage (invalid stamps/wires)** | Costs pusher CPU + egress; bees reject invalid stamps, so push credit is never burned. | Validate before push: BMT-recompute addr from wire + stamp sig + batch alive (~20 ms/MB native). `--push-verify-sample` trades CPU for egress waste where CPU is the binding constraint (Workers). |
| **Content liability** | The pusher originates chunk bytes toward the swarm from its IP — Tor-exit-class residual risk; no cryptography removes it. | Attribution converts "anonymous abuse from your IP" into "abuse attributable to a chain address with a BZZ funding trail": log `(owner, addr, time)` (JSONL), keep an owner blocklist. Push ≠ serve (mere-conduit posture); run on cloud IPs, not home IPs. |
| **Bee-credit exhaustion / blocklist** | Attacker saturating the pusher could overdraw its peers. | Already handled by the shared push path (payment-threshold mirroring, ghost-balance session retirement — same code as native uploads). Bound the blast radius with `--push-max-mbps`. |
| **Targeted amplification** | Chunk addresses are minable → aim traffic at one operator's neighborhood. | Amplification is only ~1–2× at race=1 and capped by the egress budget/quotas. |

Recommended postures: **free-tier public pusher** = defaults (batch-alive
only) + `--push-max-mbps`; **paid/metered pusher** = `--push-quota
--push-challenge`; **private pusher** = `--push-allow`, no RPC at all.

## 7. Client scheduler: lanes + weighted rendezvous — **implemented**

One scheduler, `src/pushsched.rs`, sans-I/O: no clock, no network, no
environment reads. The caller supplies `now_ms`, performs the HTTP and feeds
results back. The native CLI drives it over reqwest/tokio; the browser drives
the *same* code through the wasm `UploadSession` and `fetch`. Before this
there were two schedulers — a decent one in Rust that only the CLI used, and a
round-robin one in the dApp worker that the actual users hit — and they had
already drifted.

### What the first cut got wrong

Stage C originally routed each chunk to `argmax po(chunk_addr, lane_overlay)`.
Measured against the four production relay overlays (read from `/v1/status`,
20 k random addresses):

| lane | overlay | share |
|---|---|---|
| render-1 | `0xdf3d…` | 0.8 % |
| render-2 | `0xdd74…` | 0.2 % |
| render-3 | `0xddc9…` | 49.0 % |
| hf-space | `0x2bba…` | 50.0 % |

Two independent causes:

- **Proximity-argmax is not a load balancer.** Its cells are Voronoi regions
  in Kademlia space, so their sizes depend entirely on how the overlays happen
  to cluster — and three of the four relays share a 6-bit prefix (pairwise PO
  6, 6, 8).
- **Ties went to the highest lane index.** PO ties are the common case (two
  lanes agree at PO 1 half the time) and `Iterator::max_by_key` returns the
  *last* maximum.

Load only balanced because a work-stealing layer drained the backed-up lanes —
which discarded the routing decision anyway. The proximity machinery cost
balance and bought nothing. Both facts are now regression tests
(`distribution_is_uniform_on_clustered_production_overlays`,
`proximity_argmax_would_be_pathological`).

### Assignment — weighted rendezvous hashing

Score every eligible lane with `w_l / -ln(u(addr ‖ lane_id))` and take the
max, `u` uniform from a splitmix64 hash. This gives, by construction:

- **Weight-proportional load** — chunk addresses are hash-uniform, so load
  follows weights exactly.
- **Sticky by address** — retries can't double-spend quota across platforms;
  the lane's recent-ack cache dedupes repeats.
- **Minimal disruption** — a lane's weight changing (or the lane dropping out)
  moves only that lane's share; everyone else's assignment is untouched.
- **Deterministic rank #2** — a chunk's designated hedge/failover lane.

Assignment is **lazy**: a chunk is bound to a lane at dispatch time, not at
admission. A lane going bad mid-run therefore reroutes everything still
pending with no work-stealing layer at all.

**Weights** = `rate × budget × concurrency`:

- `rate` — EWMA of observed acked-chunks per second. Samples below 16 chunks
  are ignored: rate is `acked / elapsed`, which is meaningless for a handful
  of chunks (a 4-chunk batch answered in 10 ms reads as 400/s — measured on a
  two-lane VPS run, an under-fed lane reported 355–516/s against a real rate
  an order of magnitude lower). Before any measurement the prior is
  `pool_live / 8`, which is exactly what separates a shared-IP free tier
  (pool starves at ~10–35) from a dedicated IP (128+).
- `budget` — sheds load as `budget_remaining_gb` approaches zero, instead of
  waiting for a metered lane to start erroring.
- `concurrency` — the lane's `inflight_max`. Two lanes that answer a batch
  equally fast are not equal if one accepts 8 concurrent POSTs and the other 1.

**Proximity is off by default** (`Config::proximity_alpha = 0`, override with
`HOVERFLY_PUSH_PROXIMITY`). It survives only as a bounded weight multiplier,
`w *= 1 + α·min(po,8)/8`. The reason is measurement, not taste — see below.

### Lane health

`Warming → Live → Backoff(exp, capped) → Retired`, replacing the old
"3 consecutive failures ⇒ retired for the whole run". A `Warming` lane gets
one probe batch of 16 in flight, not a full 256 × 8: free-tier relays
cold-start (measured: 0.15 s / 2.15 s / **35.2 s** to answer `/v1/status`
across the three Render lanes) and a sleeping lane must not be able to swallow
a full batch before proving it is awake. Backoff doubles from 2 s to a 120 s
cap, each expiry re-opening half-open; only after 5 doublings is a lane
retired. Verified live by killing a relay mid-upload: the lane failed 3
POSTs, backed off 2 s → 4 s → 8 s, and the run still completed 7901/7901.

### Hedging — race the stragglers, not everything

Modelled on `erasure::joiner::fetch_node_children`, which races every sibling
and cancels the rest the moment enough have landed rather than walking them
one at a time and waiting out each timeout. Here the race is deliberately
*late* and bounded: only chunks that have already blown their lane's own
observed latency budget (`p_batch × 1.5`, clamped 3–60 s), only to their
rank-#2 lane, and only up to `hedge_fraction` (10 %) of the run. First ack
wins; the loser's later ack is ignored (`on_ack` is idempotent per address),
and the relay's recent-ack cache answers the duplicate frame without a second
real push. Measured 0.4–2.4 % of chunks hedged on healthy two-lane runs.

The joiner's *other* stopping rule is here too: `stalled()` reports
`AllLanesDown` / `ChunksExhausted` the moment nothing can proceed, instead of
grinding through the full retry budget waiting out timeouts that cannot
succeed.

### Completion policy — the erasure seam

`CompletionPolicy::Group` lets a set of chunks complete at `need` acks rather
than all of them. That is a Reed–Solomon codeword: `need` = data shards, the
rest parity, the same stopping rule `erasure::joiner` already uses on the read
side (`present >= shard_cnt`). Under it the tail of an upload stops being
blocking — stragglers are repaired by parity at download time rather than
scheduled around. The encoder that produces such groups is separate work; the
scheduler is ready for it and tested (`group_policy_completes_at_threshold`).

### Does proximity routing do anything? — measured, no

`/v1/push` acks now carry `po` (the proximity order of the peer whose receipt
was accepted) and `ms`. The client aggregates them into a receipt-depth
histogram, so the question is answerable rather than arguable.

Two-lane VPS A/B, 8 MiB each, alternating:

| α | mean receipt PO | throughput |
|---|---|---|
| 0 | 3.26 | 530 KiB/s |
| 1 | 2.95 | 545 KiB/s |
| 0 | 3.05 | 589 KiB/s |
| 1 | 3.08 | 447 KiB/s |

No effect beyond noise. The mechanism explains it: a relay pushes to the
closest peer in its **own** multi-thousand-entry peerstore, so its own overlay
barely enters the hop count — pool *coverage* is the real signal, not overlay
position. Proximity stays at α = 0 until a relay advertises its pool's
coverage (and biases its top-ups toward the keyspace arc it receives, below).

### Measured — in the wild

Four production lanes (3 × Render free + 1 × Hugging Face Space, all
shared-egress-IP free tiers), 4 MiB, from a residential client. All three runs
acked 1033/1033 and verified byte-identical back through bzz.limo:

| relays | client | pool | throughput |
|---|---|---|---|
| stage B (v0.1.9) | stage C | 32 | 21.9 KiB/s |
| stage C (v0.1.10) | stage C | 32 | 28.9 KiB/s |
| stage C (v0.1.10) | stage C | **128** | **59.0 KiB/s** |

**2.7× end to end**, roughly half from the scheduler seeing real
advertisements (`pool`, `inflight_max`, `batch_max`) instead of priors, and
half from the pool default the instrument exposed as wrong (§10). Throughput
in absolute terms is still the shared-cloud-IP gate, not the scheduler — the
structural point is that four heterogeneous, rate-limited, cold-starting lanes
complete without a single lost chunk.

The lane split is worth reading: the final run went 92 / 18 / 909 / 14, i.e.
the weight loop concentrated almost everything on the lane that was actually
performing, rather than spreading evenly across four nominally identical
lanes. 104 hedged in every run — the 10 % cap, which is where a run with this
many stragglers is expected to sit.

The first run also exercised the **mixed-version** path: those relays were
still on pre-stage-C builds, advertising no `pool` / `inflight_max` /
`budget_remaining_gb` and emitting no `po`. Every new field is optional at the
type level, so the client just schedules on priors — a stage-C client against
a stage-B relay works (259/259 acked on a single old lane), which means relays
and clients can be rolled out in either order.

### Measured — dedicated IP

Dedicated-IP VPS relay, pool 128, 10 MiB random, all chunks acked:

| configuration | throughput |
|---|---|
| stage B baseline (recorded, 1 lane) | 0.42 MiB/s |
| stage C, 1 lane | 0.58 MiB/s (555 / 624 / 616 KiB/s) |
| stage C, 2 lanes | 0.68 MiB/s (677 / 716 / 685 KiB/s) |
| stage C, 2 lanes, 32 MB | 0.85 MiB/s |

The two-lane split also demonstrates the weight loop: lane 1 (pool 16) started
on a 89 / 11 prior from pool size and settled at 79 / 21 once its measured
throughput came in higher than its pool suggested.

### Where the proximity actually goes — measured, and why pool bias is not the fix

The receipt histogram showed chunks landing at mean PO ~3.1 against a
128-session pool, which looks like an obvious argument for **pusher-side
adaptive pool bias**: under rendezvous each pusher consistently receives the
same pseudo-random ~1/N of the address space, so it could bias pool top-ups
toward bees whose overlays match that arc — less push debt per chunk, longer
session lives, higher sustained throughput.

Before building that, the loss was attributed. Acks carry `bpo` (the best
proximity the dispatcher could reach for that chunk after eligibility
filtering) alongside `po`, and `diag::summary()` reports `pool_po` (the best
proximity anywhere in the pool, ignoring filters). One 10 MiB VPS run,
pool 128:

| stage | mean PO | lost to |
|---|---|---|
| best peer anywhere in the pool | **7.31** | — |
| best peer still *eligible* | **5.43** | −1.9 to dead / in-flight-cap / dial-cooldown filters |
| actually achieved | **3.28** | −2.2 to the deliberate 3-way peer race |

`7.31` is already what theory predicts for 128 uniformly-drawn overlays
(`E[max PO] ≈ log₂ 128`). **The pool's coverage is not the problem** — biasing
it toward the received arc would raise a number that is already good, while
the two downstream losses, which are ~4 bits combined, would remain. Pool bias
is therefore low-leverage and stays deferred.

The two real losses are both defended positions:

- The **race** (`CHUNK_PEER_PARALLELISM = 3`, take the first non-shallow
  receipt) costs depth by construction — the fastest of three peers is not the
  nearest — and buys 2–3× throughput. Not worth trading back.
- The **in-flight cap** is the obvious lever for the filter loss, and it is
  already tuned: a uniform `cap = 8` measured *worse* than `cap = 4`
  (590 vs 665 KiB/s median) because of yamux substream contention per session.
  `inflight_cap()` widens it only for peers whose measured latency says they
  can take it. Raising it for high-PO peers instead would re-enter that
  regression from a different direction.

So the deliverable here is the instrument, not a tuning change: `po` / `bpo` /
`pool_po` make this a three-line attribution instead of an argument, and any
future work on push depth has a baseline to beat.
## 8. Runtime profiles

The insight that makes serverless viable: **the warm pool was never
load-bearing — the peer cache is.** A cold one-shot upload hits ~1.06 MB/s
with a ~2–5 s pool fill from the cache, and the cache is already externalized
state (CI-refreshed `peers.seed.json`, fetchable from GitHub raw/CDN). So a
pusher can be: frames in → fill small pool from CDN cache → push → stream acks
→ die.

| Profile | Where | Shape | Notes |
|---|---|---|---|
| **P0 persistent** | VPS, Render container | `hoverfly pusher` daemon-style: warm pool, maintenance tick | Reference deployment; zero new code beyond the subcommand |
| **P1 request-scoped** | AWS Lambda | Same native binary + thin `lambda_http` streaming adapter (custom runtime); pool per invocation; container reuse gives incidental warm pools between batches | 15-min cap vs ~70 s per big batch — fine |
| **P2 workerd** | CF Workers (later Deno Deploy) | wasm + a **JS-socket transport backend**: one Rust module against an abstract JS TCP-duplex (template: `src/wsws/`), ~50-line shims per platform (`connect()` / `Deno.connect` / `net.Socket`) | 6 sockets/invocation → DO sharding; 3 MB-gzip script limit is tight but passes |

Per-profile tunables (advertised via `/v1/status`, not hardcoded client-side):
batch 256 / pool 128 on P0–P1 (was 16 — see the pool A/B in §10);
batch ~32 / pool ~5 on P2-free.

## 9. Free-tier capacity (planning figures, mid-2026)

Assumptions: egress ≈ payload × amplification (~1.4× at race=1 incl. protocol
overhead/retries; in-pusher racing is off by design); push CPU ≈ 1 core-sec/MB
(measured, VPS); ingress free everywhere.

| Platform | Binding constraint | Payload/mo | Speed | Port effort |
|---|---|---|---|---|
| **Render free** | 100 GB/mo egress | **~70 GB** | 0.1 vCPU → ~0.1–0.2 MB/s lane; 30–60 s cold wake | **zero** (Dockerfile) |
| **AWS Lambda free** | 100 GB/mo egress (compute ≈ 226 GB-worth, never binds) | **~70 GB** | ~1 MB/s **per invocation**; concurrent POSTs = horizontal scale (default 1000-concurrency cap) | low (~a day) |
| **CF Workers free** | 10 ms CPU/req + 100k req/day; egress **unmetered** | **~100 GB-class** (ecrecover ≈ 0.7–1 ms wasm → ~35–40 KB/req; `--push-verify-sample` ≈ 2×) | per-isolate: client concurrency = horizontal scale | medium (the P2 port) |
| **CF Workers $5** | 30M CPU-ms/mo included | **effectively unbounded** (egress stays free) | same | same |
| Deno Deploy | 100 GB/mo egress | ~70 GB | ~50 ms CPU/req class | shares ~90% of P2 |
| Vercel Hobby | 100 GB/mo; **non-commercial ToS** | ~70 GB | Lambda-like | personal only |
| Netlify / Fly.io / Cloud Run | — | — | — | cut (wrapped Lambda w/ worse limits; no free tier; 1 GB/mo egress) |

Aggregate: Render + Lambda + free Worker ≈ **~240 GB/mo of payload for $0**,
summed by the lane scheduler with near-zero duplication.

Numbers to re-verify at implementation time: Render's 0.1-CPU figure, Workers
request math, Deno CPU/req — free tiers drift.

## 10. The standing gate: shared cloud egress IPs

Bees rate-limit inbound per source-/32, and every platform above dials from
shared cloud ranges. **If bees throttle AWS/CF egress ranges, serverless
pushers die regardless of runtime.** Nothing but an experiment answers it:
deploy the current binary to Render (zero code — Dockerfile + `hoverfly
pusher`… or even the existing one-shot upload), push a blob, read the
push-outcome counters. This is the **first task** of the pusher work, not the
last; a bad result reshapes §8–9 before any adapter is written.

## 11. PoC plan

### Platform picks (final)

| Lane | Platform / region | Why |
|---|---|---|
| 1 | **Render free web service** — Docker runtime, **Frankfurt** | P0 persistent reference on free compute; Frankfurt because mainnet bees are Hetzner-dominated (FSN/HEL) → single-digit-ms RTT to most of the swarm |
| 2 | **AWS Lambda** — **eu-central-1**, arm64, Function URL with response streaming, deployed via cargo-lambda | P1 request-scoped; the lane that matters long-term (per-invocation concurrency = horizontal scale) |
| — | CF Workers / Deno Deploy | **not in the PoC** — P2 is a transport port, only worth it after the protocol is proven |
| — | Vercel | cut (non-commercial ToS, nothing over Lambda) |

Lambda memory setting: **1769 MB = exactly 1 vCPU**. Push costs ~1 core-sec/MB,
so smaller settings throttle throughput proportionally (512 MB ≈ 0.29 vCPU ≈
0.3 MB/s). At 1769 MB a 10 MB push ≈ 18 GB-s → the 400k GB-s/mo free compute ≈
226 GB-worth — egress (100 GB) still binds first.

### Reality check that shapes stage A

The crate has **no HTTP server today** (reqwest is client-only; the daemon is
unix-socket IPC), Render free web services must bind `$PORT` and pass health
checks, and Lambda needs an adapter regardless — so a truly zero-code gate
experiment does not exist. The honest minimum is a small HTTP skeleton;
therefore the PoC makes that skeleton the pusher's actual first commit.

### Stage A — pusher skeleton + the gate experiment (~1 day of code)

New `pusher` cargo feature (hyper 1 + hyper-util + http-body-util; native-only,
wasm builds untouched) and the `hoverfly pusher` subcommand serving just:

- `GET /v1/status` — doubles as the platform health check.
- `POST /v1/probe?size=10485760` — **flag-gated (`--probe`), the experiment
  endpoint**: generate a random blob of `size`, stamp it with an env-provided
  throwaway key/batch (`HOVERFLY_PROBE_KEY`, `HOVERFLY_PROBE_BATCH`), run the
  standard push path (`push_chunks_with_pool`, pool from the bundled
  CI-refreshed peer cache), and stream back a JSON report: MiB/s, attempts,
  error histogram (overdraft/shallow/timeout/refused), **per-/32 error
  clustering**, session lifetime distribution.

Probe mode is the one deliberate exception to "not a signer" — it signs with
its *own* env key against a dust batch, exists only for self-testing, and is
off by default. It stays on the finished pusher as a diagnostics endpoint.

Deploy artifacts (in-repo): multi-stage `Dockerfile` (rust builder →
debian-slim + `peers.seed.json`) + `render.yaml` (free plan, Frankfurt, health
check `/v1/status`); `cargo lambda build --arm64` + Function URL (streaming,
auth NONE) for lane 2.

**Experiment protocol:** paired-alternating runs, same hour — 6 × 10 MiB
probes on Render, 6 on Lambda, 6 on the VPS as baseline (same methodology as
the top-up A/B). **Pass:** cloud lane ≥ 0.5 MiB/s AND attempt-error rate ≤ 2×
VPS AND no per-/32 hard-refusal signature (a farm refusing cloud IPs while
serving the VPS). **Partial throttling:** identify which farms, haircut the §9
capacity math. **Hard fail:** serverless lanes are dead → pivot to $2–3/mo
micro-VPS lanes (Fly/Hetzner) and P0-only; §8–9 rewritten.

### Stage A results — measured 2026-07-05 (Render free, Frankfurt, vs VPS)

Ran the probe on Render's free tier against the VPS baseline. Verdict:
**cloud pushing works and is correct; the free-tier throughput ceiling is a
per-/32 dial-rate limit, not a block.** Three findings, in the order they were
untangled:

1. **Raw TCP egress is clean — not Render's firewall, not network-layer IP
   blocking.** A `/v1/tcpcheck` sweep (raw `TcpStream::connect`, no libp2p)
   was byte-identical from Render and the VPS: 20/20 to every live bee port
   and to a VPS-owned listener; the only failures were dead ports that fail
   for everyone. Whatever throttles us is at bee's application layer.

2. **Overlay oversaturation was the dominant throughput killer — premining
   fixes it.** The first Render runs used a *random* overlay (no persisted
   nonce on the ephemeral FS) and cratered at 0.018 MiB/s with `push_shallow`
   ~1524 — bee dropping us from its full bin 0 (`ErrOversaturated`, §"Vanity
   overlay" in PERFORMANCE.md). With an identical premined overlay to the VPS,
   Render jumped to **0.065 MiB/s (VPS-parity) and shallow fell to 24**. This
   is why cloud pushers **must** premine both overlay nonce
   (`HOVERFLY_OVERLAY_NONCE`) and libp2p identity (`HOVERFLY_PUSHER_IDENTITY`,
   separate from the stamp key) — a random overlay per boot is a config bug,
   not a platform limit.

3. **A residual per-/32 dial-rate limit caps single-shared-IP pool size.**
   With overlay controlled, Render still logged thousands of failed dials vs
   the VPS's ~0 to the same hosts — bee's `SubnetRateLimiter` (`libp2p.go`:
   RPS 10, burst 40 per /32; also a 200-conn/​/32 cap) rejecting our burst
   pool-fill. Effect: Render's pool starves at **~8–35 live sessions** vs the
   VPS's **76+**, ceiling-ing high-load throughput at **~0.05 MiB/s (~7×
   below VPS)**. It never breaks correctness — every chunk still pushes — and
   at low load a handful of good-bin sessions carry the work at parity.
   Confirmed as *source-IP*, not our own code: same binary/overlay/peers, VPS
   unaffected. A dedicated IP (VPS) has the full per-/32 budget; a shared
   cloud IP does not.

   **Superseded 2026-07 (stage C rollout).** Re-measured on the same Render
   free plan, the pool now reaches a full **128/128** — the ~8–35 ceiling is
   gone (larger CI peer cache: 2 819 → 3 517 known peers, and the background
   maintenance loop fills gently instead of burst-dialling). The stage-B
   default of `HOVERFLY_PUSH_POOL=32` was therefore leaving most of the lane
   on the table. Single-lane A/B, 2 MiB, same platform and hour:

   | pool | throughput | shallow receipts per chunk | best available PO |
   |---|---|---|---|
   | 32 | 14.2 KiB/s | 8.1 | 3.61 |
   | 128 | **37.0 KiB/s** | **0.44** | 4.70 |

   2.6× throughput and 18× less wasted work. The mechanism is a
   shallow-receipt cascade: a small pool leaves the closest session to a
   chunk far from it, so bee forwards rather than stores, the dispatcher
   takes a shallow receipt and retries against another peer. The default is
   now 128; raising it is safe on a host that really is limited, because
   `top_up` is best-effort and `/v1/status` advertises `pool.live`, so the
   client's scheduler weights a lane by what it achieved rather than what it
   asked for.

**Aggregation (two free pushers, distinct node identities + vanity overlays):**
solo 0.063 + 0.075; concurrent combined **0.094** (vs ~0.07 for one alone).
Aggregation is **real and net-positive (~1.35×) but sublinear** on the same
provider — Render-1 held its full rate while Render-2 halved, consistent with
partial shared-egress-/32 contention (exact IPs uncapturable behind the VPS's
firewalld). The clean *linear* case is already proven by VPS-vs-Render: fully
independent budgets across different IP ranges. **Design consequence:**
multi-pusher scaling is best across **different providers / IP ranges**, and
the client scheduler (§7) should prefer IP-diverse lanes; stacking on one
provider still helps but doesn't scale linearly.

**Net:** Render grade = works, correct, volume-capable (~70 GB/mo egress-bound),
single-IP-throughput-limited (~0.05 MiB/s). Throughput is a client-side
multi-lane concern (§7, stage C), not a single-host property. AWS Lambda's
per-invocation egress-IP diversity (the natural fix) is untested — no account.

### Stage B — the protocol end-to-end (~2–3 days) — **implemented**

- `POST /v1/push`: frame decode → validation (BMT recompute, stamp sig,
  cached batch-alive RPC) → push → streamed NDJSON acks. Open mode only; no
  quota/challenge/allowlist yet.
- `upload --pusher <url>` **single-lane** (no rendezvous yet): frame encoder,
  batched POSTs, ack-driven completion, straggler re-POST to the same lane.
- dApp: pusher URL config + fetch/ReadableStream ack parsing.
- Batch of 256 frames ≈ 1.1 MB — comfortably under Lambda's 6 MB request cap.

**Success metric:** the 71 MB browser video upload sustains **≥ 0.5 MB/s
through the Lambda lane** (vs 1–3 chunks/s direct today) with the key never
leaving the browser.

### Stage C — multi-lane — **implemented**

Weighted rendezvous scheduler (§7), status-weighted lanes, straggler
re-dispatch to rank-#2 lane, `budget_remaining_gb` accounting. Shipped as the
default browser push path.

Delivered beyond the original scope, because the original scope could not have
worked without it:

- **Per-chunk acks.** `/v1/push` used to run the whole batch to completion and
  emit one all-or-nothing verdict, so a single lost chunk re-pushed all 256
  and the client's scheduling unit was really the batch. `push_chunks_with_pool_ex`
  takes a per-chunk hook; the relay streams each ack as it lands.
- **One scheduler, both targets.** `src/pushsched.rs` is sans-I/O and drives
  the CLI *and* the dApp (via the wasm `UploadSession`), replacing the
  browser's separate round-robin implementation.
- **Windowed streaming on native.** `hoverfly upload --pusher` now uses
  `UploadStreamer` like the browser does, so large files no longer stamp
  everything up front.
- **Receipt-depth instrument.** Acks carry `po`/`ms`; the client aggregates a
  histogram. This is what settled the proximity-routing question (§7).
- **Real advertisements.** `budget_remaining_gb`, `pool{live,target}` and
  `inflight_max` are populated rather than `null`, and the client reads
  `batch_max` instead of hardcoding it.
- **Recent-ack cache.** Duplicate frames (hedges, re-POSTs) are answered from
  a TTL'd LRU rather than paying a second real push.

### Deferred / watchlist

- PR-sized follow-ups: `--push-quota`/`--push-challenge` hardening, P2
  workerd port (unlocks Deno Deploy), attribution-log tooling. Note that
  the metered-relay design (§12) subsumes `--push-quota` outright — price
  is a strictly better quota — and promotes `--push-challenge` from
  optional hardening to a correctness requirement.
- Contiguous-arc lane assignment + deep pool specialization — only if receipt
  data shows forwarding depth is a real cost (§7).
- WS/WT bindings of the frame format — only on demonstrated need (§4).
- Edge control plane (Worker doing ecrecover/quota/routing in front of dumb
  push origins) — optional sugar if a public pusher federation ever forms.
- Upstream watch: if bee ever ships WebTransport listeners, browsers could
  dial storage nodes directly and the pusher's raison d'être shrinks to
  constrained networks.

## 12. Incentives — paying for relay

Specified separately in **[`pusher-incentives.md`](./pusher-incentives.md)**
(status: Stages 0–2 shipped — soft + hard enforcement + cashout).

The problem it addresses: a relay absorbs a cost it did not incur. In a
native upload the user's own machine is the peer bee debits for every
chunk; put a relay in the middle and that debt moves wholesale to the
relay, while the browser client that caused the traffic pays only postage.
§6 books this as an accepted risk and §10 identifies the dedicated egress
IP as the thing that is actually scarce.

The design adds an optional **`metered`** relay mode (today's behaviour
becomes `open`, and the four production lanes stay there) in which a
client pays with off-chain SWAP cheques over the existing HTTPS channel.
Both counterparties are hoverfly — bee is not a party, and only the
chequebook contract and EIP-712 cheque format are borrowed, not the swap
protocol. Payment is out-of-band (`POST /v1/pay`), the account is the
batch-owner EOA already established by push auth, and the relay holds only
the beneficiary *address* — never a spendable key.

**The trust model is one-directional, and it drives everything else.**
The asymmetry is **pinning, not curation** (incentives §2): a relay is a
plain HTTP service anyone can run — there is no registry, no discovery, no
federation roster, and `PUSHER_URLS` is one client's default fleet, not a
membership list. A client verifies the signed quote and pins
`(url, node_eth_address, beneficiary)` before sending a byte (or
TOFU-trusts first-seen with a warning via `--lane-pin`); a relay gets
whoever POSTs. So the design protects the *relay* from the *client*, and a
client is protected by its self-computed bill, pinned price, capped
exposure (`max_outstanding`), and measured outcomes — not by removing a
lane from a list. An earlier revision built two-sided verification for
this one-sided relationship and paid for it with a forgeable billing unit
and an unbounded residual; see incentives §2.

Findings from that doc that constrain this one:

- **The billing unit is bytes admitted, not receipts or acks.** The client
  cannot lie about it, because the client produced the bytes and the relay
  counted them — no third-party attestation to forge, no chain state to
  disagree about (incentives §8). This matters here because it settles
  what receipt forwarding is *for*: forwarding `PushsyncReceipt` into the
  ack is still worth doing — `PushInfo` currently drops the signature, so
  acks are pure relay assertion, and it is the first cryptographic signal
  a relay client has ever had — but it is **telemetry that feeds lane
  weighting, not evidence that feeds an invoice**. A receipt signs the
  bare chunk address (`bee/pkg/pushsync/pushsync.go:277`), so it is
  forgeable with any throwaway key and carries no freshness; anything that
  prices work by receipt inherits both problems.
- **`--push-challenge` becomes mandatory under metering.** Swarm stamps
  are public (§6), so an attacker can replay a victim's stamps at a
  metered relay and have the work billed to the victim. The signed payload
  must bind the relay's **origin**, not its beneficiary, and must be an
  EIP-712 typed struct — the same account key already signs stamps and
  cheques, so a third raw-bytes scheme over it invites confusion. And the
  origin the relay compares against must come from **configuration, never
  from the `Host` header** — the header is supplied by the same party
  supplying the challenge, so checking one against the other is a no-op
  that silently reopens the replay (incentives §11.1).
- **"A batch owner is a costly identity" is false as stated.** The relay
  checks batch *liveness*, and the cheapest batch the contract accepts
  costs a fraction of a cent — so any flat per-account credit line is
  roughly self-financing for an attacker. The fix is to scale the credit
  line to the batch's remaining on-chain value rather than gate on it
  (incentives §10.3). Worth knowing here because it is the same mistake
  any future per-batch quota would make.
- **`--push-quota` should be struck** if metered mode ships; price is a
  strictly better quota than a volume cliff.
- **Six live bugs in open-mode code, found during those reviews — all
  fixed** (incentives §16). None depend on metering; they were in
  production the whole time.
  - *Stamp substitution via the recent-ack cache.* Dedup was keyed on
    chunk address alone, so a hit acked a frame `ok` while silently
    discarding the submitted stamp. Since addresses are content-derived,
    one uploader's dust batch could shadow another's year-long batch for
    the 120 s TTL — the victim's chunk then garbage-collected when the
    attacker's batch expires. It also fired accidentally between honest
    users uploading the same file. Now keyed on `(addr, batch_id)`
    (`src/pusher.rs:286`).
  - *Unauthenticated RPC amplification on `/v1/push`.* `resolve_owner`
    cached only successes, unbounded, with no per-request budget, so one
    anonymous POST naming bogus batches became up to 512 serial
    `eth_call`s — and `EthRpc::new` built a fresh HTTP client per read.
    Now a bounded cache with negative caching, TTLs, and an 8-lookup
    budget, over one shared client.
  - *No connection limit.* The accept loop spawned per connection with
    nothing bounding it, despite §3 listing a cap as table stakes. Now a
    256-permit semaphore acquired before `accept()`.
  - *One transient accept error killed the relay.* `accept().await?`
    propagated `EMFILE`/`ECONNABORTED` out of `run`. Now logged, backed
    off, and continued.
  - *No HTTP timeouts.* The comment claiming hyper's defaults sufficed was
    backwards: `header_read_timeout` is inert unless a timer is installed,
    so nothing was enforced. Now a timer plus a 30 s header timeout and a
    120 s body timeout.
  - *Pushsync receipt addresses were never validated* — the one that
    matters here, because §7's whole receipt-forwarding idea rests on it.
    `receipt.address` was neither length-checked (callers
    `copy_from_slice` it into `[u8; 32]`, so a missized address was a
    remote panic) nor compared to the address actually pushed (so a peer
    could store nothing and sign for a different address deep in its own
    neighbourhood, and `is_shallow` would call it a perfect delivery).
    Checked at the protocol boundary now, with regression tests.

### Deferred / watchlist (cont.)

- Contiguous-arc lane assignment + deep pool specialization — only if receipt
  data shows forwarding depth is a real cost (§7).
- WS/WT bindings of the frame format — only on demonstrated need (§4).
- Edge control plane (Worker doing ecrecover/quota/routing in front of dumb
  push origins) — optional sugar if a public pusher federation ever forms.
- Upstream watch: if bee ever ships WebTransport listeners, browsers could
  dial storage nodes directly and the pusher's raison d'être shrinks to
  constrained networks.
