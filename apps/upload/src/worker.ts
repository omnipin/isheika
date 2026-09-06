/// <reference lib="webworker" />
//
// hoverfly node Worker.
//
// Owns the wasm HoverflyClient and runs everything off the main thread: wasm
// instantiation, the rayon hashing/stamping pool, libp2p dial churn, the
// background discover/warm loop, and hoverfly's verbose `INFO` tracing. The
// page talks to it over postMessage (see worker-protocol.ts), so none of that
// work can jank the UI — which it badly did when the node ran in the foreground
// (hundreds of wss dials + per-dial console logs on the main thread).

import {
  DEFAULT_BOOTSTRAP, DISCOVER_WAIT_SECS, HOVERFLY_JS, IDB_NAME, IDB_PEERS_KEY,
  IDB_STORE, MAINTENANCE_SECS, NETWORK_ID, PEERS_SEED_BUNDLED, PEERS_SEED_URL,
  PUSHER_URLS, STATUS_POLL_SECS, STATUS_TIMEOUT_MS, UPLOAD_RETRIES, WARM_POOL, usePushers
} from './config.ts'
import type { Req, Res } from './worker-protocol.ts'

declare const self: DedicatedWorkerGlobalScope

interface HoverflyClient {
  start: (bootstrap: string, intervalSecs: number, waitSecs: number, warmPool?: number, skipPrewarm?: boolean) => Promise<number>
  loadPeers: (json: string) => void
  mergePeers: (json: string) => number
  exportPeers: () => string
  peerCount: () => number
  connectedPeerCount?: () => Promise<number>
  uploadProgress?: () => number[]
  uploadDiagnostics?: () => string
  // `redundancy` is the Reed–Solomon level ('none'|'medium'|'strong'|'insane'|'paranoid');
  // omitted means bee's default, 'medium'. See src/erasure/ in the Rust crate.
  uploadFile: (data: Uint8Array, path: string, contentType: string | undefined, batchIdHex: string, depth: number, immutable: boolean, maxRetries: number, redundancy?: string) => Promise<string>
  uploadCollection: (files: Array<{ path: string, data: Uint8Array, contentType?: string }>, indexDocument: string | undefined, errorDocument: string | undefined, batchIdHex: string, depth: number, immutable: boolean, maxRetries: number, redundancy?: string) => Promise<string>
  // Pusher path: windowed streaming — stamp + yield one bundle at a time so
  // memory stays flat for arbitrarily large files (see UploadStream).
  beginUpload?: (data: Uint8Array, path: string, contentType: string | undefined, batchIdHex: string, depth: number, immutable: boolean, raw: boolean, redundancy?: string) => UploadStream
  beginCollection?: (files: Array<{ path: string, data: Uint8Array, contentType?: string }>, indexDocument: string | undefined, errorDocument: string | undefined, batchIdHex: string, depth: number, immutable: boolean, redundancy?: string) => UploadStream
  /** Wrap a stream in the shared multi-lane scheduler (wasm UploadSession). */
  beginSession?: (lanes: number, stream: UploadStream) => UploadSession
}
/** Windowed streaming upload handle (wasm UploadStream). */
interface UploadStream {
  readonly root: string
  readonly chunkCount: number
  /** Stamp + encode the next bundle, or undefined when exhausted. */
  nextBatch: (batchSize: number) => Uint8Array | undefined
}
/** One dispatch the scheduler wants POSTed (wasm PushRequest). */
interface PushRequest {
  readonly lane: number
  readonly batch: number
  readonly body: Uint8Array
  readonly hedge: boolean
}
/**
 * Scheduler-driven multi-lane upload (wasm UploadSession) — the same
 * `pushsched::Scheduler` the native CLI drives. It performs no I/O: JS asks
 * for a dispatch, POSTs it, and reports acks back.
 */
interface UploadSession {
  readonly root: string
  readonly chunkCount: number
  readonly acked: number
  readonly failed: number
  readonly hedges: number
  readonly done: boolean
  /**
   * Feed a lane's /v1/status JSON (pool size, batch_max, budget, overlay).
   * False when the lane was retired instead of scheduled — it enforces
   * payment and this build has no chequebook.
   */
  setLaneStatus: (lane: number, status: unknown) => boolean
  /** Next POST to issue, or undefined if nothing is dispatchable now. */
  nextRequest: (nowMs: number) => PushRequest | undefined
  /** One streamed NDJSON ack. Idempotent per address (hedges rely on this). */
  reportAck: (lane: number, addrHex: string, ok: boolean, nowMs: number) => void
  /** HTTP-level result of a dispatch, after all of its acks. */
  reportBatch: (batch: number, lane: number, acked: number, elapsedMs: number, ok: boolean, nowMs: number) => void
  /** 402/401: pause the lane without charging health or burning retries. */
  reportPaymentRequired?: (batch: number, lane: number, nowMs: number) => void
  /** How long to wait before retrying nextRequest (0 = wait on in-flight). */
  waitMs: (nowMs: number) => number
  /** Non-empty when the run cannot proceed (all lanes gone / attempts spent). */
  stallReason: (nowMs: number) => string | undefined
  laneStats: () => unknown
}
interface HoverflyModule {
  default: (input?: unknown) => Promise<unknown>
  initThreadPool?: (n: number) => Promise<unknown>
  HoverflyClient: new (
    key?: string | null, networkId?: bigint | null, doh?: string | null,
    timeout?: number | null, nonceHex?: string | null
  ) => HoverflyClient
}

const HOVERFLY_URL = new URL(HOVERFLY_JS, self.location.href).href

let client: HoverflyClient | null = null
let startPromise: Promise<void> | null = null

function log (message: string): void { post({ kind: 'log', message }) }
function post (msg: Res, transfer?: Transferable[]): void {
  self.postMessage(msg, transfer ?? [])
}

// ---- peer-store persistence (mirrors the gateway daemon) ----
function idb (): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, 1)
    req.onupgradeneeded = () => req.result.createObjectStore(IDB_STORE)
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}
async function idbGet (key: string): Promise<string | undefined> {
  try {
    const db = await idb()
    return await new Promise((resolve, reject) => {
      const r = db.transaction(IDB_STORE, 'readonly').objectStore(IDB_STORE).get(key)
      r.onsuccess = () => resolve(r.result as string | undefined)
      r.onerror = () => reject(r.error)
    })
  } catch { return undefined }
}
async function idbSet (key: string, value: string): Promise<void> {
  try {
    const db = await idb()
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, 'readwrite')
      tx.objectStore(IDB_STORE).put(value, key)
      tx.oncomplete = () => resolve()
      tx.onerror = () => reject(tx.error)
    })
  } catch { /* best effort */ }
}

/** CDN-first cold-start seed, bundled fallback. Mirrors gateway `loadSeed`. */
async function loadSeed (): Promise<string | undefined> {
  if (PEERS_SEED_URL != null) {
    try {
      const ctrl = new AbortController()
      const t = setTimeout(() => ctrl.abort(), 5_000)
      const resp = await fetch(PEERS_SEED_URL, { signal: ctrl.signal, cache: 'no-store' })
      clearTimeout(t)
      if (resp.ok) { log('Peer seed: loaded fresh from CDN'); return await resp.text() }
      log(`Peer seed: CDN returned ${resp.status} — falling back to bundled copy`)
    } catch { log('Peer seed: CDN fetch failed — falling back to bundled copy') }
  }
  try {
    const resp = await fetch(new URL(PEERS_SEED_BUNDLED, self.location.href).href)
    if (resp.ok) { log('Peer seed: loaded bundled copy'); return await resp.text() }
  } catch { /* offline */ }
  return undefined
}

async function loadModule (): Promise<HoverflyModule> {
  // No crossOriginIsolated check: this build uses the no-shared-memory hoverfly
  // wasm (built threadless by build-wasm.sh — no wasm-bindgen-rayon, plain linear
  // memory), so SharedArrayBuffer / COOP / COEP are NOT required. That's what
  // lets the dApp run on the eth.limo ENS gateway. There is no initThreadPool to
  // call; nectar's parallel splitter (`sync_split`) runs inline on this single
  // worker thread (no rayon pool), which is correct and also sidesteps the
  // wasm `parking_lot` "Parking not supported" panic that a contended pool hit.
  log('Loading hoverfly wasm…')
  const mod = await import(/* @vite-ignore */ HOVERFLY_URL) as HoverflyModule
  await mod.default()
  log('hoverfly wasm ready (single-threaded hashing)')
  return mod
}

/** One-time node bring-up: wasm → client → seed → discover/warm → persist. */
async function start (sessionKeyHex: string): Promise<void> {
  if (startPromise != null) return startPromise
  startPromise = (async () => {
    const mod = await loadModule()
    log('Constructing hoverfly client (session-key signer)…')
    const c = new mod.HoverflyClient(sessionKeyHex, BigInt(NETWORK_ID), undefined, 30, undefined)
    client = c

    // Pusher mode: no in-browser p2p at all. The wasm client exists only to
    // stamp chunks locally (BMT + EIP-191); the relays do the actual pushing
    // over TCP. Skip the whole discover/warm/seed path — the wss-sliver
    // problem it fights simply doesn't apply when we never dial a bee.
    if (usePushers()) {
      log(`Pusher mode: ${PUSHER_URLS.length} relay(s), no in-browser p2p (browser only stamps).`)
      post({ kind: 'status', connected: PUSHER_URLS.length })
      return
    }

    // Load the IndexedDB cache first (peers we actually reached last session),
    // then MERGE the freshly-fetched CDN seed on top. The cache alone goes
    // stale fast: mainnet /ws[s] underlays are AutoTLS SNI hostnames that
    // rotate within ~2-3h, so a cache from a previous session is mostly dead
    // underlays — dialing them spams the browser console with `can't establish
    // a connection` and finds nothing. The CDN seed is re-derived hourly
    // precisely to beat that rotation. `mergePeers` (NOT loadPeers, which
    // REPLACES the store) upserts the seed into the cache: underlays are
    // unioned and the newer reachability wins, so we keep last session's live
    // peers AND gain the fresh underlays. On a true cold start the cache is
    // absent and the seed is the only source.
    const saved = await idbGet(IDB_PEERS_KEY)
    if (saved != null) {
      try { c.loadPeers(saved); log(`Loaded ${c.peerCount()} peers from cache`) } catch (e) { console.warn(e) }
    }
    const seed = await loadSeed()
    if (seed != null) {
      try {
        const before = c.peerCount()
        const total = saved != null ? c.mergePeers(seed) : (c.loadPeers(seed), c.peerCount())
        log(`Merged fresh seed (+${total - before} new, ${total} total)`)
      } catch (e) { console.warn(e) }
    }

    log('Discovering browser-dialable peers…')
    // skipPrewarm=true: this dApp only uploads. The retrieval warm pool `start`
    // would otherwise open is never used by the pushsync upload path, and
    // warming it just doubled cold-start dialing (retrieval sessions + the
    // upload's own pushsync pool), making bring-up far slower than native for
    // no benefit. Discover peers, skip the retrieval warm-up.
    const n = await c.start(DEFAULT_BOOTSTRAP, MAINTENANCE_SECS, DISCOVER_WAIT_SECS, WARM_POOL, true)
    log(`Discovery done: ${n} peers known`)
    await pushStatus()
    try { void idbSet(IDB_PEERS_KEY, c.exportPeers()) } catch { /* ignore */ }
    startStatusPoll()
  })()
  return startPromise
}

let statusTimer: ReturnType<typeof setInterval> | null = null
let lastConnected = -1
async function pushStatus (): Promise<void> {
  const c = client
  if (c?.connectedPeerCount == null) return
  try {
    const n = await c.connectedPeerCount()
    if (n !== lastConnected) { lastConnected = n; post({ kind: 'status', connected: n }) }
  } catch { /* ignore */ }
}
function startStatusPoll (): void {
  if (statusTimer != null) return
  statusTimer = setInterval(() => { void pushStatus() }, STATUS_POLL_SECS * 1000)
}

function requireClient (): HoverflyClient {
  if (client == null) throw new Error('node not started')
  return client
}

/**
 * Run an upload while polling the wasm client's `uploadProgress()` and posting
 * `progress` events, so the UI can render a real per-chunk bar. Emits a final
 * `done === total` frame on completion so the bar reaches 100%. The poll timer
 * is always cleared, even if the upload throws.
 */
async function withProgress<T> (c: HoverflyClient, run: () => Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setInterval> | null = null
  if (c.uploadProgress != null) {
    const poll = (): void => {
      try {
        const [done, total] = c.uploadProgress!()
        if (total > 0) post({ kind: 'progress', done, total })
      } catch { /* ignore */ }
    }
    timer = setInterval(poll, 200)
  }
  try {
    return await run()
  } finally {
    if (timer != null) clearInterval(timer)
    // Dump the transport diagnostic counters so browser throughput can be
    // debugged from real data (push RTT vs open-stream vs retirement churn).
    try {
      const diag = c.uploadDiagnostics?.()
      if (diag != null && diag.length > 0) log(`diag: ${diag}`)
    } catch { /* ignore */ }
    // Final snapshot so the bar snaps to 100% rather than stopping at the last
    // poll (which may lag a few hundred chunks behind completion).
    try {
      const [done, total] = c.uploadProgress?.() ?? [0, 0]
      if (total > 0) post({ kind: 'progress', done: Math.max(done, total), total })
    } catch { /* ignore */ }
  }
}

// ---- pusher relay path (windowed streaming: stamp local, POST frames) ----
//
// Routing, failover, hedging and lane health all live in the wasm
// `UploadSession` — the same `pushsched::Scheduler` the native CLI drives.
// This file owns only what JS must: `fetch` and the clock. The browser used
// to carry its own round-robin scheduler with whole-bundle failover, which
// re-pushed chunks a relay had already acked and drifted from the Rust one.

/** One relay's `/v1/status`, best-effort: a sleeping free-tier instance just
 *  keeps its default priors instead of degrading routing for every lane. */
async function fetchLaneStatus (baseUrl: string): Promise<unknown | undefined> {
  try {
    const ctl = new AbortController()
    const t = setTimeout(() => { ctl.abort() }, STATUS_TIMEOUT_MS)
    const resp = await fetch(`${baseUrl.replace(/\/+$/, '')}/v1/status`, { signal: ctl.signal })
    clearTimeout(t)
    if (!resp.ok) return undefined
    return await resp.json()
  } catch { return undefined }
}

/** POST one dispatch, feeding each streamed NDJSON ack straight back into the
 *  session so the scheduler can retire chunks (and hedges) as they land. */
async function postDispatch (
  session: UploadSession, lane: number, pushUrl: string, body: Uint8Array, batch: number,
  onAck: () => void
): Promise<void> {
  const t0 = Date.now()
  let acked = 0
  let ok = false
  let loggedErr = false
  const handle = (line: string): void => {
    if (line.length === 0) return
    try {
      const v = JSON.parse(line) as { a?: string, s?: string, e?: string }
      if (v.a == null) return
      const good = v.s === 'ok'
      if (!good && v.e != null && !loggedErr) {
        // One sample per dispatch: a batch can carry hundreds of chunks and
        // they nearly always fail for the same reason.
        loggedErr = true
        log(`Pusher ${pushUrl} rejected a chunk: ${v.e}`)
      }
      // Report *before* signalling progress: `Scheduler::on_ack` is idempotent
      // by address, so `session.acked` is the deduped truth, and progress is
      // derived from it below.
      session.reportAck(lane, v.a, good, Date.now())
      if (good) {
        acked++
        onAck()
      }
    } catch { /* skip non-JSON */ }
  }
  let paymentRequired = false
  try {
    const resp = await fetch(pushUrl, {
      method: 'POST',
      body: body as BodyInit,
      headers: { 'content-type': 'application/octet-stream' }
    })
    if (!resp.ok) {
      const t = (await resp.text().catch(() => '')).slice(0, 300)
      log(`Pusher ${pushUrl} → HTTP ${resp.status}: ${t}`)
      // A 402 is a bill and a 401 a stale capability — neither is a fault.
      // Pause the lane (no health charge, no retry burn); hard lanes are
      // retired upfront, so this is the mid-run soft→hard flip path.
      if (resp.status === 402 || resp.status === 401) paymentRequired = true
    } else {
      ok = true
      const reader = resp.body?.getReader()
      if (reader != null) {
        const dec = new TextDecoder()
        let buf = ''
        for (;;) {
          const { done, value } = await reader.read()
          if (done) break
          buf += dec.decode(value, { stream: true })
          let nl: number
          while ((nl = buf.indexOf('\n')) >= 0) { handle(buf.slice(0, nl)); buf = buf.slice(nl + 1) }
        }
        handle(buf)
      } else {
        for (const line of (await resp.text()).split('\n')) handle(line)
      }
    }
  } catch (e) {
    log(`Pusher ${pushUrl} fetch failed: ${e instanceof Error ? e.message : String(e)}`)
  }
  // `ok` is the HTTP-level verdict; per-chunk outcomes were already reported.
  // 402/401 pauses via the dedicated path so chunks keep their attempts.
  if (paymentRequired && session.reportPaymentRequired != null) {
    session.reportPaymentRequired(batch, lane, Date.now())
  } else {
    session.reportBatch(batch, lane, acked, Date.now() - t0, ok && !paymentRequired, Date.now())
  }
}

/**
 * Drive an `UploadSession` to completion: pull dispatches, POST them, feed
 * results back. Stamping the next window happens inside `nextRequest`, so it
 * overlaps the network push of earlier ones and memory stays flat.
 */
async function pushSession (session: UploadSession, lanes: string[]): Promise<string> {
  const total = session.chunkCount
  log(`Streaming ${total} chunks across ${lanes.length} relay lane(s)…`)

  // Warm the scheduler with each lane's advertisement (pool size, batch_max,
  // budget) before the first dispatch, so weights start from measurements
  // rather than priors. Lanes that don't answer are simply left on defaults.
  //
  // `setLaneStatus` returns false for a lane it retired rather than
  // scheduled — a relay that *enforces* payment, which this build cannot
  // make (the chequebook lives in the native client; the browser only
  // stamps). Paying is optional across the fleet, so free, soft-metered and
  // hard lanes can all sit in PUSHER_URLS and each client uses the subset it
  // can actually be served by.
  let usable = 0
  await Promise.all(lanes.map(async (u, i) => {
    const st = await fetchLaneStatus(u)
    if (st === undefined) { usable++; return } // asleep, not refusing — keep it
    if (session.setLaneStatus(i, st)) usable++
    else log(`Pusher ${u} requires payment; skipping it (browser uploads are unpaid).`)
  }))
  if (usable === 0) {
    throw new Error('every relay in PUSHER_URLS requires payment — the browser cannot pay')
  }

  const pushUrls = lanes.map(u => `${u.replace(/\/+$/, '')}/v1/push`)
  let lastPost = 0
  const onAck = (): void => {
    // Must come from `session.acked`, not a local counter incremented per
    // `"ok"` line. The scheduler hedges stragglers onto a second lane, so one
    // chunk can be acked twice on the wire; `on_ack` dedupes by address but a
    // wire-line counter does not. Counting lines made the bar read 100% (via
    // the `Math.min` clamp) while chunks were still genuinely outstanding —
    // i.e. "1755/1755" with no root, which is precisely the stuck-tail case.
    const done = session.acked
    const now = Date.now()
    if (now - lastPost >= 150 || done >= total) {
      lastPost = now
      post({ kind: 'progress', done: Math.min(done, total), total })
    }
  }

  const inflight = new Set<Promise<void>>()
  for (;;) {
    if (session.done) break
    const req = session.nextRequest(Date.now())
    if (req != null) {
      const p = postDispatch(session, req.lane, pushUrls[req.lane], req.body, req.batch, onAck)
      inflight.add(p)
      void p.finally(() => inflight.delete(p))
      continue
    }
    if (inflight.size > 0) {
      // Something is on the wire; wake on whichever finishes first, but no
      // later than the next hedge deadline the scheduler is waiting on.
      const wait = session.waitMs(Date.now())
      await (wait > 0
        ? Promise.race([...inflight, new Promise(r => setTimeout(r, wait))])
        : Promise.race(inflight))
      continue
    }
    const stall = session.stallReason(Date.now())
    if (stall != null) {
      throw new Error(`push stalled (${stall}): ${session.acked}/${total} acked — ${JSON.stringify(session.laneStats())}`)
    }
    const wait = session.waitMs(Date.now())
    if (wait <= 0) break
    // Every lane is backing off; sleep exactly until the earliest is due.
    await new Promise(r => setTimeout(r, wait))
  }
  await Promise.all(inflight)

  if (session.acked < total) {
    throw new Error(`${total - session.acked} of ${total} chunks unacked — ${JSON.stringify(session.laneStats())}`)
  }
  if (session.hedges > 0) log(`Hedged ${session.hedges} straggler(s) onto a second lane.`)
  post({ kind: 'progress', done: total, total })
  return session.root
}

self.onmessage = async (e: MessageEvent<Req>) => {
  const msg = e.data
  try {
    switch (msg.kind) {
      case 'start':
        await start(msg.sessionKeyHex)
        post({ kind: 'result', id: msg.id, ok: true, value: null })
        break
      case 'connected': {
        let n = 0
        try { n = (await requireClient().connectedPeerCount?.()) ?? 0 } catch { /* 0 */ }
        post({ kind: 'result', id: msg.id, ok: true, value: n })
        break
      }
      case 'uploadFile': {
        const c = requireClient()
        let root: string
        if (usePushers()) {
          if (c.beginUpload == null || c.beginSession == null) throw new Error('wasm build lacks beginUpload/beginSession (rebuild)')
          const stream = c.beginUpload(
            new Uint8Array(msg.data), msg.path, msg.contentType, msg.batchIdHex, msg.depth, msg.immutable, false
          )
          root = await pushSession(c.beginSession(PUSHER_URLS.length, stream), PUSHER_URLS)
        } else {
          root = await withProgress(c, async () => await c.uploadFile(
            new Uint8Array(msg.data), msg.path, msg.contentType, msg.batchIdHex, msg.depth, msg.immutable, UPLOAD_RETRIES
          ))
          await pushStatus()
        }
        post({ kind: 'result', id: msg.id, ok: true, value: root })
        break
      }
      case 'uploadCollection': {
        const c = requireClient()
        const files = msg.files.map(f => ({ path: f.path, data: new Uint8Array(f.data), contentType: f.contentType }))
        let root: string
        if (usePushers()) {
          if (c.beginCollection == null || c.beginSession == null) throw new Error('wasm build lacks beginCollection/beginSession (rebuild)')
          const stream = c.beginCollection(
            files, msg.indexDocument, msg.errorDocument, msg.batchIdHex, msg.depth, msg.immutable
          )
          root = await pushSession(c.beginSession(PUSHER_URLS.length, stream), PUSHER_URLS)
        } else {
          root = await withProgress(c, async () => await c.uploadCollection(
            files, msg.indexDocument, msg.errorDocument, msg.batchIdHex, msg.depth, msg.immutable, UPLOAD_RETRIES
          ))
          await pushStatus()
        }
        post({ kind: 'result', id: msg.id, ok: true, value: root })
        break
      }
    }
  } catch (err) {
    post({ kind: 'result', id: (msg as { id: number }).id, ok: false, error: err instanceof Error ? err.message : String(err) })
  }
}
