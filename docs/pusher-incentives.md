# Pusher incentives: paying for relay with SWAP cheques

Status: **Stages 0–2 shipped (soft + hard enforcement + cashout).** A relay meters, reports, accepts
cumulative cheques, refuses over-cap accounts with 402 in hard mode, and held cheques are redeemable via
`hoverfly cashout`. Stage 3 (erasure-aware completion policy) is outstanding. See §14 for exactly what is
and is not in. This doc
specifies an
optional *metered* mode for `hoverfly pusher` in which a client pays the
relay for bandwidth with off-chain SWAP cheques. It is a companion to
`docs/pusher-design.md`, which stays the index for the pusher subsystem;
read §§1–7 there first.

The short version: **both counterparties are hoverfly.** A client pays a
relay. Bee is not a party to the payment — we borrow SWAP's *contracts and
cheque format*, not its protocol.

**This is a rewrite.** Three rounds of adversarial review went into the
previous version, and the third round's most important finding was
structural rather than local: the doc was building *two-sided*
cryptographic verification for a *one-sided* trust relationship. A client
**chooses and pins** its relay before sending a byte; a relay gets whoever
POSTs. Roughly half the old document defended the client against the
relay — a party it had already vetted — and it paid for that with a
forgeable billing unit, an unbounded residual, and a ship-blocking
measurement nobody had taken.

This version points every defence in one direction — **the relay is what
gets protected, from the client** — and picks a billing unit the client
cannot lie about. The result is smaller, has no kill criterion, and closes
the attacks that involve actual money. §16 records the live bugs that
review found in open-mode code; they are the durable artifact of the
process and are all fixed.

## 1. Why

Today the relay eats a cost it did not incur.

In a native upload the user's own machine opens the pushsync streams, and
bee debits *it* for every chunk — `price(po) = (32 − po) × 10 000`
accounting units (`bee/pkg/pricer/pricer.go:34-36`, mirrored at
`src/transport.rs:94-97`). Put a relay in the middle and that debt moves
wholesale to the relay: it is the peer bee sees, so it is the peer bee
charges. The browser client that caused the traffic pays nothing but
postage.

`docs/pusher-design.md` §6 currently books this as an accepted risk —
*"worst case = the platform's free egress for the month (~70–100 GB)
burned, $0 lost"* — and §10 identifies the thing that is actually scarce:
a dedicated egress IP with an unthrottled dial budget. Free-tier lanes
starve at a fraction of a dedicated host's throughput, and the only way to
get more of them is for someone to volunteer.

Metering is the answer to both. It puts the cost back on the party that
caused it, converts §6's accepted quota-drain risk into a priced one, and
makes running a dedicated-IP relay a rational act rather than a donation.

Nobody gets rich. §9's economics are thin: at $0.02/GiB and §9.1's 3.7×
egress, a relay saturating a 2 TB/month bandwidth allowance bills about
**$10**. On hardware whose cost is already sunk — a box running other
things, bandwidth already included — that is close to all margin, since
§9.3's gas turns out to be negligible and the *client* funds the
chequebook, not the relay. But the allowance is a ceiling and crossing it
inverts the economics in one step (§9.2), so what this funds is a
self-sustaining lane federation, not a business.

## 2. Trust model — read this before anything else

Every design decision below follows from one asymmetry.

> **The client chose its relay. The relay did not choose its client.**
>
> A client verifies the signed quote and pins
> `(url, node_eth_address, beneficiary)` (§7.3) before it sends a byte. A
> relay is whatever URL it was pointed at, and a client is whoever POSTs.
> Defences point *from* the relay *at* the client. The security goal is:
> **a client cannot obtain relay service without paying for it, and cannot
> lie to the relay about what it owes.**

**The asymmetry is pinning, not curation, and the difference is not
cosmetic.** A relay is a plain HTTP service: there is no registry, no
discovery mechanism, and no list anyone has to be admitted to. Anyone can
run `hoverfly pusher`, and any client can point `--pusher` at any URL.
`PUSHER_URLS` is one client's default fleet — the dApp's — not a
federation roster.

So "relays are known" is only true of a relay a given client has already
chosen. The property the design can actually lean on is that **a client
only ever pays a relay it configured and pinned**, which is a decision it
made with the signed quote in hand.

The inverse — a relay defrauding a client — is still **out of scope for
cryptographic treatment**, but it does not follow that the client is
unprotected. Four bounds hold without the relay being trustworthy:

- **The client computes its own bill** from bytes it sent (§8.4), so an
  over-reported `kib_admitted` is immediately visible and attributable.
- **The price is pinned** from a signed quote and echoed verbatim in every
  402 (§7.3), so it cannot move under the client.
- **Exposure per lane is capped at the credit line** — `max_outstanding`
  at most, and `remaining_value ÷ credit_ratio` for a small batch.
- **Outcomes are measured.** A lane that takes bytes and delivers poorly is
  deweighted by the scheduler's existing EWMA.

The one place a relay's own assertion could exceed that cap is §17.1's
reconcile, where the client adopts the relay's `owed`. It is bounded by
the ceiling in the relay's *signed quote* precisely so that this list stays
true; see `LanePayer::check_reported_debt`.

Three consequences worth stating so they don't get re-litigated:

**No confidentiality is claimed or implied.** The pusher sees plaintext
chunks, the stamp, and the batch-owner address. That is inherent to
relaying, and Swarm is not an anonymity system in the first place — chunks
carry a signed postage stamp, addresses are content-derived and publicly
retrievable, and retrieval hands the stamp back
(`src/protocols/retrieval.rs:27`, `:42-80`). Metering changes none of
this. The one operational consequence: **a relay holds every stamp it has
ever relayed**, which makes it the richest possible source of harvestable
stamps and is an argument for §7.2's origin-bound challenge.

**The client is not asked to verify the relay's work cryptographically.**
It verifies *arithmetic* — it knows exactly how many bytes it sent — and
it measures *outcomes*, which `src/pushsched.rs` already does by
deweighting lanes that underperform. That is the same protection open mode
has today, and open mode works.

**Receipts are telemetry, not evidence.** The relay forwards the pushsync
receipt in the ack because it is genuinely useful — it is the first
cryptographic signal a relay client has ever had about where its chunk
landed, and it feeds lane weighting — but **it does not enter the
invoice.** An earlier draft billed per verified receipt, which required
anchoring each receipt in the staking registry to stop forgery, and still
left a replay hole that no off-chain check could close. §8 explains why
the billing unit moved.

## 3. Scope and non-goals

**In scope:** a client (native CLI first, browser later) pays a
`hoverfly pusher` for relayed bytes, over the existing HTTPS channel,
denominated in BZZ.

Explicit non-goals, each with its reason:

- **Not bee's swap protocol.** No `/swarm/swap/1.0.0/swap` stream, no
  `Handshake`/`EmitCheque` framing, no `exchange`/`deduction` headers, no
  priceoracle. Client and relay already speak HTTP; there is nothing to
  gain from tunnelling a libp2p settlement protocol through it. We reuse
  the *cheque* (§4), not the transport.
- **Not bee's accounting model.** No `paymentTolerance`, no ghost
  balances, no trust ramp, no blocklist state machine. But note §10.2:
  bee's *reservation* concept is mandatory and an early draft wrongly
  dropped it.
- **Not "the relay uses the income to pay bees."** `PERFORMANCE.md`
  measured paid at 160 KiB/s against unpaid at 195 KiB/s ("verdict: not
  confirmed at this workload"), and the arithmetic agrees: bee grants
  4 500 000 accounting units/s per peer via pseudosettle, ≈ 18 chunks/s at
  PO 8, ≈ 2 400 chunks/s across a 128-session pool — against ~150 chunks/s
  actually measured. The relay is session- and RTT-bound, not
  credit-bound, so buying credit buys nothing. Relay→bee settlement stays
  free pseudosettle. (The pusher does not even wire `SwapConfig` today —
  `build_push_state` (`src/pusher.rs:724-772`) never calls `.with_swap`,
  so the global `--chequebook` flag has no effect on a relay.)
- **Not confidentiality, not anonymity.** §2.
- **Not defence against a malicious relay.** §2, §14.
- **Not encrypted uploads.** 64-byte references are unsupported throughout
  (`src/feed.rs:150`; the erasure coder is non-encrypted-path only at
  `src/erasure/mod.rs:145`, `:365`, `:408`) and adding a key-management
  surface is out of proportion to the problem.
- **Not a new contract.** See §13.

## 4. What we borrow from SWAP, and what we drop

| Borrowed | Where it comes from | Why |
|---|---|---|
| `ERC20SimpleSwap` chequebook + canonical factory | `bee/pkg/config/chain.go:89` (Gnosis `0xc2d5a532cf69aa9a1378737d8ccdef884b6e7420`), `chain.go:66` (Sepolia `0x0fF044F6bB4F684a5A149B46D7eC03ea659F98A1`) | Audited, deployed, in production. Nothing to write. |
| EIP-712 cheque | `bee/pkg/settlement/swap/chequebook/cheque.go:32-38` | Domain `{name:"Chequebook", version:"1.0", chainId}` — no `verifyingContract`, no `salt`. Type `Cheque(address chequebook, address beneficiary, uint256 cumulativePayout)`. Already implemented at `src/signer.rs:309-337`. |
| Cumulative-payout monotonicity | `chequestore.go:133-138` (`ErrChequeNotIncreasing`) | Makes cheques loss-tolerant and replay-proof (§8.3). |
| Funding check | `chequestore.go:172-179` (`ErrBouncingCheque`) | But **use `liquidBalanceFor(us)`, not `balance()` — bee's version is unsound**, see §11.6. |
| Reservation against concurrent issuance | `chequebook.go:163-178` (`reserveTotalIssued`) | Needed on both sides. See §10.2. |
| Payee-only role | `bee/pkg/node/node.go:592-625`, `bee/pkg/node/chain.go:206` | The beneficiary is a plain **EOA**, not a chequebook. A payee needs no contract of its own. |
| Cheque JSON encoding | `src/protocols/swap.rs:84-106` (`encode_signed_cheque_json`) | Byte-exact Go `encoding/json` compatibility already solved. |

| Dropped | Reason |
|---|---|
| swap libp2p stream, `Handshake`, `EmitCheque` framing | We're on HTTP. |
| priceoracle, `exchange`, `deduction` | Relay quotes PLUR directly. No oracle dependency, no new-peer ramp. |
| accounting-unit indirection | Prices are PLUR. One unit, no conversion. |
| `ErrChequeValueTooLow` as inherited | Bee's floor is "≥ 1 accounting credit" (`chequestore.go:37-38`), denominated in the oracle indirection we dropped. Our `min_cheque_plur` (§10.1) is a *different* mechanism with a different justification; do not treat bee as precedent for its sizing. |
| ghost/shadow balances, tolerance, trust ramp | No analogue in request/response. |
| `StakeRegistry` / staked-set snapshot | An earlier draft needed this to make forged pushsync receipts expensive. With receipts out of the invoice (§8) there is nothing to anchor, and Stage 1 loses its two largest work items. |

## 5. Relay modes

A relay runs in exactly one of two modes, advertised in `/v1/status`:

- **`open`** — today's behaviour, unmetered. The four free-tier lanes in
  `apps/upload/src/config.ts` keep running this. Auth stays "stamp signer is
  the live batch's on-chain owner" and nothing is billed.
- **`metered`** — every byte admitted is billed (§8). There is no free
  allowance. `pusher.browserbzz.link` is the first production lane running
  it, with hard enforcement.

**Mode is per relay, and paying is optional for the client.** A fleet mixes
freely: the same `PUSHER_URLS` holds four `open` lanes and one hard-metered
one, and each client uses the subset it can be served by. The rule is
symmetric on both sides of the wire:

| relay mode | client has a chequebook | client does not |
| --- | --- | --- |
| `open` | used, nothing billed | used, nothing billed |
| `metered`, soft | used, billed, settles | used, billed, served anyway |
| `metered`, hard | used, billed, settles | **lane retired at startup** |

Retiring is the load-bearing case. A hard lane answers a push without a
challenge header with 401, and a 401 is not a 402 — it counts against lane
health, so scheduling one anyway spends a retry per chunk rediscovering
something the lane advertised in `/v1/status` before the first byte moved.
Both drivers therefore drop it up front: `src/client.rs` (native) when no
`--chequebook` is configured, and `UploadSession::set_lane_status`
(`src/wasm.rs`) unconditionally, since the browser only stamps and the
chequebook lives in the native client. Soft-metered lanes are *kept* by
both — they bill and serve, so an unpaying client is served exactly as on
`open`. A run whose every lane is hard-metered fails immediately with that
reason rather than stalling.

Four further consequences worth stating up front:

**Metering subsumes the deferred `--push-quota`.** Design §6 proposed
capping each batch at its own effective volume per TTL. Under metering the
price *is* the quota, and a better one: it scales continuously instead of
cliff-edging at a volume boundary, and it doesn't require the relay to
model batch TTL semantics. `--push-quota` should be struck from the
watchlist if metered mode ships.

**Metering makes `--push-challenge` mandatory, not optional** — and it
does double duty as the admission mechanism (§7.2, §11.1).

**Metered mode requires durable storage.** Not a recommendation. §11.4
shows that an ephemeral filesystem turns one signature into unlimited free
service. Free-tier hosts with ephemeral disks (Render free, the reference
deployment in design §11) **must** run `open`.

**Metered mode requires a chain RPC.** Open mode already needs one for
batch-owner resolution; metering adds batch-value reads (§10.3) and cheque
verification (§11.6). Only on the relay — the client needs no chain access
to compute its own bill, which is the point of §8.

## 6. Identity: the account is the batch owner, the credit line is the batch

The relay's existing auth already establishes a strong, on-chain identity
for every push (`src/pusher.rs:895-960`): the stamp signature must recover
to the address that the `PostageStamp` contract reports as the batch's
owner, and the batch must be alive. That recovered address is the natural
account key.

> **Account = the batch-owner EOA.** Cheques, the cumulative and the
> settlement ledger are keyed on it.
> **A cheque is valid for that account iff its chequebook's on-chain
> `issuer()` equals the same EOA.**
> **Credit is keyed one level finer, on the *batch*.** Standing (below),
> the credit line (§10.3) and admission (§7.2) are all per batch, because
> one owner can hold many batches of wildly different value and the
> cheapest of them must not buy the credit of the dearest.

This binds payment to identity cryptographically, with no session tokens,
no registration step, and no extra protocol message. It lines up with the
CLI's existing semantics: `--chequebook`'s documented precondition is
already *"`issuer()` == `--key`'s address"* (`src/bin/hoverfly.rs:90-105`),
and `--key` is the stamp key. And in a browser it means the session key —
which already owns the batch — is the chequebook issuer, so cheques sign
with **zero wallet prompts**.

**One *batch* per request.** `run_push` currently re-resolves the owner
whenever a frame's batch id changes (`src/pusher.rs:905-925`), so a single
POST can legally mix batches and owners. Metered mode must forbid this:
standing, the credit line and the reservation are all properties of a
*batch*, not of an owner who may hold many. Every frame in a POST must
carry the exact batch id named in the challenge, and a mismatched frame is
rejected rather than billed to whoever it names. Without this the
admission check in §7.2 is trivially bypassed by prefixing one frame from
a good-standing batch (§11.8).

Tightening account → batch costs nothing and buys three alignments: the
recent-ack cache is already keyed on `(addr, batch_id)` (§16.1), admission
resolves standing once per POST instead of once per frame, and the
reservation has exactly one credit line to check against. A client mixing
batches splits them across POSTs, which the scheduler already pipelines.

**The relay never holds spendable key material.** It needs the
beneficiary's *address* only. `cashChequeBeneficiary(recipient, cumulativePayout, signature)`
must be called *by* the beneficiary (`cashout.go:137`, and
`_cashChequeInternal` takes `msg.sender` as the beneficiary), so cashing
out happens later, elsewhere, from a machine that does hold the key. A
relay box holds nothing worth stealing — the property that makes today's
pusher safe (design §1, "not a signer") survives metering intact. The
relay *does* hold its node-identity key (`HOVERFLY_PUSHER_IDENTITY`),
which is not spendable and is used to sign quotes and challenges (§7.3).

**The factory check is security, not compatibility.** The relay must
verify `factory.deployedContracts(chequebook) == true`
(`bee/pkg/settlement/swap/chequebook/factory.go:101-118`) against a
factory address **hardcoded per chain**, never one supplied by the client.
Skip it and a client presents an arbitrary contract that returns a forged
`issuer()` and `liquidBalanceFor()` and implements `cashChequeBeneficiary`
as a no-op — total compromise for one `eth_call` saved. Optionally also
check the deployed bytecode hash against `AcceptedChequebookBytecodeHashes`
(`bee/pkg/config/chain.go:96-98`).

**Liveness is not enough: metering needs batch *standing*.** Open-mode
code now caches `batch_id → owner` through a bounded `OwnerCache` with
separate TTLs for successes and definitive rejections
(`src/pusher.rs:181-239`, `:1106`) — an amplification fix (§16.2) that
happens to give metering a staleness bound. Two gaps remain.

The first is that the TTL is tuned for amplification, not standing.
`OWNER_OK_TTL_SECS = 1800` bounds how stale an aliveness answer can be;
§10.3's Sybil bound needs the *credit line* re-read on the same schedule.
Metered mode extends the cache entry rather than adding a second cache.

The second is that liveness is a *boolean* and the thing it stands in for
is a *quantity*. "Alive" is satisfied by the cheapest batch that clears
the contract's minimum — minimum depth, minimum validity — which costs a
fraction of a cent. So metered mode reads standing, not liveness:

```
standing(B) = (owner, depth, remaining_value_plur)
remaining_value_plur = remainingBalance(B) × 2^depth
```

Both reads already exist — `read_batch` returns owner and depth
(`src/batch.rs:248`), `read_remaining_balance` returns PLUR per chunk
still funded (`:288`) — so this is one extra `eth_call` over what open
mode already does, cached per batch under the same TTL. §10.3 turns
`remaining_value_plur` into that account's credit line, which is what
makes the Sybil bound hold by construction rather than by assumption.

Known limitation: one account = one batch owner = one chequebook. A client
uploading under several batches with distinct owners needs a chequebook
per owner. A signed authorization linking extra batch owners to one
chequebook is possible but deferred (§15).

## 7. Wire protocol

Push frames (`src/pushframe.rs`) are **unchanged**. Payment is
out-of-band, for the same reason bee keeps swap on a separate stream from
pushsync: it must not sit on the hot path, and a payment failure must not
fail a push.

| Endpoint | Shape |
|---|---|
| `GET /v1/status` | new `payment` block, signed (§7.3); `mode: "open" \| "metered"` |
| `GET /v1/challenge?account=&batch=` | `{nonce, expires_ms, max_outstanding_plur}` — stateless MAC, issued only to a batch in good standing (§7.2) |
| `GET /v1/account` | requires the challenge header. `{owed_plur, reserved_plur, outstanding_plur, kib_admitted, kib_dedup, cumulative_received_plur, settle_every_plur, max_outstanding_plur}` |
| `POST /v1/pay` | requires the challenge header; body = `SignedCheque` JSON → `{accepted_plur, cumulative, outstanding_plur}` |
| `POST /v1/push` | requires the challenge header; `402 Payment Required` when over cap |

`/v1/account` is authenticated because unauthenticated it is a
per-identity volume oracle over on-chain-enumerable batch owners, and a
targeting oracle for tipping a victim into 402 at a chosen moment.

### 7.1 Rollout

Two-phase. *Soft mode* first: the relay meters, accepts cheques, and
reports `owed`, but **never answers 402** — an account over its credit line
is recorded and served anyway.

**Soft mode does not require the challenge; hard mode does.** A request
with no challenge header is an unmetered request, served exactly as `open`
mode serves it (with Stage 0 still shadow-counting it) — that is what lets
a relay flip to `--meter` while the existing fleet keeps working, because
clients that predate the protocol simply do not send the header. Requiring
it unconditionally would 401 the whole fleet the moment metering was
enabled, the opposite of a staged rollout. What soft mode drops is
enforcement of the cap, not authentication of those who present one: a
header that is *present but invalid* is refused (401) in both modes —
claiming a capability you do not hold is not the same as not claiming one,
and letting it through would make the check bypassable by corrupting a
byte. (An earlier draft of this section said the opposite — that soft must
require the challenge lest metering be bypassable by omitting a header.
That confuses bypass with non-participation: an omitted header is billed
nothing and grants nothing, served as `open`; a forged header is refused.)

Only once clients in the wild can pay does a relay flip to hard mode.

Soft mode is an *instrument*, not a migration path for clients: the `done`
line lands after the whole batch (`src/pusher.rs:1090`), so a client
cannot use it to pace itself. Its job is to tell the operator what §14
Stage 0 needs to know.

### 7.2 Admission — the challenge carries account, batch and credit line

An early draft claimed 402 was easy because `/v1/push` spawns its body
(`src/pusher.rs:835`), so the status is committed before any chunk is
processed. That is true and it is the *problem*: at that moment the relay
does not yet know whose account to check. The account only exists after
`stamp::validate` (`:900`) and `resolve_owner` (`:912`, two `eth_call`s on
a miss), both inside the spawned task. Hoisting them means up to 512
ecrecovers (~40 ms) plus a possible RPC round-trip synchronously in front
of every response — the exact unauthenticated amplification surface §11.6
spends a section defending, and instantly over budget on the CF Workers
profile (design §9: 10 ms CPU/req).

**The challenge solves this by moving the chain reads off the POST path
entirely.** Standing (§6) is resolved once when the challenge is *issued*,
and the resulting credit line is baked into the nonce. `/v1/push`
admission then reads no chain state at all:

```
GET /v1/challenge?account=A&batch=B
  → resolve standing(B) (cached per batch, TTL; §6)
  → require owner(B) == A, else 403 — no nonce is issued
  → cap = credit_line(standing(B))                       (§10.3)
  → nonce = HMAC(relay_secret, preimage(A, B, origin, expiry, cap))
  → {nonce, expires_ms, max_outstanding_plur: cap}
```

**The MAC preimage is fixed-width and domain-tagged, not a
concatenation.** `origin` is variable-length, so a bare concatenation
makes `("host.a", "bc")` and `("host.ab", "c")` share a preimage, and a
relay serving several hostnames would issue one nonce valid for two of
them. In bytes rather than a typed struct, because only the relay ever
parses it:

```
preimage = "hoverfly-pusher-challenge-v1"   // domain tag, fixed 28 B
         ‖ A            (20 B)
         ‖ B            (32 B)
         ‖ expiry_be    ( 8 B)
         ‖ cap_be       (16 B)
         ‖ len(origin)  ( 2 B, big-endian)
         ‖ origin       (variable, last)
```

Two operational rules come with it. Compare the MAC in **constant time** —
it is the only secret in the exchange and the client controls every other
field, so a byte-wise early exit is a forgery oracle. And **persist
`relay_secret` alongside the ledger** (§11.4): a secret regenerated at
boot invalidates every outstanding challenge, which on a host that sleeps
and cold-starts (design §7 measured a 35.2 s wake) turns every restart
into a 403 storm for clients mid-upload.

The nonce is therefore a **capability**: possessing one is proof the relay
already checked standing and already priced the credit line. Admission
becomes:

1. Verify the MAC over `preimage(A, B, origin, expiry, cap)` — symmetric,
   no RPC, constant-time compare.
2. Verify `origin` against the relay's **configured** hostname — never
   against the request's `Host` or `X-Forwarded-Host` (see below).
3. Verify the client's signature over the challenge struct → recovers `A`
   (1 ecrecover, no RPC, no body).
4. `reserve = ceil(Content-Length / 1024) × price_plur_per_kib`; if
   `outstanding(A) + reserve > cap` → **402**, before reading the body.
5. Otherwise commit the reservation atomically, return 200, spawn.
6. On completion, convert reservation → `owed` for bytes actually admitted
   (§8) and release the remainder.

**`origin` must be configured, not derived.** This is the single
easiest-to-get-wrong line in the design. The obvious implementation reads
the `Host` header and compares the challenge's `origin` against it — and
that is a no-op, because `Host` is *supplied by the same client that
supplies the challenge*. An attacker replaying a victim's signature at
relay B simply sends `Host: relay-b.example`, the comparison passes, and
§11.1's cross-relay replay is restored in full while the doc claims it is
closed. `X-Forwarded-Host` is worse: attacker-set on any relay not behind
a proxy that overwrites it, which the reference deployment is not. So the
relay takes its hostname from a required `--origin` flag and compares
against that constant. A relay reachable at several hostnames configures
the list; a relay that cannot state its own origin must not run metered.

**The reservation is exactly the billing unit.** Because §8 bills bytes,
the quantity reserved at admission and the quantity billed at completion
are the same thing, computed the same way — `Content-Length` before, bytes
counted after. No estimation, no conversion, no over-reserve. (An earlier
draft reserved a flat `PUSH_BATCH_MAX × price`, which was ~10× a dust
batch's entire credit line and 402'd every POST from it regardless of
size.) A request with no `Content-Length` is refused; the existing client
always sets one, and `PUSH_MAX_BODY` (`src/pusher.rs:64`, ≈ 2.08 MiB)
caps it anyway.

**Small batches are the client's job to size.** A 0.01 BZZ dust batch gets
~208 KiB of credit (§10.3), so it cannot push a full 512-frame POST
(~2 125 KiB) in one go. The challenge returns `max_outstanding_plur`, so
the client knows its ceiling before it builds the request and simply sends
smaller POSTs. This is a normal flow-control interaction, not a failure.

Issuing the challenge only to a batch in good standing also closes a hole
an earlier draft left open: admission previously granted a reservation to
*any* EOA that could sign, since standing was established per frame inside
the spawned task. Free identities could occupy reservation-ledger entries
without ever owning a batch. Now they cannot obtain a nonce at all.

**Nonces are stateless.** No server-side table, so no unbounded-memory DoS
from a free `GET /v1/challenge`, and no per-POST round trip that would
serialize the pipeline the scheduler exists to exploit (`inflight_max` up
to 8, `src/pusher.rs:517`). Replay within the window is bounded by the
reservation, not by nonce uniqueness. Two limits follow from making the
challenge endpoint do chain work:

- **Rate-limit and cache `/v1/challenge`.** Amplification is bounded by
  *distinct batch ids*, not request count, so cache standing per batch
  under the §6 TTL and negative-cache unknown batches. Per-IP limiting on
  top (§11.6's inbound limiter).
- **Bound live-reservation cardinality.** The in-memory
  `account → reserved` map is attacker-influenced (one entry per batch in
  standing), so cap the number of accounts holding live reservations and
  shed beyond it. Persist a row only once `owed > 0`.

**The challenge is EIP-712, not a concatenation.** The account key already
signs postage stamps (EIP-191 over stamp bytes) and cheques (EIP-712,
domain `Chequebook`). A third raw-bytes scheme over the same key invites
cross-scheme confusion. Use a typed struct with its own domain:

```solidity
// domain: {name: "HoverflyPusher", version: "1", chainId}
struct PushChallenge {
  bytes32 nonce;
  string  origin;      // host the client dialled; relay checks its own
  address account;
  bytes32 batchId;
  uint256 expiry;
}
```

`quote_valid_secs` governs the quote; the challenge gets its own, much
shorter `challenge_ttl_secs` (~300 s), since re-signing is one local
ecrecover's worth of work and a short window shrinks the replay surface to
near nothing.

**Browser blocker:** the CORS preflight currently allows exactly one
request header, `content-type` (`src/pusher.rs:468-486`, header list at
`:481`). A custom challenge header fails preflight in every browser until
that list grows. Push *frames* are unchanged, but the challenge is still a
wire change.

### 7.3 The quote is signed

`/v1/status` is unsigned JSON today (`src/pusher.rs:488-528`). An unsigned
price is repudiable in both directions: the relay can serve `P` and bill
`10P`, the client can claim it saw `P/10`, and reconciliation can detect
the mismatch but never attribute it. So the `payment` block is signed with
the node-identity key — which the relay already holds and already
publishes as `overlay` (`:499`) — and the signed blob is echoed verbatim
in every 402.

**The pin is on the node's Ethereum address, not on its overlay.** An
overlay is `keccak(eth_addr ‖ network_id_LE8 ‖ nonce)`; verifying a
signature yields the **eth address**, and the nonce is neither transmitted
nor derivable, so "pin `(url, overlay)`" is not implementable — the
recovered address and the pinned overlay are values in different spaces.
The signed block therefore carries `node_eth_address` and `overlay_nonce`,
so any client can recompute `overlay` and check it against what
`/v1/status` advertises, and clients pin
**`(url, node_eth_address, beneficiary)`**. A client already names its
relays somewhere — `PUSHER_URLS` in the dApp, `--pusher` on the CLI — so
carrying two more fields alongside a URL it already had costs nothing.

```jsonc
// GET /v1/status → new field (the whole object is covered by `sig`)
"payment": {
  "mode": "metered",
  "beneficiary": "0x…",                  // EOA that must appear in Cheque.beneficiary
  "node_eth_address": "0x…",             // recovers from `sig`; client pins this
  "overlay_nonce": "0x…",                // 32 B; lets the client recompute `overlay`
  "origin": "relay-a.example",           // must equal the configured --origin (§7.2)
  "chain_id": 100,
  "factory": "0xc2d5a532cf69aa9a1378737d8ccdef884b6e7420",
  "price_plur_per_kib":    "480000000",
  "min_cheque_plur":       "3900000000000",
  "settle_every_plur":    "15600000000000",
  "max_outstanding_plur": "62200000000000",  // ceiling; actual cap is per
                                             // batch, see §10.3
  "credit_ratio": 1000,                      // credit line = batch value ÷ this
  "quote_valid_secs": 86400,
  "challenge_ttl_secs": 300,
  "sig": "0x…"                              // node-identity key over the above
}
```

Parameters are derived in §9 and §10.1; the ordering
`min_cheque ≤ settle_every < max_outstanding` is a hard invariant (§10.1).
`quote_valid_secs` (86400) must exceed one settlement period (§10.1 sizes
~32 MiB per window); the client may cache the quote that long without
re-reading `/v1/status`.

## 8. The billing unit: bytes admitted

> **`owed = (kib_admitted − kib_dedup) × price_plur_per_kib`**, where
> `kib_admitted` is the body bytes the relay accepted under a valid
> challenge, rounded up to KiB.

That is the whole billing rule. It has one property that matters more than
everything else in this document:

> **The client cannot lie about it, because the client is the one who
> produced the bytes and the relay is the one who counted them.**

There is no third-party attestation to forge, no signature to replay, no
chain state to disagree about, and no relay assertion the client has to
take on faith. The client committed to `Content-Length` when it built the
request; the relay counted what arrived. Both numbers are known to both
parties before any push work happens, and they must agree or the request
was malformed.

Compare what this replaces. An earlier draft billed per *verified pushsync
receipt*, which forced a five-clause predicate anchored in the staking
registry (to stop trivial receipt forgery), a set-valued invoice (to stop
self-replay), a sampled retrieval audit (to catch fabrication), a staked-set
log sweep on both sides, and a shared predicate module that had to be
byte-identical between client and relay or it would generate disputes with
no adjudicator. All of that existed to make a *third party's* signature
into a billing input. Removing the receipt from the invoice removes the
entire apparatus and every attack against it.

### 8.1 Why bytes rather than successful pushes

Because bytes are what the relay spends money on. §9.1's cost basis is
egress, and egress is incurred on *attempts* — the 3-way peer race and the
shallow retries happen whether or not a chunk ultimately lands. Billing
successes would mean the relay eats the cost of every failure, which is
what made an earlier draft's "shallow-cascade arbitrage" (§11.5) an
unresolvable tension between verifiable billing and cost recovery. Billing
attempts dissolves it: the relay charges for what it spends, and the
*client* protects itself against a lane that spends without succeeding by
deweighting it in the scheduler, which is a mechanism that already exists
and already works.

Two mechanisms, each doing what it is good at, instead of one mechanism
trying to do both and failing at the second.

### 8.2 Dedup hits are billed at zero

A frame served from the recent-ack cache (`src/pusher.rs:928-948`) does no
push work, so its bytes are subtracted. The ack already reports dedup, and
the `done` line carries the count (`:969-971`), so the client can
reconstruct the invoice exactly.

This is the one place a relay assertion enters the bill — the relay claims
"this was a dedup hit". It is safe because the claim only ever *lowers*
the amount owed, so a relay has no incentive to make it falsely, and a
client that disagrees is disagreeing in its own favour.

### 8.3 Cumulative cheques, and why not per-chunk

A cheque is a cumulative running total for one `(chequebook, beneficiary)`
pair. Three properties fall out, all of which we want:

- **Loss-tolerant.** A dropped or failed `/v1/pay` costs nothing; the next
  cheque supersedes it. No retry state machine.
- **Replay-proof within a live relay.** Strict monotonicity means a
  re-presented cheque credits zero. (Across a *restart*, see §11.4.)
- **Cheap, and gas-amortizing by construction.** One signature per
  `settle_every_plur`, and the relay cashes only the *latest* cumulative,
  so on-chain gas is paid once per account, not once per cheque. This is
  why the dust floor (§10.1) is about RPC cost, not gas.

**Attaching cheques to chunks or frames is rejected.** ~137 bytes per
4 KiB chunk, an EIP-712 signature on the per-chunk hot path, and — fatally
— cumulative payouts are *serial* per `(issuer, beneficiary)` pair, so
per-chunk cheques would force a total order on chunks within a lane,
destroying the concurrent multi-POST pipelining the scheduler depends on
(design §7).

**Two lanes may share one beneficiary, and the client must handle it.** A
cumulative is per `(chequebook, beneficiary)` — the beneficiary is what
the contract keys `paidOut` on — while a *lane* is a URL, and one operator
running four lane URLs behind one beneficiary EOA is the obvious
deployment. If the client tracks cumulatives per lane, that configuration
**bricks**: `src/cheques.rs` keys `payouts` on the peer *overlay*, with a
comment explaining that the overlay is the only stable cross-run identity
(`:64-76`) — correct for bee peers, wrong for relay beneficiaries. Lane 1
issues cumulative 10; lane 2, counting from its own zero, issues 8; the
relay applies `ErrChequeNotIncreasing` and rejects it, forever.

> **Key the client's cumulative store on `(chequebook, beneficiary)`, not
> on lane or overlay.** Two lanes advertising one beneficiary are one
> settlement channel; sum their `owed` before signing, and send the same
> cheque to both.

Detecting the sharing is free — the beneficiary is in the signed quote
(§7.3), so the client sees it before its first push.

Independently, lanes with *distinct* beneficiaries still **share one
chequebook balance**, so the client must track the sum. `src/cheques.rs`
needs a `total_issued` mirroring bee's `reserveTotalIssued`
(`chequebook.go:163-178`). Without it a cheque to the second lane silently
exceeds the balance and bounces.

### 8.4 Reconciliation

`GET /v1/account` returns `kib_admitted` and `kib_dedup`. The client
compares them against what it sent. Because the client's byte count comes
from its own request construction and not from anything the relay returns,
this is immune to the failure mode that made an earlier draft's
reconciliation useless: ack sends are fire-and-forget
(`src/pusher.rs:855-860`), so a client that hangs up mid-stream legitimately
receives fewer acks than the relay emitted — but it still knows exactly how
many bytes it sent. There is nothing to dispute.

A relay over-reporting `kib_admitted` is therefore immediately visible and
attributable. The client's response is to withhold the next cheque and
deweight the lane. That is not social enforcement — it needs no operator,
no list and no reputation — it is simply the client declining to sign for
a number it can check itself. What it costs the client to detect the
disagreement is bounded by the credit line, since nothing above that can
be admitted before the next settlement.

## 9. Pricing

### 9.1 Cost basis

Design §9's *"egress ≈ payload × 1.4× at race=1; in-pusher racing is off
by design"* is wrong on its premise. **In-pusher racing is on:**
`CHUNK_PEER_PARALLELISM = 3` (`src/client.rs:4086`), and three peers are
seeded concurrently at dispatch, each writing a full Delivery before any
receipt is read. Design §7 says so in its own words — *"the deliberate
3-way peer race"*, measured at 2.2 PO of receipt depth for 2–3×
throughput.

Real cost per 4 KiB chunk relayed:

| | |
|---|---|
| Delivery on the wire | addr 32 + stamp 113 + span/data ≤ 4104 ≈ 4249 B, +~5 % protobuf/yamux/noise/TCP ≈ **4.4 KiB** |
| Peer race | **×3** |
| Shallow retries at pool 128 | **×1.15** (design §10: 0.44 shallow/chunk) |
| **Egress per chunk relayed** | **≈ 15 KiB** |
| **Egress per GiB of payload** | **≈ 3.7 GiB** (262 144 chunks/GiB) |

**The Stage 0 counter does not check this, and currently cannot.**
`/v1/meter` → `egress.attempts_per_frame` exists to test the ×3.45 model
against reality, and the production relay reports **1.077**. That is not a
refutation of the model, it is an instrument fault. `PUSH_OUTCOME_*` is
incremented *after* the await inside the racing future
(`src/client.rs:5818-5870`), and the dispatcher cancels the losing racers
the moment it accepts a receipt — `src/client.rs:4806-4809` says so in as
many words. A cancelled racer has already written its Delivery to the
wire, so the relay pays that egress, and then the future is dropped before
it ever reaches the counter.

The relay's own diagnostics show the shape plainly: `ok = 3756` against
`frames_admitted = 3756` — exactly one counted success per chunk, with
only 285 shallow retries and 4 errors above it. A metric that counts
completions cannot see a race it loses on purpose, so it floors near 1.0
by construction.

Counting at *dispatch* (where `inflight_pushes` is already incremented,
`src/client.rs:4818-4820`) rather than at completion would fix it. Until
then §9.1's model stands unverified in both directions, and **nothing here
should be repriced on `attempts_per_frame`** — which was the one job Stage
0 was supposed to do for §9.2.

### 9.2 Price

| | per GiB of payload |
|---|---|
| Cheap VPS bandwidth (~€1/TB) | ≈ €0.0037 |
| AWS egress ($0.09/GB) | ≈ $0.36 |
| **Suggested price** | **$0.02** |
| Postage (buys a *year* of storage) | orders of magnitude more |

$0.02/GiB is ~5× a VPS's raw bandwidth cost — a real margin covering CPU,
the dedicated IP, and gas — and ~18× cheaper than AWS egress. Against what
the user already paid for postage it is a rounding error.

**Read that AWS row as a constraint, not a favourable comparison.** At
§9.1's 3.7 GiB of real egress per GiB of payload, per-GB-billed clouds
cost the relay ~$0.36/GiB against $0.02 of revenue. Metered mode is only
rational on **flat-rate or included bandwidth** — the same class of host
§5 already requires for durable storage, and the same class §1 says
metering exists to fund. A relay on metered egress should run `open` and
eat the quota, or not run at all.

At $0.40/BZZ: `$0.02 / $0.40 = 0.05 BZZ/GiB`; `0.05 × 10¹⁶ = 5e14` PLUR
per GiB, ÷ 1 048 576 KiB =

> **`price_plur_per_kib ≈ 4.8 × 10⁸`** (1 BZZ = 10¹⁶ PLUR).

A full push frame is `HEADER_LEN(147) + wire(4104) = 4251` B ≈ 4.15 KiB,
so a 4 KiB chunk costs ≈ `2.0 × 10⁹` PLUR all in. Framing overhead is
billed because the relay received those bytes.

Flat per KiB, deliberately. Any pricing curve steeper than flat
re-introduces a per-item number for the two sides to disagree about, and
the entire point of §8 is that there is exactly one number and both
parties measure it directly.

### 9.3 Gas, and who is actually profitable

Cashout's gas *limit* is `GetGasLimitWithDefault(ctx, 300_000)`
(`cashout.go:145`), but a limit is not a spend. The two real
`cashChequeBeneficiary` calls on Gnosis mainnet used **75 378** and
**109 590** gas at **169** and **1 292** wei/gas — fees of `1.3e-11` and
`1.4e-10` xDAI:

| | gas used | gas price | fee |
|---|---:|---:|---:|
| 2026-08-07 | 109 590 | 1 292 wei | 1.4e-10 xDAI |
| 2026-08-08 | 75 378 | 169 wei | 1.3e-11 xDAI |

Both are `cashChequeBeneficiary` on chequebook
`0x17c89DE40f5ec07343AB095bfDa9dE1A5c095Fc1` (txs `0xb33bd199…` and
`0x9d4a8b29…`), settling `1.46e12` PLUR in total to the relay beneficiary.

An earlier draft of this section carried **$0.0005**, assuming the full
300 k limit at gwei-scale prices. Gnosis base fee during these runs was
50–1 300 wei, so that estimate was high by roughly **six orders of
magnitude**. Issuing a cheque still costs nothing
(`chequebook.go:190-250` sends no transaction); only cashing out touches
the chain, and because cheques are cumulative that gas is paid **once per
account**.

**This removes the gas floor, not the price floor.** At ~`1e-10` xDAI a
cashout, essentially any non-zero cheque is worth collecting. Design §11's
flagship 71 MB browser upload is worth `71/1024 × $0.02 ≈ $0.0014`, which
clears its own settlement fee by about seven orders of magnitude. The
conclusion this section used to draw — *"a one-shot user is not
profitable"* — was an artifact of the stale gas number and is withdrawn.

What survives is an *operational* floor rather than an economic one: an
RPC round trip, a pending transaction to watch, and a chequebook that has
to stay funded. So read the 0.25 BZZ threshold as a batching convenience,
not as a break-even point — and note that Gnosis gas is not permanently
this cheap. A floor computed from `eth_gasPrice` at cashout time holds
under a price spike in a way a hardcoded constant does not, in either
direction.

## 10. Credit and settlement

**Postpaid.** The client accrues `owed` and settles when it crosses
`settle_every_plur`. Not prepaid: an anonymous browser prepaying a relay
is exposed to outright theft, whereas postpaid exposes the relay to at
most one cap of bandwidth. The asymmetry is correct — the relay's risk is
a fraction of a cent, the client's would be its deposit.

### 10.1 Parameters, and the invariant to hold

> **Invariant: `min_cheque_plur ≤ settle_every_plur < max_outstanding_plur`.**
> A client that is 402'd must always be able to clear it with a cheque for
> exactly what it owes.

An early draft published `min_cheque_plur` 87× larger than
`settle_every_plur`. Every metered account would have bricked: accrue →
cross `settle_every` → sign a cheque → **rejected as dust** → keep
accruing → 402 → the only cheque that clears the 402 is 21× what is owed,
which the no-prepayment rule forbids. No exit. The error came from sizing
the dust floor against *cashout gas*, which cumulative cheques amortize
separately (§8.3).

`min_cheque_plur` exists only to bound RPC cost per unit of value (§11.6
lists up to 4 `eth_call`s per cheque, of which `liquidBalanceFor()` and
`paidOut()` cannot be cached). A quarter of `settle_every` is sufficient.

At $0.02/GiB → 4.8e8 PLUR/KiB:

| parameter | value (PLUR) | in payload | rationale |
|---|---|---|---|
| `price_plur_per_kib` | 4.8e8 | 1 KiB | §9.2 |
| `min_cheque_plur` | 3.9e12 | ~8 MiB | ≥ 4 `eth_call`s' worth of value |
| `settle_every_plur` | 1.56e13 | ~32 MiB | ~2–3 cheques per 71 MB upload |
| `max_outstanding_plur` | 6.22e13 | ~127 MiB | 4 × settle_every — a *ceiling*, not the cap; §10.3 |
| cashout threshold | 2.5e15 | ~5 GiB | §9.3 |

The unsecured credit at risk per account is at most ~127 MiB ≈ **$0.0024**,
and less for any batch worth under ~6.2 BZZ, since §10.3 caps it at a
thousandth of the batch's remaining on-chain value. `settle_every` at
32 MiB also keeps the honest path off §11.6's amplification profile: ~2–3
`/v1/pay` calls per 71 MB upload, not ~71.

### 10.2 Reservation: bee's `reserve` was needed after all

A monotone debit counter per account is not sufficient. `/v1/push`
deliberately does not serialize (`src/pusher.rs:785-846`: *"serializing
them … forced needless failover churn"*), so N concurrent POSTs each read
`outstanding` before any of them debits.

N is now bounded — §16.3 added a 256-permit semaphore acquired before
`accept()` (`src/pusher.rs:377-415`) — but 256 concurrent full-size POSTs
is still `256 × 2 125 KiB × 4.8e8 = 2.6e14` PLUR, **4×
`max_outstanding_plur`**. The connection cap turns an unbounded overshoot
into a merely large one; it does not remove the need for a reservation. A
*polite* client at the relay's own advertised `inflight_max` of 8
overshoots a 4-×-`settle_every` cap on its own.

Fix, per §7.2: reserve `ceil(Content-Length / 1024) × price_plur_per_kib`
atomically at admission and release the unused remainder at completion —
bee's `reserveTotalIssued` applied to the receiving side.

There are four coupled per-account quantities, not one: `owed`,
`reserved`, `last_cumulative[chequebook]`, and the `chequebook → account`
binding. They are written by N spawned tasks and read by admission, so
they need one lock.

**But `reserved` must not be persisted.** A reservation belongs to an
in-flight POST, and no in-flight POST survives a restart — there is no
task left to release it. Restoring `reserved` from disk leaks credit
permanently and can brick an account into 402 with no way out, which is
exactly what §10.1's invariant exists to prevent.

> **Persist `owed`, `last_cumulative` and the chequebook binding
> atomically. Reconstruct `reserved` as zero at boot.**

The exposure from zeroing is one body's worth of over-admission
immediately after a restart — cents of egress, against an accounting
corruption that never self-heals. `owed` is written at batch completion,
so a crash forfeits at most the batch in flight, the same safe direction.

### 10.3 Sybil bound: derive the credit line, don't assert it

"An account is a batch owner, a live batch costs real BZZ, so the margin
is three orders of magnitude" is false. The relay checks **liveness**, and
liveness is satisfied by the cheapest batch the `PostageStamp` contract
will accept — minimum depth, minimum validity — which costs a fraction of
a cent. At a flat $0.0024 credit line the real margin is of order **1×**:
a throwaway batch buys roughly its own value in free relay.

A hard floor on batch depth and TTL would fix the arithmetic at the cost
of excluding small legitimate users, which is the wrong trade for a system
whose flagship case is a 71 MB browser upload. So instead of gating on
batch size, **scale the credit line to it**:

> **`max_outstanding(A, B) = min(remaining_value_plur(B) ÷ credit_ratio,
> max_outstanding_plur)`**

with `credit_ratio = 1000` and `remaining_value_plur` from §6's standing
read. The Sybil margin is then **1000× by construction and independent of
batch size**: any attacker, holding any mix of batches, obtains total
credit equal to one thousandth of the on-chain value they actually funded.
There is no cheap corner of the parameter space, because the ratio is the
invariant rather than a consequence of a particular batch being expensive.

Concretely: a batch needs ~6.2 BZZ (≈ $2.49) of remaining value to
saturate the global $0.0024 ceiling; a 0.01 BZZ dust batch earns
`1e11 ÷ 4.8e8 ≈ 208 KiB` of credit — enough to be useful, far too little
to farm. The line decays on its own as the batch is spent down or
approaches expiry, and §6's TTL is what makes that decay visible.

This is the same move as §8's: replace an asserted constant with a
quantity read from chain, so the property holds by construction rather
than by assumption about what attackers will bother to buy.

## 11. Attack surface

Everything here is **a client attacking a relay**, per §2. Severity is
from the relay's point of view. "Inherited" means the issue exists in
bee's SWAP too; "introduced" means metering creates it.

### 11.1 CRITICAL — stamp replay becomes billing griefing (introduced)

**Swarm stamps are public.** Design §6 says so — *"anyone who saw your
chunks holds valid `(addr, stamp, wire)` triples"* — and they are
recoverable from the network, since retrieval returns the stamp alongside
the data (`src/protocols/retrieval.rs:27`, `:42-80`). A relay holds every
stamp it has ever relayed, so it is the densest source of all (§2).

In open mode this is harmless: re-pushing is idempotent. **Under metering
it is an attack.** An attacker harvests a victim's stamps and replays them
at a metered relay. Auth passes — the stamps genuinely recover to the
batch owner — so the work is billed to the *victim's* account. Cost to the
attacker: zero.

**Mitigation, mandatory:** the challenge of §7.2, plus §6's rule that
every frame must carry the exact batch id named in the challenge. The
challenge must be *signed by the account*, so possession of a harvested
stamp is not enough — the attacker would need the batch owner's key, which
is the same key that signs the stamps it is replaying.

**The signed payload binds the relay's origin, not its beneficiary.** An
earlier draft signed `(nonce ‖ beneficiary ‖ account)` so a challenge could
not be replayed across relays. That fails: nothing authenticates a
beneficiary, so relay A can advertise honest relay B's beneficiary *and*
serve B's nonce, collect a victim's signature during a normal upload
through A, and replay it at B alongside V's stamps. Bind **`origin`** —
the host the client dialled — and have the relay verify it against its own
**configured** hostname (§7.2). Deriving it from a request header makes
the binding a no-op.

### 11.2 CRITICAL — the withdraw race: cheques are unsecured (inherited)

bee deploys chequebooks with a hard-deposit timeout of zero
(`init.go:169` passes `big.NewInt(0)` to `Deploy`, whose parameter is
`defaultHardDepositTimeoutDuration`, `factory.go:35`, `:62`) and never
places hard deposits, so the whole balance stays liquid and the issuer can
`withdraw()` at any time. The relay's funding check is therefore true **at
acceptance time, not at cashout time**.

Attack: accrue debt → sign a covering cheque → relay verifies and keeps
serving → withdraw the chequebook → the relay's cashout collects less than
it is owed. Bee has the identical exposure; it is inherent to
SimpleSwap-as-deployed.

**What reading `ERC20SimpleSwap` directly established:**

*Cashout does not revert.* `_cashChequeInternal` pays
`totalPayout = Math.min(requestPayout, liquidBalanceFor(beneficiary))`,
credits `paidOut[beneficiary]`, and only then, if
`requestPayout != totalPayout`, sets `bounced = true` and emits
`ChequeBounced()`. An underfunded cashout **succeeds partially** and takes
whatever is there. The exposure is the shortfall, not the whole claim, and
`bounced` is *readable contract state* set contract-wide, so one bounce
marks the chequebook permanently.

*Hard deposits work, but are inert as bee deploys them.* `withdraw()` is:

```solidity
function withdraw(uint amount) public {
  require(msg.sender == issuer, "not issuer");
  require(amount <= liquidBalance(), "liquidBalance not sufficient");
  require(token.transfer(issuer, amount), "transfer failed");
}
```

with `liquidBalance() = balance() − totalHardDeposit`, so a deposit
genuinely locks funds. But decreasing uses

```solidity
uint timeout = hardDeposit.timeout == 0 ? defaultHardDepositTimeout : hardDeposit.timeout;
hardDeposit.canBeDecreasedAt = block.timestamp + timeout;
```

and `decreaseHardDeposit` requires
`block.timestamp >= canBeDecreasedAt && canBeDecreasedAt != 0`. With bee's
`defaultHardDepositTimeout = 0` and a fresh deposit's `timeout == 0`, both
conditions hold in the *same block*: prepare, decrease, withdraw. A hard
deposit on a bee chequebook is this attack with two extra calls in front
of it.

`setCustomHardDepositTimeout(beneficiary, timeout, beneficiarySig)` is the
way out — issuer-submitted, but requiring an EIP-712 signature **from the
beneficiary**, and the hash binds `address(this)`, the client's chequebook,
so it cannot be pre-signed. Secured mode therefore costs one interaction
with the cold beneficiary key per client chequebook. Deferred to §14
Stage 2 as an account-tier feature, not a default.

**Mitigations, in force:**

1. **The per-account cap** (`max_outstanding_plur`), bounding the yield to
   $0.0024 per account and one postage batch per account. This is the real
   defence — **and it only works if §10.2's reservation ships.**
2. **Cash out at the threshold and treat sub-threshold value as at risk.**
   At 5 GiB/account (§9.3) most accounts are never cashed, so the exposure
   is chronic rather than acute. Bounded by mitigation 1, not by
   promptness.
3. **Blocklist bouncing issuers.** Read the `bounced` flag — a cheap
   `eth_call`, not a log subscription you had to be watching at the time.

Do not treat an accepted cheque as settled revenue. It is a claim.

### 11.3 HIGH — Sybil beneficiaries and aggregate exposure (introduced)

Nothing proves a relay controls the beneficiary EOA it advertises; that
would require holding the key, destroying the property in §6. Since a
cumulative is per `(chequebook, beneficiary)`, **one operator running N
lane URLs with N beneficiary EOAs presents N independent accounts**, and
the client has no aggregate view until `src/cheques.rs` grows
`total_issued` (§8.3).

Under §2 this is not a relay-fraud concern — it is a client-side budgeting
concern, and the fix is client-side: `total_issued` as a hard ceiling
across all beneficiaries, and pinning `(url, node_eth_address, beneficiary)`
in config rather than reading the beneficiary from `/v1/status` at runtime.

### 11.4 HIGH — relay state loss is an unbounded free-service loop (introduced)

If the relay loses `last_cumulative[chequebook]`, a client re-presents its
most recent cheque and is credited the full cumulative instead of the
delta.

Seeding `last_cumulative` from on-chain `paidOut(beneficiary)` is inert at
§9.3's parameters: with a 5 GiB cashout threshold, almost no account is
ever cashed, so `paidOut` is permanently 0 and the seed is 0. The attack
is then: pay one cheque, consume service, wait for a restart, re-present
**the same cheque**, repeat — unbounded free service from a single
signature at zero incremental cost. Restarts are not incidental on free
tiers that sleep and cold-start (design §7 measured a 35.2 s wake).

**Mitigation: metered mode requires durable storage** (§5). Persist
`owed`, `last_cumulative`, the `chequebook → account` binding **and
`relay_secret`** (§7.2) atomically together — losing only
`last_cumulative` over-credits, losing only `owed` under-bills, losing
`relay_secret` 403s every live client. Seed from `paidOut` on first run as
a floor, never as the primary source. A relay that cannot guarantee
durable state must run `open`.

**`reserved` is deliberately excluded** and reconstructed as zero at boot
(§10.2).

### 11.5 MEDIUM — shallow-cascade cost griefing (introduced)

For a chunk nothing will store: 3 peers are raced immediately
(`src/client.rs:4086`); candidates are topped up to
`cap = max_retries.min(order.len())` with `PUSH_MAX_RETRIES = 20`
(`src/pusher.rs:94`, applied at `src/client.rs:4315`); if every outcome is
shallow or overdraft with no hard error the dispatcher **walks past `cap`**
over the whole eligible pool (`:4573-4602`, up to 128 sessions);
shallow-only then returns a *retryable* outcome and the outer loop
re-dispatches up to `MAX_CHUNK_RETRIES = 60` (`:4104`). The attacker aims:
the relay publishes its overlay (`src/pusher.rs:499`), `pool.live`
(`:511-514`) and the `pool_po` mean inside `diag` (`:525`), so addresses
can be mined into arcs the pool covers poorly. Design §10 measured 8.1
shallow receipts/chunk at pool 32 as the *accidental* rate.

**Bytes-admitted billing prices most of this away.** The attacker pays for
every byte it sends regardless of outcome, so it can no longer buy cheap
egress by aiming at badly-covered arcs — the arbitrage that made this
economically rational under receipt billing is gone. What remains is pure
griefing: the attacker burns its own credit to make the relay burn more.

> **Not yet implemented:** metered pushes currently spend the same
> downstream budget as open ones (`PUSH_MAX_RETRIES = 20`,
> `src/pusher.rs:94,1818-1830`, no metered branch). Capping delivery
> *attempts* per chunk below open mode's fallback and disabling the
> past-`cap` walk for metered requests is outstanding work — the
> amplification factor is the cost control that matters there. Until then,
> treat the per-account cap (§11.2) as the griefing bound: an attacker can
> multiply each admitted byte downstream, but each admitted byte is billed,
> so the griefing budget is the credit line, not free.

### 11.6 HIGH — RPC amplification on `/v1/pay` (introduced)

Accepting a cheque costs up to 4 `eth_call`s. Order the checks
cheapest-first and reach the chain only after every free check passes:

1. Parse and length-check.
2. **Reject non-canonical signatures**: length ≠ 65,
   `s > secp256k1n/2`, or `v ∉ {27, 28}`. Free, and mandatory — see below.
3. EIP-712 recover (local, ~80 µs).
4. `beneficiary == ours`, `chain_id == ours`.
5. `cumulative > last_cumulative[chequebook]` and
   `amount ≥ min_cheque_plur`.
6. *Then* RPC: `deployedContracts` (positive cached 24 h, negative 10 min
   per chequebook), `issuer()` (**cache per chequebook** — bee refetches
   it on every cheque at `chequestore.go:149` despite its own comment
   saying it never changes; do not copy that), `liquidBalanceFor`,
   `paidOut` and `bounced` batched in one JSON-RPC request and cached 30 s
   (`STATE_TTL`). The balance reads are the §11.2 check, and caching them
   does not weaken it: §11.2 is true *at acceptance time, not at cashout* —
   the issuer can withdraw the instant after acceptance, so a fresh read
   only narrows the window against an exposure already bounded by
   `max_outstanding` either way. What the cache buys is real: most cheques
   cost zero chain reads (§10.1 windows ~2-3 cheques per 71 MB upload).

**That ordering bounds nothing on its own.** Every "free" check passes for
a cheque an attacker synthesizes at zero cost: it reads `beneficiary` and
`chain_id` from the public quote, picks a random chequebook address, signs
with a throwaway key — step 3 recovers *some* address, and nothing
compares it to anything until `issuer()` — and sets `cumulative` above
`min_cheque_plur`, which clears step 5 trivially because `last_cumulative`
for an unseen chequebook is zero. Each garbage POST costs one
`deployedContracts` call. Cheapest-first is a latency optimisation; the
bound must come from somewhere the attacker cannot reach:

- **No debt, no cheque.** Refuse any cheque for an account with
  `owed == 0`, before parsing. Postpaid (§10) means an honest client
  always has debt by the time it settles, so this costs nothing legitimate
  and makes the endpoint useless to anyone who has not first done billable
  work under a challenge.
- **Require the challenge header on `/v1/pay`**, as on `/v1/push`. The
  caller must hold a batch in standing to reach any code path, pricing the
  amplifier at one live postage batch.
- **Negative-cache non-deployed chequebooks** — bounded LRU with a TTL,
  the structure the owner cache grew in §16.2.
- **Rate-limit per account.** **`src/ratelimit.rs` cannot be reused** — it
  is a per-peer *outbound libp2p dial* GCRA pacer that parks rather than
  refuses (`src/ratelimit.rs:1-30`), with no inbound, per-account or HTTP
  concept. Stage 1 needs a new inbound limiter, also covering
  `/v1/challenge`.

**On step 2 — this is a validity check, not a malleability nicety.**
`ERC20SimpleSwap.recoverEIP712` calls `ECDSA.recover` from
`@openzeppelin/contracts/cryptography/ECDSA.sol` at `^3.4.1-solc-0.7-2`
(the repo's `package.json`), which is unconditionally strict:

```solidity
require(uint256(s) <= 0x7FFF…5D576E7357A4501DDFE92F46681B20A0, "ECDSA: invalid signature 's' value");
require(v == 27 || v == 28, "ECDSA: invalid signature 'v' value");
```

plus a 65-byte length check and a zero-address check. `alloy` recovers
high-`s` and `v ∈ {0,1}` happily, so **a client can issue cheques that
verify off-chain, buy service, and revert at cashout** — free relay, with
the relay's own acceptance as the evidence it was paid. OZ's comment notes
the alternative of rewriting as `(n − s, v^1)`, but there is no reason to
accept a client that cannot produce a canonical signature, and `alloy`
always does, so rejection costs honest clients nothing.

### 11.7 MEDIUM — hedging costs money (introduced)

The scheduler hedges stragglers to a rank-#2 lane (design §7). Both relays
receive the bytes, so both bill. The recent-ack cache does not absorb it:
`push.recent` is populated only **after the whole batch drains**
(`src/pusher.rs:1050-1065`), not in the per-chunk callback (`:1000-1025`),
so two concurrent POSTs containing the same address — including the
design's own *"re-POST unacked frames"* retry model (design §3) — are not
deduped even on the same relay.

Under §8 this is not a dispute: the client knows it sent those bytes
twice, and it did. **`hedge_fraction` becomes an economic parameter, not
just a latency one**, and clients should lower it against metered lanes.

### 11.8 MEDIUM — mixed-account batches bypass admission (introduced)

`run_push` handles frames from different batches with different owners in
one POST (`src/pusher.rs:905-925`), while §7.2's admission necessarily
picks one account. Prefix one frame from a good-standing account and fill
the remaining 511 from a 402'd account: admission passes, billing lands on
the wrong account. Closed by §6's one-batch-per-request rule.

### 11.9 LOW

| Threat | Assessment |
|---|---|
| Cross-relay cheque replay | Impossible: `beneficiary` is inside the signed EIP-712 struct. |
| Cross-chain replay | Impossible: `chainId` is in the domain separator; the relay pins its own. |
| Reorg invalidating `deployedContracts`/`liquidBalanceFor` | Negligible on Gnosis at these values; re-verified at cashout. |
| Paying off someone else's debt | Requires their chequebook key. Not a threat. |
| Price change mid-flight | Bill at the signed quote in force when the work was done; `quote_valid_secs` must exceed one settlement period (§10.1's sizing gives 24 h against a ~32 MiB period). |
| `/v1/account` as a volume/targeting oracle | Closed by requiring the challenge header (§7). |
| Challenge replay inside its own window | Bounded by the reservation (§7.2), a 300 s `challenge_ttl_secs`, and origin binding. Only the relay sees the header over TLS, so it must never be logged or echoed back. |
| Client under-reports bytes | Not possible. The relay counts what it received; `Content-Length` is a commitment the client made before the relay did any work. |
| Client disputes the invoice | Nothing to dispute — §8.4. |

## 12. Client scheduler integration

- `LaneInfo` (`src/pushsched.rs:101-112`) gains `price_plur_per_kib` and
  `mode`. All five existing fields are already `Option`, so parsing is
  free — but *scheduling* is not: `weight()` (`:257-278`) multiplies
  `rate × budget × concurrency` against a `MIN_WEIGHT` floor (`:65-68`),
  and an unknown price has no safe default. Treating it as free prefers
  unadvertised lanes; treating it as expensive pushes warming lanes under
  `MIN_WEIGHT`, where they can never revise their EWMA — the exact failure
  `MIN_WEIGHT` exists to prevent. Probably "unknown price ⇒ treat as the
  median of known lanes".
- **A 402 needs its own outcome.** `BatchOutcome` is
  `Answered | Failed(String)` (`:304-310`), so a 402 maps to `Failed` →
  `fail_streak++` → `Backoff` → `Retired` after 5 doublings (`:60-63`,
  `:88-91`). "Pay, then retry" would cost lane health on every routine
  settlement and retire a healthy lane mid-upload. Add
  `BatchOutcome::PaymentRequired`, which pauses the lane without touching
  the streak.
- **"Cannot pay" needs a non-terminal ineligible state.** `eligible()`
  (`:228-234`) is a pure function of `LaneHealth`, and the only ineligible
  terminal state is `Retired`, which is permanent for the run — wrong for
  "temporarily out of chequebook balance".
- **POST sizing must respect `max_outstanding_plur`.** The challenge
  returns the cap; the client sizes its body to fit rather than
  discovering the ceiling as a 402 (§7.2).
- Lower `hedge_fraction` against metered lanes (§11.7).
- Lane weighting should prefer `open` lanes when both are eligible and the
  client has no chequebook — otherwise a browser client with no payment
  path spends its first POST discovering a 402.
- **Lane health is the client's protection**, per §2. A lane that takes
  bytes and delivers poorly shows up in the existing EWMA and gets
  deweighted. No new mechanism.

## 13. Rejected alternatives

**Billing per verified pushsync receipt.** The previous design. Rejected
in §8: it makes a third party's signature into a billing input, which
forces a staking-registry anchor, a set-valued invoice, a sampled
retrieval audit, and a shared predicate module that must not drift between
the parties — and after all of it, a receipt still carries no freshness,
so a relay could replay one for content already in the swarm and no
off-chain check could tell. Bytes-admitted deletes the input and the
entire apparatus with it.

**Per-chunk / per-frame cheques.** §8.3. Serial by construction; kills
multi-lane pipelining.

**Billing per ack.** Every field of an ack is a relay assertion
(`src/pusher.rs:1005-1020`). Under §2's trust model this is *nearly*
acceptable — but bytes-admitted is strictly better at the same cost, since
the client can verify it without trusting anything.

**Relay earns like a bee forwarder.** Bee's ledger does pay forwarders — a
forwarder earns `(PO_next − PO_self) × 10 000` per chunk — but cheques are
issued *only* against `originatedBalance`
(`bee/pkg/accounting/accounting.go:472-484`). Non-originated debt settles
purely in free, rate-capped refreshments, so the spread is never
monetised.

**Postage in kind** (client stamps chunks the relay names). Pays in
storage for a service whose cost is bandwidth. Cute, weak.

**Direct on-chain BZZ prepay.** Simpler — no chequebook deployment — but
gas on every top-up and no off-chain micropayments. Kept as a fallback if
chequebook onboarding proves fatal in the browser.

**A shared multi-tenant escrow contract.** Would remove per-user chequebook
deployment: one contract, many depositors, cumulative vouchers to any
beneficiary. Attractive UX, but a new contract to write, audit and
maintain, forfeiting reuse of an audited deployment. Not worth it unless
per-user deployment measurably kills conversion.

**Cheque-as-credential, never cashed.** The relay accepts cheques purely
as funded, non-replayable proof of identity and never cashes them. Zero
cashout machinery, zero gas, no §11.2 exposure, no §9.3 profitability
problem — and it subsumes `--push-challenge`. The cost is that it prices
nothing: it gates abuse but does not fund the dedicated egress IP §1 says
is actually scarce. Kept as the fallback if Stage 0 shows consumption too
thin to bother metering.

## 14. Staged plan

**Stage 0 — metering instrument, zero protocol change. Shipped:
`src/meter.rs`.** Shadow accounting in the relay: per-`(owner, batch)`
bytes admitted, what they would owe at §9.2's candidate price, and the
credit line §10.3 would have granted each batch. Nothing is billed, no
request is refused, and no client-visible behaviour changes.

Where to read it:

- **`GET /v1/status` → `meter`** — aggregates only. Accounts and batches
  seen, KiB admitted and deduped, total owed in PLUR and USD, how many
  accounts would reach one settlement or the cashout threshold, the
  observed egress multiplier, and the credit-line distribution. Names
  nobody, so it stays public alongside the `bytes_pushed` total already
  published there.
- **`GET /v1/meter`** — per-account and per-batch rows. **Open by default**;
  set `HOVERFLY_PUSH_METER_TOKEN` to require an `Authorization: Bearer`
  header. Everything in it derives from state that is already public —
  batch owners and balances are on-chain and enumerable from
  `BatchCreated`, and the stamp on every relayed chunk names its batch,
  which retrieval hands back (§2) — so it adds only relay attribution and
  timing.

  **This changes at Stage 1, for a reason worth stating precisely.** §7
  authenticates `/v1/account` on two grounds, and only the second is load
  bearing: "per-identity volume oracle" is weak against a network where
  stamps are public anyway, but "targeting oracle for tipping a victim into
  402 at a chosen moment" is real — knowing an account's *outstanding*
  balance lets an attacker time a stamp replay (§11.1) to break a victim's
  upload at a chosen instant. That is an active attack enabler, not a
  privacy leak, and it does not exist in Stage 0 because there is no 402
  and no cap enforcement. Do not carry the Stage 1 conclusion backwards.

Three properties worth knowing when reading the output:

- **Costs no extra RPC.** `resolve_owner` already reads both `read_batch`
  and `read_remaining_balance` to check for expiry, so the batch's total
  value (`remainingBalance × 2^depth`) simply rides along on the cached
  success rather than being discarded.
- **Costs one lock per POST**, not per frame: a request accumulates into a
  stack-local `PostTally` and merges once at completion.
- **Bounded and in-memory.** 4 096 `(owner, batch)` rows with FIFO
  eviction, for the same reason the owner cache is bounded (§16.2) — the
  key is attacker-chosen. Evicted rows keep contributing to the totals, so
  headline volume stays honest; only their detail is lost. State resets on
  restart, which biases "do accounts return?" downward — check
  `window_secs` before drawing conclusions.

**What gates Stage 1:** the **distribution of batch remaining value across
accounts**, reported as `credit.batches_below_one_full_post` and the
`credit_kib` percentiles. It calibrates `credit_ratio` (§10.3) —
specifically, what fraction of real users would be capped below the global
ceiling, and whether §7.2's POST-sizing interaction bites in practice.

Stage 0 was also meant to settle §9.1's cost basis, which the doc *models*
rather than measures: `egress.attempts_per_frame` against the modelled
3.45. **It does not, and the claim that justified it was wrong.** The
counter was believed to see every per-stream attempt including losing
racers; it is bumped after the await inside a future the dispatcher
cancels, so it sees completions only. §9.1 has the detail. This gate is
**not met** and needs the counter moved to dispatch before any repricing.

*(The previous design had four gating measurements including a kill
criterion — the staked fraction of receipt signers, which could have
vetoed metering outright. Bytes-admitted removes the dependency.)*

**Stage 1 — the relay can be paid (native client only), soft mode.**
**Relay side shipped.** Enabled with `--meter --origin <host> --beneficiary
<0x…> --state-dir <dir>`; without `--meter` nothing below is reachable and
the relay behaves exactly as it does today. Modules: `src/ledger.rs`,
`src/metered.rs`, `src/inbound_limit.rs`, plus cheque recovery in
`src/signer.rs`, a `SignedCheque` decoder in `src/protocols/swap.rs` and
chequebook bindings in `src/batch.rs`. Endpoints: `GET /v1/challenge`,
`GET /v1/account`, `POST /v1/pay`, and metered admission on
`POST /v1/push`.

Those four sit behind the `pusher` cargo feature, which exists to pull in
hyper — it is the *relay*. The shared and client-side pieces
(`src/challenge.rs`, `src/meter.rs`, `src/payer.rs`) deliberately do not:
a client that pays a metered relay needs the challenge wire format, the
pricing arithmetic and the payer, but no server. `challenge.rs` owns the
whole challenge protocol including the `x-hoverfly-challenge` codec, so
the two ends cannot drift on a format only one of them defines.

**Client side shipped** (`src/payer.rs`): signed-quote verification with
lane pinning on `(url, node_eth_address, beneficiary)`, challenge parsing
and signing, POST sizing against the returned cap, and local `owed`
tracking computed from bytes sent. `BatchOutcome::PaymentRequired` and a
non-terminal `LaneHealth::Unfunded` are in `src/pushsched.rs`, and
`src/cheques.rs` gained `total_issued` plus a `relay:` key namespace.

**Chequebook deployment is an explicit user action, never automatic.** It
belongs in its own command (`hoverfly chequebook deploy`, alongside
`batch create`), not on the upload path. Deploying a contract is
irreversible and spends real funds, so an upload that silently deployed one
because some lane quoted a price would fire on the *first* metered lane a
user ever met — before they had decided they wanted to pay at all. This is
the same shape §14 Stage 3 gives the browser, where the wallet deploys the
chequebook as a deliberate opt-in. hoverfly has no deploy path today: it
consumes a chequebook via `--chequebook` and documents "already deployed by
bee's official factory" as a precondition.

Hard mode is shipped: the driver settles on the window and on 402, calls
`Scheduler::fund_lane` after an accepted cheque, reconciles carried debt
via `/v1/account` when a 402 cannot be paid from local books (§17.1), and
the `/v1/pay` chain reads (`deployedContracts`, `issuer`,
`liquidBalanceFor`, `paidOut`, `bounced`) are exercised against Gnosis
mainnet (§14 deployment notes). What remains is Stage 3 (erasure-aware
completion) and the per-lane pin UX (`--lane-pin`; unpinned lanes are
TOFU-trusted with a warning).


- Byte accounting per account with a **body-bounded reservation** (§7.2,
  §10.2), durably persisted except `reserved` (§11.4).
- EIP-712 **recovery** in `src/signer.rs`, mirroring `sign_cheque`
  (`:309-337`). The `sol!` `Cheque` type exists at `:21-27`; the
  `Eip712Domain` is built inline at `:321-327` and needs extracting to be
  shared.
- `SignedCheque` JSON **decoder** in `src/protocols/swap.rs` — only the
  encoder exists (`encode_signed_cheque_json`, `:84-106`). It must reject
  non-canonical signatures at parse time (§11.6): it is the one place
  every cheque passes through.
- `ERC20SimpleSwap` + factory `sol!` bindings — `issuer()`,
  `liquidBalanceFor(address)`, `paidOut(address)`, `bounced()`,
  `deployedContracts(address)`. `EthRpc::call_view` (`src/batch.rs:726`)
  is **private**, so these either live in `batch.rs` or it gains
  visibility.
- **Re-key `src/cheques.rs` on `(chequebook, beneficiary)`** instead of
  peer overlay (`:64-76`), and add `total_issued` (§8.3).
- Stateless MAC challenge with standing baked in, over a length-prefixed
  domain-tagged preimage compared in constant time; EIP-712
  `PushChallenge` verification; `relay_secret` persisted with the ledger
  (§7.2). CORS `allow-headers` update (`src/pusher.rs:468-486`).
- Signed quote carrying `node_eth_address`, `overlay_nonce` and `origin`
  (§7.3); a new inbound per-account rate limiter (§11.6), also covering
  `/v1/challenge` and `/v1/pay`.
- `/v1/pay` hardening: challenge header required, `owed == 0` refused
  before parsing, non-deployed chequebooks negative-cached (§11.6).
- One-**batch**-per-request enforcement; batch *standing* reads with a TTL
  on the owner cache (§6); credit line derivation (§10.3).
- Metered retry policy (§11.5).
- Forward the pushsync receipt into the ack as **telemetry** (§2). Not
  billing-relevant, but independently the first cryptographic evidence a
  relay client has ever had, and it feeds lane weighting.

Pusher flags: `--meter`, `--origin` (**required under `--meter`**; §7.2,
§11.1), `--beneficiary`, `--price-plur-per-kib`, `--settle-every-plur`,
`--max-outstanding-plur`, `--min-cheque-plur`, `--credit-ratio`,
`--state-dir`.

Client: the native path already has `--chequebook` / `--cheques-file` /
`--chequebook-chain-id`, so it needs the 402 handler, the challenge
signature, POST sizing against the returned cap, lane pinning on
`(url, node_eth_address, beneficiary)` (§7.3), and `total_issued` (§8.3).

**Stage 2 — hard mode and cashout.** 402 enforcement; scheduler changes
(§12).

**`hoverfly cashout` shipped**, run from a machine holding the beneficiary
key, never the relay. It reads the relay's ledger, prices each held cheque
on-chain, and presents the ones worth collecting. Two things it forced:

- **The ledger has to keep the signature.** The first cut stored only the
  cumulative, which made the whole thing a record of money that could not
  be collected — the relay could prove nothing about a number it held
  alone. On-disk format is now version 2; a version 1 entry loads (losing
  its cumulative would let the client replay, §11.4) but is skipped at
  cashout rather than submitted for the contract to reject.
- **Cashing is naturally idempotent**, because the contract tracks
  `paidOut(beneficiary)`. A repeated run sees `unclaimed 0` and presents
  nothing, which matters for a command that will be run on a timer.

`--min-amount` defaults to 0.25 BZZ (§9.3's threshold). The reasoning it
was given — cashing costs ~300k gas whatever the amount, so a smaller
cheque is worth less than collecting it — does not survive §9.3's measured
fees; at ~`1e-10` xDAI the amount that is *not* worth collecting is far
below any cheque this system will produce. Keep the default as batching
convenience, and see §9.3 on deriving it from live gas. Verified on Gnosis
mainnet — a 145,920,000,000 PLUR cheque presented,
`paidOut` moved by exactly that, and the beneficiary's BZZ balance moved by
exactly that. Cashout reads `bounced` and
`liquidBalanceFor` rather than `balance` (§11.2), and optionally offers
**secured mode** for high-volume accounts: the beneficiary signs a
`setCustomHardDepositTimeout` for that client's chequebook, the client
calls `increaseHardDeposit`, and the cheque stops being an unsecured
claim. Interactive by nature — it needs the cold key once per client
chequebook — so it is an account-tier feature, not a default.

**Stage 3 — browser.** Deferred. Unblockers: export `sign_cheque` through
`#[wasm_bindgen]` (it already compiles on wasm — `src/signer.rs` has no
`cfg` gates — it is simply not bound in `src/wasm.rs`); an IndexedDB or
localStorage cumulative store, anticipated at `src/cheques.rs:24-26`; and
an opt-in dApp flow where the wallet deploys a chequebook with
`issuer = sessionKey` and funds it — two transactions on top of today's
approve + `createBatch`, ≈ $0.001 of Gnosis gas, one-time per user and
reused across every upload and lane. The dApp's four public lanes stay in
`open` mode throughout, so nothing here is on the settlement path at all.

One Stage 3 hazard Stage 1 does not have: **a session-key chequebook can
strand funds permanently.** `withdraw()` is issuer-only, and the issuer
here is a key living in localStorage. Clearing site data destroys the only
key that can recover the remaining balance. Fund in small increments, warn
on deposit, and offer an explicit "drain chequebook" action before the key
is discarded. A wallet-owned chequebook with the session key as a mere
*signer* would avoid this, but SimpleSwap has no such split.

## 15. Residual risks and open questions

Carried knowingly:

- **§11.2** — cheques are unsecured claims, bounded by the per-account cap.
  Hard deposits work but are inert as bee deploys them; secured mode costs
  a cold-key signature per client chequebook.
- **§9.3** — the cashout threshold is a hardcoded constant sized against a
  gas cost that no longer holds. At today's Gnosis prices it is a batching
  convenience, not a break-even, and a gas spike moves the real floor
  without moving the constant. Deriving it from `eth_gasPrice` at cashout
  time is the fix; until then the number is stale in whichever direction
  gas has drifted.
- **§11.3** — aggregate exposure across beneficiaries is invisible to the
  client until `total_issued` ships.
- **§11.5** — griefing by aiming at badly-covered arcs still forces the
  relay to spend more than the attacker pays, even though the attacker now
  pays. Bounded by the same attempt caps as open mode (no metered-specific
  cap yet — see §11.5), not eliminated; the attacker-side bound is the
  credit line.
- **A relay can take payment and drop chunks.** Out of scope for
  cryptographic treatment by §2. What bounds it is that the client pinned
  the lane, caps its exposure at one credit line, and deweights a lane
  whose acks do not arrive — so the loss is at most `max_outstanding` and
  is detected within one settlement window. Adequate for a lane a client
  chose; **not** a proof of delivery, which pushsync cannot give us.

Open:

- What would it take to open the relay set? The honest answer is a
  freshness-bearing proof of delivery, which pushsync does not provide —
  the storer signs the bare chunk address
  (`bee/pkg/pushsync/pushsync.go:277`), so a receipt is valid forever, for
  everybody, and a relay can replay one for content already in the swarm.
  Two upstream asks would fix it, in increasing order of difficulty:
  **(a)** a read-only "do you hold `(address, batch)`?" query — bee's
  reserve is *already* indexed exactly that way
  (`BatchRadiusItem.ID() = BatchID ‖ Bin ‖ Address ‖ StampHash`,
  `pkg/storer/internal/reserve/items.go:35-37`), so this is a lookup on an
  existing index; **(b)** having the storer sign
  `keccak(chunk_address ‖ stamp_hash)` instead of the bare address. Both
  have value well beyond metering — any uploader could prove *its own*
  stamp reached a neighbourhood — and (a) is a much easier sell.
- Price discovery across a federation: fixed per-operator quotes, or
  something the client aggregates?
- Should a relay accept cheques from a chequebook whose `issuer()` is not
  the batch owner, via a signed authorization (§6)? Needed by anyone
  uploading under multiple batch owners.
- Is the batch owner the right account key at all, given §6's TTL problem
  and the fact that batches expire?
- Is `credit_ratio = 1000` (§10.3) right? Chosen for a comfortable margin,
  not derived. Stage 0's batch-value distribution should justify it or
  move it.

## 16. Found during review: six live open-mode bugs (all fixed)

All independent of metering, all in code running in production. They are
recorded here rather than in a commit message because the design argument
keeps citing them: §6, §10.2 and §11.6 all describe relay behaviour these
fixes changed.

### 16.1 The recent-ack cache let one uploader substitute another's stamp

**Status: fixed** — `RecentAcks` is now keyed on `(addr, batch_id)`
(`src/pusher.rs:286`, applied at `:928-948` and `:1050-1065`).

Dedup was keyed on `chunk.addr` alone. On a hit the frame is acked
`{"s":"ok"}` and is **never added to `accepted`** — the submitted stamp
never reaches the swarm. Swarm addresses are content-derived, so two
uploaders of the same bytes collide by construction.

Attack: push chunk X stamped with a dust batch expiring tomorrow. Within
`RECENT_ACK_TTL_SECS = 120` (`:129`) the victim pushes X stamped with its
year-long batch, is told `ok`, and the chunk lives under the attacker's
dying stamp. When that batch expires the chunk is garbage-collected and
the victim's manifest 404s. The victim has a successful upload record and
no way to know. The same thing happens *accidentally* between two honest
users uploading the same file within 120 s on one lane.

Two notes on the applied fix, neither a defect today:

- The completion path resolves the batch via `batch_of.get(a)` with an
  all-zero sentinel fallback (`:1050-1065`). No admitted chunk currently
  reaches it unmapped, but a sentinel that could in principle alias a
  batch id is worth replacing with an `if let Some` that skips caching.
- If one POST carries the same address under two different batches, only
  the last-inserted mapping is cached. That under-dedups rather than
  mis-dedups — the safe direction — and metered mode forbids the case
  outright under §6's one-batch-per-request rule.

### 16.2 `/v1/push` was an unauthenticated RPC amplifier

**Status: fixed.** `resolve_owner` cached only *successes*, in an unbounded
`HashMap`, with no per-request budget. A batch id that failed to resolve —
not found, or zero remaining balance — was re-resolved on every mention,
so one anonymous POST of `PUSH_BATCH_MAX` frames naming bogus batches
became that many serial `eth_call`s against the operator's RPC endpoint.
Nothing about the request needed to be valid: the amplification happens
*before* any push work. `EthRpc::new` made it worse by building a fresh
`reqwest::Client` per read, so every call also paid a new connection pool
and TLS handshake.

Fixed by a bounded `OwnerCache` (`src/pusher.rs:181-239`, `:1106`) that
caches definitive rejections under a shorter TTL than successes but never
caches transport errors — an RPC blip must not blacklist a live batch — is
capped at 4 096 entries with FIFO eviction, and by a per-request budget of
`PUSH_MAX_BATCH_LOOKUPS = 8` distinct lookups. `EthRpc` now shares one
process-wide client (`src/batch.rs`).

This is the same defect §11.6 identifies in metered `/v1/pay`, which is
why that section stopped treating cheapest-first ordering as a bound.

### 16.3 The accept loop had no connection limit

**Status: fixed.** The loop spawned per connection with no semaphore and
no cap anywhere, despite design §3 listing one as table stakes. Now a
`PUSH_MAX_CONNS_DEFAULT = 256` semaphore permit is acquired **before**
`accept()` and held for the connection's life (`src/pusher.rs:377-415`,
`HOVERFLY_PUSH_MAX_CONNS` to override). Acquiring before accepting is what
applies backpressure to the kernel queue instead of admitting everything
and queueing internally.

§10.2's reservation argument is written against the fixed behaviour: 256
is a bound, and it is still 4× `max_outstanding_plur`.

### 16.4 One transient accept error killed the relay

**Status: fixed.** `listener.accept().await?` propagated out of `run`, so a
single `EMFILE` or `ECONNABORTED` — both transient and both routine under
load — terminated the process. The loop now logs, backs off exponentially
to `ACCEPT_BACKOFF_MAX_MS = 1000`, and continues.

### 16.5 There were no HTTP timeouts at all

**Status: fixed.** The pre-existing comment said hyper's defaults were
fine. They are not, and the reason is worth recording: `header_read_timeout`
is **silently inert unless a timer is installed**. Without `.timer(...)`
hyper's `Time` is `Empty`, its `check()` returns `None`, and the
configured timeout never fires — so the code read as protected while
accepting connections that could hold a slot forever sending one header
byte at a time.

Now `TokioTimer` is installed, `HEADER_READ_TIMEOUT_SECS = 30` applies,
and the `/v1/push` body read is wrapped in a
`PUSH_BODY_READ_TIMEOUT_SECS = 120` `tokio::time::timeout` returning
`408 Request Timeout`. Combined with §16.3's cap, a slowloris now costs an
attacker 256 connections for 30 seconds rather than indefinitely.

### 16.6 Pushsync receipt addresses were never checked

**Status: fixed** (`src/protocols/pushsync.rs:142-148`, with regression
tests).

`receipt.address` was copied straight off the wire and never compared to
the address that was pushed. Two things followed, and any peer in the pool
could reach both — pool membership comes from hive gossip and the seed
list, so it is not a trusted set:

- **Remote panic.** Callers build a `[u8; 32]` from it with
  `copy_from_slice` (`src/client.rs:5380`, `:5398`), which panics on any
  other length. A 0- or 33-byte address unwound the push task.
- **Address substitution.** A peer could accept the Delivery, store
  nothing, and sign a receipt for some *other* address deep inside its own
  neighbourhood. `is_shallow` and the `po` computation both read
  `r.address`, so the forged receipt looked like a perfect deep delivery
  and the chunk was acked `ok` having never been stored.

Receipts no longer carry money under this design, but they still carry the
`po` and shallow signals the client schedules on, so a peer able to forge
them could steer traffic. Checking at the protocol boundary means every
`PushsyncReceipt` in the codebase carries exactly the 32 bytes that were
pushed.

## 17. Found by running a metered relay: six bugs (all fixed)

None of these is reachable from a single upload against a fresh relay,
which is why all six survived the test suite and the Stage 1 round-trip.
They need a relay whose ledger *persists across client runs* — the shipped
configuration — enough concurrency to have several POSTs on the wire at
once, and a batch that has been spent down far enough for its credit line
to bind.

The last of those is the one to take seriously as a *method* point: §17.3
is not a coding mistake but an invariant checked against the wrong
quantity, and nothing short of running a real batch until its value
decayed would have surfaced it.

### 17.1 Debt the relay carried across sessions could not be paid

**Status: fixed** (`LaneAccount::adopt_relay_debt`, `LanePayer::reconcile`,
with regression tests).

§10.2's dust floor guarantees a run ends owing something: the residual
below `min_cheque_plur` is left unpaid because a cheque for it would be
refused. The relay is right to keep counting that against the credit line
— forgiving it would make "stay under the floor" a way to be served for
free. But the client's books are per-process, so the *next* run starts
believing it owes nothing, and the relay's `owed` only ever grows.

Once the carry crosses `max_outstanding_plur` the account is refused on
its first POST, and the refusal is unpayable: `next_cumulative()` computes
the cheque from the client's own `owed`, which is zero. Observed live as
a second upload failing 151/151 against a relay carrying 290,400,000,000
PLUR. With the shipped defaults the per-run residual is under 3.9e12
against a 62.2e12 cap, so it takes roughly sixteen runs rather than two —
a slow-motion deadlock, not a corner case.

The fix is to ask rather than to remember: `GET /v1/account` already
reports the relay's own figure, so a 402 the client cannot pay triggers a
reconcile and it pays what the relay says it owes. Three things about
which number, each of which was wrong in a draft:

- **`owed`, not the `outstanding_plur` in the 402 body.** `reserve()`
  adds the reservation *before* computing what it reports, so the body's
  figure includes the request just refused. Adopting it over-pays by
  exactly that body and the next cheque bounces as an overpayment.
- **Reservations excluded on our side too**, for the same reason: bytes
  still in flight are already held in `pending_plur` and would be billed
  twice when those POSTs land. Under-counting is safe and self-correcting;
  over-counting is a refused cheque.
- **Bounded by the quote's ceiling, not by the per-batch credit line — and
  then by the chequebook balance.** The line is the wrong bound: it shrinks
  as the batch is spent down, so it falls below debt properly incurred when
  the batch was worth more, and rejecting on that basis refuses a real bill
  and preserves the deadlock. `max_outstanding_plur` from the *signed* quote
  is the right one: admission refuses above the per-batch cap, and every cap
  is `min(value / ratio, ceiling)`, so a figure above the ceiling describes
  debt that cannot have been incurred. The balance check stays as a second,
  looser gate — `settle` enforces it exactly across all lanes (§8.3), and
  stating it here turns a confusing failure at signing time into a legible
  one at reconcile time.

This makes the client trust the relay's arithmetic about its own
receivable, but only within the credit that relay granted — which is what
pinning buys (§2). The first version bounded on the chequebook balance
alone, which would let any lane a client pointed at name the whole balance
and be signed for it. That is not something §2 grants: a relay is pinned,
not vetted, and there is no list to be thrown off.

The alternative — persisting the
residual client-side — keeps better books but has no recovery when that
state is lost, and a client permanently locked out of a relay with no way
to clear it is the worse failure.

### 17.2 The headroom guard admitted a frame, then sent a batch

**Status: fixed** (`LanePayer::has_headroom` prices a real POST;
`dispatch_ok` re-evaluated per dispatch).

The pre-dispatch guard asked whether one more *frame* fit inside the
credit line and then dispatched a full `batch_max` POST, and its answer
was computed once for an unbounded run of dispatches. Several concurrent
POSTs were each waved through against the same headroom; the relay
reserved every one of them, their sum crossed the line, and it answered
402 to a client whose own books said it had room.

That refusal is the unpayable kind — the bytes are in flight, so nothing
is owed yet and settling changes nothing — and the batch returns having
spent an attempt per chunk, which is why handing batches back was
measured to make things worse rather than better. §7.2's whole point is
that the client sizes to fit instead of discovering the ceiling as a 402.

The guard now prices the POST the scheduler will actually build. Where the
line holds only one POST this serialises the lane, which is the honest
answer: a credit line that fits 1.8 POSTs cannot have eight in flight.
Measured on a hard-mode relay, per-upload 402s went 11 → 1 and unpayable
refusals 6 → 0; the one remaining 402 is §17.1's carried debt, paid on
reconcile.

`LaneAccount::max_body_bytes` had the same confusion — sizing against
`owed` while `has_headroom` and `would_exceed` both bind on `outstanding`.
It is only reached from tests today, but it would have reintroduced the
bug at its next caller.

The first attempt at this fix gated dispatch on whether a *full* POST
would fit, which is worse: see §17.3, which it caused.

### 17.3 §10.1's invariant does not hold at the line that binds

**Status: fixed** (`Params::effective`, applied on both sides, with tests).

`Params::validate` checks `min_cheque <= settle_every < max_outstanding`.
But `max_outstanding_plur` is only the *ceiling* on a credit line; the
line that actually binds an account is per batch,
`min(remaining_value / credit_ratio, ceiling)` (§10.3). For any batch
whose remaining value is under `min_cheque_plur * credit_ratio` — about
0.39 BZZ at the shipped defaults — the configured floor sits above
everything that account can ever owe, and the invariant quietly stops
holding.

What follows is a permanent refusal. The account accrues to its cap, is
answered 402, and cannot write a cheque large enough to be accepted:
`next_cumulative()` returns `None` below the floor, and `/v1/pay` rejects
anything below it as dust. Nothing on either side is broken or dishonest
— the parameters simply cannot be satisfied. Observed live at a credit
line of 679,783,122,862 against a 3,900,000,000,000 floor, 5.7× short,
which halted an upload at 16 of 219 chunks with the relay reporting
`err=0`.

This is exactly §10.3's small batch — the case the value-scaled credit
line exists to keep serving — so refusing it defeats the purpose of
scaling the line at all.

The thresholds are now resolved against the line before they are applied:
settle at half of it, and never demand a cheque larger than that. Both
sides derive this from `(params, cap)`, and `cap` is already in the
challenge, so they agree without exchanging anything new. A generous line
keeps the configured values unchanged; only a line that cannot reach them
scales them down.

Accepting a smaller cheque costs the relay nothing, which is what makes
this safe: cheques are cumulative, so a small one now does not force a
small cash-out later, and `hoverfly cashout --min-amount` already declines
to spend gas on a claim that is not worth collecting. The dust floor
belongs at redemption, where the gas is, not at acceptance.

### 17.4 A lane refused for bytes in flight was parked for good

**Status: fixed** (`unpayable_402` in the driver).

The relay refuses on `owed + reserved`, but only `owed` is payable —
reservations are bodies it is still reading. A lane can therefore be over
its line while its *debt* is under the dust floor, and that is neither a
disagreement nor something a cheque fixes: those bytes simply have to
land.

A 402 marks the lane `Unfunded`, and only a successful settle re-funds it
(§12). With nothing payable there is no settle, so the lane stayed parked
and the upload ended with chunks pending and the relay reporting `err=0` —
2 MiB stopping at 311 of 567 frames. The bigger the upload, the more
certain this is, because more POSTs are in flight when the line fills.

The driver now distinguishes the two cases. Bytes in flight means busy:
re-fund the lane and let it resume when they clear. Nothing in flight and
nothing payable is the genuine disagreement, and still warns. Re-funding
cannot spin, because `has_headroom` binds on `outstanding` and so
dispatches nothing until the in-flight bytes actually clear.

The same run surfaced the mirror of §17.1 in the reconcile itself:
adopting the relay's `owed` while a POST it had already booked was still
`pending` locally counted that body twice once the response closed, and
the cheque was refused as an overpayment (`credits 535680000000 but only
510240000000 is owed`). Reconciliation now deducts what is in flight.
Under-adopting is safe — the remainder is still owed and the next settle
collects it.

### 17.5 A broken response stream made every later cheque bounce

**Status: fixed** (`LaneAccount::sync_relay_debt`, one bounded re-present
in `LanePayer::pay`).

§7.3's ack-tail cuts both ways. A POST whose response stream breaks was
still *read*, so the client bills it — but if the relay's task is
cancelled before it commits, the `Admitted` guard releases the reservation
and it books nothing. The client cannot tell that case from a clean one,
so it over-counts.

The overshoot is not self-correcting: it rides on the cumulative, so every
later cheque carries it and is refused for the same reason, and the lane
never settles again. Seen the first time the relay was reached through a
real reverse proxy — two broken streams, then `cheque credits
212640000000 but only 148800000000 is owed`.

The relay is the party deciding what it will accept, so the client yields
to it: on a rejection naming a smaller figure, re-read `/v1/account`, take
that number, and re-present once. Nothing was issued, so there is no
cumulative to be inconsistent with. The retry is bounded to a single
attempt, so a relay that keeps refusing cannot loop the client.

This is the same yielding as §17.1 in the opposite direction, and
`forgive_phantom_debt` was already the total-loss case of it.

### 17.6 The first POST of a run was sized before the debt was known

**Status: fixed** (reconcile once per lane at setup).

§17.1 made carried debt *recoverable*, via a 402 the client answers by
reconciling. It did not stop the client from walking into it. A fresh
process starts believing it owes nothing, so it sizes its first POST
against the entire credit line while the relay is already holding part of
it — and is refused immediately.

Worse, the recovery could land in a hole: if the carried debt happens to
sit below the dust floor, the client reconciles, finds it cannot write an
acceptable cheque, and stops with the lane over its cap. Observed at 16 of
567 frames with 152,160,000,000 carried against a 416,771,800,039 line.

Reading `/v1/account` once per lane at setup costs one GET and makes every
subsequent size correct, so the refusal never happens. §17.1's path
remains as the recovery for debt that appears mid-run.

The same run showed that POST sizing has to be recomputed per *dispatch*
rather than per pass of the driver loop: the inner loop hands out several
assignments in a row, and a ceiling refreshed only on the outer pass sizes
the second and third of them as if each were alone on the lane.

After all six fixes, uploads of 128 KiB through 4 MiB against a hard-mode
relay complete every frame, with no unpayable refusals and no rejected
cheques:

| payload | frames acked | 402s | stuck | rejected cheques |
|--------:|-------------:|-----:|------:|-----------------:|
|  128 KiB |      43/43 |    0 |     0 |                0 |
|  256 KiB |      76/76 |    0 |     0 |                0 |
|  512 KiB |    151/151 |    0 |     0 |                0 |
|    1 MiB |    290/290 |    2 |     0 |                0 |
|    2 MiB |    567/567 |    2 |     0 |                0 |
|    4 MiB |  1122/1122 |    4 |     0 |                0 |

The remaining 402s are the intended kind: the line genuinely fills, the
client pays or waits, and the lane resumes.

Repeated over public HTTPS through a reverse proxy, with §17.6 in place so
the client knows its carried debt before sizing anything, the 402s go away
entirely — the client never reaches its cap because it never builds a body
that would cross it:

| run | payload | frames acked | 402s | rejected cheques |
|----:|--------:|-------------:|-----:|-----------------:|
|   1 |   2 MiB |      567/567 |    0 |                0 |
|   2 |   2 MiB |      567/567 |    0 |                0 |
|   3 |   2 MiB |      567/567 |    0 |                0 |

Each run settles to `owed: 0` on the relay, so the next carries nothing.
That is the intended steady state: 402 is the recovery path, not the
mechanism.
