---
marp: true
theme: default
paginate: true
header: 'Paying for relay — an incentive layer for hoverfly pushers'
---

<!-- This file is the source. `marp-cli` renders it to PDF as-is; the
     self-contained HTML deck is built with:
       python3 docs/deck/build.py docs/pusher-incentives-slides.md -o deck.html
     Directives (<!-- title -->, part:, eyebrow:, hazard) are documented
     in docs/deck/build.py.

     Keep slides sparse: a heading, ONE block (a short table, up to four
     bullets, or two short paragraphs), and ONE callout. The detail lives in
     docs/pusher-incentives.md.

     Headings name the mechanism and nothing else — "Trust model", not "Who
     has to trust whom". The claim about that mechanism goes in the body,
     where there is room to say it precisely. Eyebrows mark the act (the
     problem / theory / practice), so they never restate the heading. -->

<!-- title -->

# Paying for relay

## An incentive layer for hoverfly pushers, reusing parts of SWAP

*docs/pusher-incentives.md · one paid relay in production*

---

<!-- eyebrow: the problem -->

# Unpaid relay bandwidth

Upload directly and bee debits your own node for every chunk. Put a relay in the middle and that debt moves to it — the relay is the peer bee sees. The debt is real (pseudosettle pays it in time rather than money), so what a relay actually spends is bandwidth, and nothing prices that.

|  | open | metered |
|---|---|---|
| client → relay | nothing | 4.8e8 PLUR per KiB |
| relay → bee | time, not money | unchanged |

> A free tier allows a relay 70–100 GB of egress a month (a ceiling, not consumption). Burn all of it under metering and it bills **$0.35–0.51**.

---

<!-- eyebrow: theory -->

# Trust model

A relay is a standalone HTTP service — no registry, no list to get onto. Trust runs one way: the client checks a signed quote before sending a byte; the relay gets whoever shows up.

> So every defence here points from the relay at the client. The other direction gets no cryptography, only bounds: the client computes its own bill, and risks at most one credit limit per lane — about **$0.0024**.

---

<!-- eyebrow: theory -->

# The billing unit

```
owed = (KiB admitted − KiB served from cache) × price per KiB
```

> The client cannot lie about it. It produced the bytes; the relay counted them. Dedup hits (§8.2) bill at zero.

Bytes admitted, not delivery receipts. Billing per receipt meant trusting a **third party's signature**, which took five mechanisms to make safe. Changing the unit removed all five.

---

<!-- eyebrow: theory -->

# Admission control

The relay must accept or refuse **before** reading an upload — but at that moment it does not know whose account to check.

<!-- hazard -->
> Checking on every upload would mean 512 signature recoveries before it can answer at all. Cheap to attack, expensive to serve.

So the chain lookups happen **once**, when a slip is issued, and the credit limit is sealed into it. The batch owner signs it, so stolen stamps cannot bill their owner.

---

<!-- eyebrow: theory -->

# The credit limit

The cheapest live batch costs a fraction of a cent, so "owns a batch" proves nothing. The limit tracks what the batch is worth:

```
credit limit = min(batch's remaining value ÷ 1000, a global ceiling)
```

> An attacker gets back **at most a thousandth of what they funded**, and less once the ceiling binds. The ratio is what is fixed, so there is no cheap corner to aim at.

---

<!-- eyebrow: theory -->

# Settlement

A cheque is a running total: "you have now paid me *this much in total*".

- **Losing one costs nothing** — the next covers it
- **Old ones are worthless** — each must exceed the last
- **Gas is paid once per account** (one cumulative per chequebook), not per cheque

<!-- hazard -->
> Money set aside for an upload in progress must never be written to disk. No upload survives a restart, so nothing would ever release it.

---

<!-- eyebrow: practice -->

# Unit economics

Relaying earns **$0.02 per GiB** admitted (at $0.40/BZZ). On a host you already pay for, cashout gas is negligible — the two real cashouts used 75k/110k gas at ~1e-10 xDAI (assumes xDAI≈$1; Gnosis gas varies ~8× observed).

| | per month |
|---|---:|
| payload under a 2 TB egress cap | 503 GiB |
| billed at $0.02/GiB | **$10** |

> So the ceiling is the allowance, not the cost — and only on bandwidth nobody bills by the gigabyte. Billed per GB, the same traffic costs **$0.36 per GiB** against $0.02 of revenue, and that relay should run free.

---

<!-- eyebrow: practice -->

# Deployment

Paying is optional, and each relay sets its own mode.

| Relay | Client can pay | Client cannot |
|---|---|---|
| open | nothing billed | nothing billed |
| metered, soft | billed, settles | billed, served anyway |
| metered, hard | billed, settles | **dropped at startup** |

> Four open relays run on ephemeral free-tier hosts (disk wiped on restart) — and a relay that forgets what it is owed serves for free forever, which is why §5 requires durable state for metering. The browser app skips hard lanes: it can sign chunks, not cheques.

---

<!-- eyebrow: practice -->

# Bugs found in production

| § | Bug |
|---|---|
| 17.1 | Carried-over debt could not be paid |
| 17.2 | Headroom admitted a frame, then sent a batch |
| 17.3 | A rule checked against the wrong number |
| 17.4 | A client refused for bytes in flight parked the lane forever |
| 17.5 | One broken stream bounced every later cheque |
| 17.6 | The first POST was sized before the debt was known |

> No test suite reached any of them, and none is reachable from one upload against a fresh relay. Between them they needed debt surviving restarts, several POSTs in flight, and a batch spent down far enough to bind.

---

<!-- eyebrow: practice -->

# Results

Steady state over public HTTPS (post-§17 fixes): three runs of 2 MiB, 567/567 each, 0 refusals, 0 rejected cheques, each settling to zero. Earlier sizes still show intended 402s as the recovery path (1 MiB: 2, 2 MiB: 2, 4 MiB: 4 — see §17). Cheques cash from a separate machine — the relay must never hold that key.

| | to date (relay `owed_usd` + two `cashChequeBeneficiary` transfers) |
|---|---:|
| billed | $0.0003 |
| cashed on-chain | $0.00006 |
| paying clients | 1, and it was me |

> The mechanism works; nobody is paying it. The browser dApp is the only real traffic and it signs stamps, not cheques. Nothing yet stops a relay billing for chunks it drops.
