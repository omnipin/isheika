<img src="./logo.svg" width="75" height="75" alt="hoverfly logo" />

# hoverfly

Experimental [Swarm][swarm] light client. Upload and download files to decentralized storage natively and in a browser.

[swarm]: https://www.ethswarm.org/

## Features

- **Light node functionality.** End-to-end content upload and download.
- **Browser-friendly.** upload files from your browser using the [demo](https://hoverfly.bzz.link) and integrate into your web app with [`@omnipin/hoverfly`](https://www.npmjs.com/package/@omnipin/hoverfly) .
- **Collection support.** Upload, download and list content-addressable tarballs.
- **Erasure coding.** Reed–Solomon redundancy on both upload and download.
- **Onchain postage batch creation.** Buy storage straight from the CLI.
- **Multiple modes** Static commands for simplicity, daemon mode for warm connection pool, pusher nodes for splitting content signing and upload.
- **Cross-platform.** Compiles to WebAssembly, Linux x86/ARM, MacOS and FreeBSD.
- **Small size.** 5MB gzipped, 14MB unpacked x86 Linux binary.
- **CI-friendly.** ~400-500KB/s uploads in GitHub Actions.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/omnipin/hoverfly/main/install.sh | sh
```

### Specific version

```sh
curl -fsSL https://raw.githubusercontent.com/omnipin/hoverfly/main/install.sh | HOVERFLY_VERSION=v0.1.2 sh
```

### Build from source

```bash
cargo install --git https://github.com/omnipin/hoverfly
```

## Setup

### 1. Generate a key

Your secp256k1 private key (`--key` / `--identity`, 32 bytes hex) is
your long-lived signer. Bee uses the derived Ethereum address to
recognize you across reconnects, route cheques, and verify your
postage stamps.

```bash
cast wallet new
```

Save the printed `Private key` and `Address` — both are useful (the
key for `--key`/`--identity`, the address for funding xDAI + BZZ).

### 2. Generate a vanity overlay nonce

Your Swarm overlay is `keccak256(eth_addr ‖ network_id ‖ nonce)`. A
random nonce works, but most random overlays land in bee's already-full
low kademlia bins and get dropped right after the handshake. `hoverfly
vanity-overlay` searches for a nonce that puts you in deeper,
undersaturated bins instead. Anchoring against a few stable peers
(`--target-overlay`) roughly **doubles** upload throughput.

```bash
hoverfly vanity-overlay --key 0xYOUR_KEY --output overlay-nonce
```

One-time, CPU-bound (seconds to minutes). The resulting `overlay-nonce` is your Swarm identity together with `--key` — keep it.

### 3. Obtain xDAI + BZZ on Gnosis

The address from step 1 needs a little xDAI (for gas) and some BZZ (to fund the batch). The optional `bridge` command obtains both via [Relay](https://docs.relay.link) — for example, from USDC on Base:

```bash
hoverfly bridge --from-chain base --from-token USDC --amount 3 --to both --rpc-url https://mainnet.base.org --key 0xYOUR_KEY
```

`--from-token` takes a symbol (resolved to the canonical address automatically) or a raw `0x` address.

### 4. Create a postage batch

Once the address holds xDAI + BZZ:

```bash
hoverfly batch create --rpc-url https://rpc.gnosischain.com --key 0xYOUR_KEY --size 2GB --duration 30d
```

`--size` and `--duration` map to `--depth` and `--amount-per-chunk` via the same formulas as the [official postage stamp
calculator](https://docs.ethswarm.org/docs/develop/tools-and-features/buy-a-stamp-batch/#calculators).

The on-chain `BatchCreated` event takes 1-3 minutes to propagate to the bee nodes that'll accept your stamps. Poll [Swarmscan](https://swarmscan.io/) until it 200s:

```bash
curl -s "https://api.swarmscan.io/v1/postage/batches/<BATCH_ID>"
# 404 = network hasn't indexed it yet
# 200 with a JSON body = ready to use
```

### 5. Run the daemon

A long-lived daemon holds a warm session pool across uploads, so it pays the pool-fill cost once at startup instead of on every upload — a big win for repeated or one-shot-heavy workloads. For a single upload you can skip this step and pass `--peerlist` directly to `hoverfly upload`.

Startup cost depends on how warm the peerlist is. On a cold or stale `peers.json` the daemon runs a bootnode discover round before filling the pool; on a warm one (enough recently-reachable peers) it skips discover automatically and fills straight from the peerlist, opening the pool in well under a second. The daemon persists reachability observations on shutdown, so a node that has run before restarts warm.

```bash
hoverfly daemon --socket /tmp/hoverfly.sock --pool-size 256 --listen /ip4/0.0.0.0/tcp/1635 --identity 0xYOUR_KEY --advertise /ip4/YOUR_PUBLIC_IP/tcp/1635 --discover-rounds 3
```

The repo ships a curated `peers.seed.json`; the daemon loads it via `--peerlist` (default: `peers.json`) for fast cold-start without running `discover` first.

```bash
cp peers.seed.json peers.json
```

### 6. Upload

```bash
hoverfly upload --daemon /tmp/hoverfly.sock --batch YOUR_BATCH_ID_HEX --key 0xYOUR_KEY path/to/file.bin
```

Uploads are Reed–Solomon erasure coded at level `medium` by default, exactly as
a bee gateway codes `POST /bzz`. The extra parity chunks are what keep a freshly
uploaded object readable while its data chunks are still confined to their
storage neighbourhood ([bee#5541]) — at a cost of roughly +8% chunks (and hence
postage) on large files, more on small ones. Pass `--redundancy` to change it:

```bash
hoverfly upload --redundancy none   ... # no parity, cheapest, pre-erasure behaviour
hoverfly upload --redundancy strong ... # ~5% expected chunk retrieval error rate
```

Note that the level is encoded in the root chunk's span, so the same file has a
different reference at each level. `hoverfly bmt --redundancy <level>` computes
that reference offline.

[bee#5541]: https://github.com/ethersphere/bee/issues/5541

## Compatibility

Tracks the upstream [bee][bee] mainnet protocols:

| Protocol     | Versions accepted                         | Notes                            |
| ------------ | ----------------------------------------- | -------------------------------- |
| handshake    | `15.0.0` (preferred), `14.0.0` (fallback) |                                  |
| hive         | `2.0.0` (preferred), `1.1.0` (fallback)   |                                  |
| retrieval    | `1.4.0`                                   |                                  |
| pushsync     | `1.3.1`                                   |                                  |
| pricing      | `1.0.0`                                   |                                  |
| pseudosettle | `1.0.0`                                   |                                  |
| status       | `1.1.3`                                   | inbound-only                     |
| swap         | `1.0.0`                                   | cheque issuance only, no cashout |

[bee]: https://github.com/ethersphere/bee
