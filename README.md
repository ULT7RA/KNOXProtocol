

# KNOX Protocol

**The world's first fully end-to-end lattice-based privacy blockchain.**

Every layer of KNOX — transaction signing, output commitments, range proofs, stealth addresses,
block proof-of-work, consensus signatures, and P2P session encryption — runs on ULT7Rock lattice
cryptography. No elliptic curves. No classical assumptions. No forks. Built from the ground up.

[![Support on Patreon](https://img.shields.io/badge/Patreon-F96854?style=for-the-badge&logo=patreon&logoColor=white)](https://www.patreon.com/ULT7ROCK)

- Whitepaper: [WHITEPAPER.md](./WHITEPAPER.md)
- Threat Model: [security.md](./security.md)
- Inquiries: KNOXULT7Rock@proton.me
 

---

## Download the Wallet

Go to [Releases](../../releases) and download **KNOX WALLET x.x.x.msi**.

Run the installer. No dependencies required.

---

## Getting Started

### 1. Generate TLS

On first launch, click **Generate TLS** on the Dashboard.

This creates a self-signed TLS certificate for your local wallet daemon. Required before starting the node.

### 2. Quick Start

Click **Quick Start**.

This starts the KNOX node and wallet daemon together, connects to the network, and begins mining automatically.

> The status bar at the top will show **RPC ONLINE** and **SOURCE NETWORK** when connected.

### 3. Your Address

Your wallet address is generated automatically on first run. To see it:

- Click **Get Wallet Address** on the Dashboard
- Or go to the **Send** tab — your addresses are listed in the right panel

To generate additional addresses, click **New Address** on the Dashboard.

### 4. Send KNOX

1. Go to the **Send** tab
2. Paste a recipient address into the **Recipient Address** field
3. Enter amount, fee (e.g. `0.01`), and ring size (default: `11`)
4. Click **Send Transaction** and confirm the dialog

> After sending, your balance may briefly appear higher until the wallet syncs the spent key image.
> Hit **Sync Wallet** on the Dashboard to update immediately.

### 5. Mining

Mining starts automatically with Quick Start. Monitor it on the **Mining** tab — hash rate, difficulty, streak bonus, and surge status are all displayed live.

To run sync-only (no mining), click **Start Node (Mining Off)** instead of Quick Start.

---

## Build From Source

### Requirements

- Rust stable (`rust-toolchain.toml` pins the toolchain automatically)
- Node.js 18+ (for the desktop wallet)

### Build everything

```sh
cargo build --workspace --release
```

### Build the Windows installer

```powershell
powershell.exe -File scripts\build-installer.ps1
```

### Build Linux node binary (from WSL, for server deployment)

```bash
cargo zigbuild -p knox-node --target x86_64-unknown-linux-musl --profile release-lite
```

### Docker (Linux node + GUI)

```bash
docker build -f docker/Dockerfile.node -t knox/node:linux .
docker build -f docker/Dockerfile.gui -t knox/gui:linux .
```

For full run commands (node, GUI, and compose), see [docker/README.md](./docker/README.md).

---

## Run a Node (CLI)

```sh
# Full node with mining (open-mining runtime)
cargo run -p knox-node -- ./data 0.0.0.0:9735 0.0.0.0:9736 127.0.0.1:9735 <miner_knox1_address>

# Sync only
KNOX_NODE_NO_MINE=1 cargo run -p knox-node -- ./data 0.0.0.0:9735 0.0.0.0:9736 127.0.0.1:9735 <miner_knox1_address>
```

---

## Network Architecture — The StarForge

KNOX mainnet is anchored by **ForgeTitans** — dedicated Oracle Cloud relay nodes that serve
RPC and relay blocks across the P2P mesh. ForgeTitans do not mine. Desktop nodes are the
block producers (**Forgers**).

| Role | What it does |
|---|---|
| **ForgeTitan** | Relay-only infrastructure node. Serves upstream RPC, relays blocks between peers. Runs on OCI. |
| **Forger** | Desktop node that solves ULT7Rock Lattice-PoW and proposes blocks to the network. |

There are currently **3 ForgeTitans** running **6 RPC endpoints** (2 per machine):

| ForgeTitan | Public IP | RPC Ports |
|---|---|---|
| `knoxmine` | `161.153.118.97` | 9736, 9746 |
| `knoxsync` | `129.146.133.68` | 9736, 9746 |
| `knoxrpc` | `129.146.140.173` | 9736, 9746 |

Desktop wallets automatically discover and failover across all 6 endpoints.

---

## Crate Architecture

| Crate | Role |
|---|---|
| `knox-types` | Wire types and protocol constants |
| `knox-lattice` | ULT7Rock lattice core: ring sigs, commitments, range proofs, stealth, PoW, surge |
| `knox-storage` | Encrypted flat-file key-value store |
| `knox-consensus` | Lattice consensus primitives (open-mining with Forger slot election and optional Diamond Auth) |
| `knox-ledger` | Block and UTXO validation and storage |
| `knox-p2p` | Lattice two-round KEM handshake, authenticated encrypted transport, cover traffic |
| `knox-core` | Node runtime: mempool, RPC server, block production, StarForge relay |
| `knox-node` | Node binary |
| `knox-wallet` | Wallet library: UTXO scanning, transaction building |
| `knox-walletd` | HTTP/TLS wallet daemon (JSON API for desktop UI) |
| `knox-keygen` | Key generation utility |
| `knox-smoke` | Integration smoke tests |

---

## Testnet

```sh
# Generate Docker testnet (50-100 nodes)
bash scripts/gen-testnet.sh

# 24h load test
bash scripts/testnet-bench.sh
```

---

## License

Apache-2.0 — see [LICENSE](./LICENSE)

