# KNOX Protocol

**The world's first fully end-to-end lattice-based privacy blockchain.**

Every layer of KNOX — transaction signing, output commitments, range proofs, stealth addresses,
block proof-of-work, consensus signatures, and P2P session encryption — runs on ULT7Rock lattice
cryptography. No elliptic curves. No classical assumptions. No forks. Built from the ground up.

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

---

## Run a Node (CLI)

```sh
# Full validator node with mining
cargo run -p knox-node -- ./data 0.0.0.0:9735 0.0.0.0:9736 127.0.0.1:9735 ./data/validators.txt

# Sync only
KNOX_NODE_NO_MINE=1 cargo run -p knox-node -- ./data 0.0.0.0:9735 0.0.0.0:9736 127.0.0.1:9735 ./data/validators.txt
```

`validators.txt` contains hex-encoded lattice consensus public keys, one per line.

---

## Crate Architecture

| Crate | Role |
|---|---|
| `knox-types` | Wire types and protocol constants |
| `knox-crypto` | Curve25519 classical layer (secondary wire format) |
| `knox-lattice` | ULT7Rock lattice core: ring sigs, commitments, range proofs, stealth, PoW, surge |
| `knox-storage` | ChaCha20Poly1305-encrypted flat-file key-value store |
| `knox-consensus` | PulsarBFT consensus engine |
| `knox-ledger` | Block and UTXO validation and storage |
| `knox-p2p` | Lattice two-round KEM handshake, XChaCha20 session encryption, cover traffic |
| `knox-core` | Node runtime: mempool, RPC server, block production |
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

# Regenerate validators.txt from existing node keys
bash scripts/regenerate-lattice-validators.sh <key_root> <validator_count>

# 24h load test
bash scripts/testnet-bench.sh
```

---

## License

Apache-2.0 — see [LICENSE](./LICENSE)
