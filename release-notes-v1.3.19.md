KNOX v1.3.19

Network Stability & Fork Recovery Release

This release resolves critical P2P block-serving stalls, chain fork divergence,
and desktop wallet connectivity issues that affected mainnet operations.

## P2P Layer Fixes (knox-p2p)

- **Non-blocking sends**: Replaced all `.send().await` calls with `try_send()`
  across `Network` and `NetworkSender`, eliminating full-channel deadlocks that
  froze the core event loop when outbound P2P channels were saturated.
- **Channel capacity increase**: P2P inbound/outbound channels widened from
  1,024 to 4,096 slots to absorb burst traffic during sync storms.

## Core Node Fixes (knox-core)

- **Biased `select!` polling**: Added `biased;` to the main `tokio::select!`
  loop so inbound block/message processing always takes priority over the timer
  branch, preventing timer-tick starvation under load.
- **`MissedTickBehavior::Skip`**: Eliminated accumulated tick bursts that
  allowed the timer branch to dominate the event loop after brief stalls.
- **Batch-drain inbound messages**: The core loop now drains up to 128 queued
  inbound messages per select iteration (collect first + `try_recv` loop),
  dramatically improving block-serving throughput.
- **GetBlocks deduplication**: Stale GetBlocks requests (same height range
  served within 3 seconds) are now skipped, preventing queue flooding from
  impatient peers retrying before prior responses arrive.
- **Automatic fork recovery**: Nodes now detect chain forks by tracking
  consecutive out-of-order block stalls. After 5 consecutive stalls the node
  automatically wipes its ledger and resyncs from genesis. Detection covers both
  ahead-of-tip and overlapping-range fork patterns.

## Desktop Wallet Fixes (knox-wallet-desktop)

- **Fixed `env is not defined` crash** (line 2722): Upstream sync config
  logging now uses `DESKTOP_UPSTREAM_SYNC_BATCH` / `DESKTOP_UPSTREAM_SYNC_TIMEOUT_MS`
  constants instead of referencing `env` outside its lexical scope.
- **Removed unreachable RPC endpoint**: VM3 (161.153.118.97:9736) removed from
  `HARDCODED_RPC_CANDIDATES` — it is P2P-only with RPC bound to 127.0.0.1.
- **Desktop fork detection**: Added `forkOoStallState` tracking in the stdout
  parser to detect and surface chain continuity mismatches in the UI.
- **Version gate fix**: Renderer `CURRENT_DESKTOP_VERSION` synced with
  `MIN_SUPPORTED_INSTALLER_VERSION` to eliminate false "installer obsolete" banners.

## VM Infrastructure

- Enabled `KNOX_TRUST_SYNC_BLOCKS=1` on all 3 mainnet VMs for fast sync
  (skips full 512 MB VeloxReaper DAG rebuild per block during upstream sync).
- All 3 VMs converged on canonical chain after ledger wipe + redeploy.

## Version Bumps

- Cargo workspace: 1.3.1 → 1.3.19
- Desktop app / renderer / MSI: 1.3.19
- MIN_SUPPORTED_INSTALLER_VERSION: 1.3.19

## Artifacts

### Windows Installer
- File: KNOX WALLET 1.3.19.msi

### Docker Hub
- docker pull ult7ra/knox-node:1.3.19
- docker pull ult7ra/knox-gui:1.3.19

### GHCR
- docker pull ghcr.io/ult7ra/knox-node:1.3.19
- docker pull ghcr.io/ult7ra/knox-gui:1.3.19
