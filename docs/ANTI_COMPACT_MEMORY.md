# Anti-Compact Memory — KNOX Operational State (Mar 2026)

> **Purpose**: Persistent runbook so agents (and humans) do not repeat solved
> problems or destroy in-progress state.  This file is gitignored — it lives
> on the operator workstation only.

---

## Critical Safety Rules

1. **NEVER delete ledger data** — not in `_release_quarantine_*`, not in
   `data/node/ledger`, not anywhere — unless the operator explicitly asks.
2. **NEVER delete `_release_quarantine_*` directories** without explicit
   permission.  They contain ledger snapshots and launch artifacts from prior
   releases.
3. **Do not use remote-only wallet mode** unless explicitly requested.
   Fork guard is the primary protection; user can close wallet to stop risk.
4. In **mainnet-locked builds**, do not let host/user env overrides control
   peer/RPC routing.  Ignore `KNOX_DESKTOP_LOCAL_PEERS`,
   `KNOX_PUBLIC_P2P_ADDR`, `KNOX_PUBLIC_RPC_ADDR` by default.

---

## Done in Code

- **`crates/knox-core/src/async_impl.rs`**: Added sync batch diagnostics
  (`sync batch received`, `sync batch made no progress`) and tightened
  block-append loop handling.
- **`crates/knox-p2p/src/lib.rs`**: Added richer block range logs (`count`,
  `first_h`, `last_h`) and changed `Message::Blocks` send path to prefer
  direct requester delivery (avoid gossip pollution).
- **`apps/knox-wallet-desktop/main.js`**: Packaged builds no longer trust
  shell env overrides for network routing; default to seed set behavior.
- **`scripts/rebuild-install-run.ps1`**: Reordered params so
  `-SkipVersionBump -SkipTail` does not mis-bind `TailLines`.

---

## What Has NOT Worked Yet (User-Observed)

- Desktop still seen stuck at local tip `0` in multiple runs.
- Logs continue showing stale block batches (`first_h=64`, `last_h=66`)
  while wallet telemetry tracks much higher upstream tip (~490+).
- Walletd transport remains unstable at times (`ECONNRESET`, timeout,
  endpoint rotation).

---

## Current State

- **Root symptom persists**: node receives blocks but does not advance local
  chain from genesis.
- **Highest-likelihood blocker**: runtime not yet executing newest node
  binary in some installs/restarts, or stale peers repeatedly feeding old
  range.
- **Next validation source**: wallet built-in Logs (user preference: avoid
  external tail commands unless explicitly requested).

---

## Tip-0 Incident Memory (Mar 2026)

| Observation | Detail |
|---|---|
| Symptom | Repeated `sync request from h=0/1` + `writing GetBlocks` with no durable `sync h=…` |
| Desktop single-endpoint pin | Canonical RPC flaky → `endpoint 1/1`, `ECONNRESET`, timeout |
| P2P Blocks delivery | Must not be direct-only; use direct attempt + broadcast fallback |
| Blocks send timeout | Longer timeout than control traffic; do not timeout-drop `Message::Blocks` at all |
| Bootstrap dual-probe | When primary sync uses `h=0`, secondary probe must use `h=1` (not duplicate `h=0`) |
| Desktop launch | Must not pin P2P/RPC to single canonical node; default to full seed set |
| Broadcast fix | Do not broadcast `Message::Blocks` to all peers after serving `GetBlocks`; reply directly to requester |

---

## Infrastructure — The StarForge (3 ForgeTitans, 6 RPC Endpoints)

KNOX mainnet infrastructure runs on 3 Oracle Cloud (OCI) ForgeTitan nodes.
Each ForgeTitan runs **two** relay/RPC instances (node-a and node-b) for a
total of **6 publicly reachable RPC endpoints**. ForgeTitans do not mine —
they relay blocks, serve RPC, and anchor the P2P mesh. Desktop nodes are
the block producers (Forgers).

| ForgeTitan | Public IP | node-a (P2P / RPC) | node-b (P2P / RPC) | Spec |
|---|---|---|---|---|
| `knoxmine` | `161.153.118.97` | 9735 / 9736 | 9745 / 9746 | Oracle 2-OCPU / 32 GB |
| `knoxsync` | `129.146.133.68` | 9735 / 9736 | 9745 / 9746 | Oracle 2-OCPU / 32 GB |
| `knoxrpc`  | `129.146.140.173` | 9735 / 9736 | 9745 / 9746 | Oracle 2-OCPU / 32 GB |

All 6 nodes run with `KNOX_NODE_NO_MINE=1` and `KNOX_NODE_RPC_ALLOW_REMOTE=1`.

> The previous 6-VM fleet (IPs in `_release_quarantine_*/launch-mainnet/public-ips.txt`)
> is **terminated and gone**.

---

## Environment Variable Pins (Local Machine)

`KNOX_DEFAULT_PUBLIC_RPC` and `KNOX_DEFAULT_PUBLIC_RPC_CANDIDATES` should
be cleared (User + Machine scope) so the wallet uses the full hardcoded
candidate list and failover works across all 6 ForgeTitan endpoints.
