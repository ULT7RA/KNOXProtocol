# KNOX Anti-Compact Memory

Purpose: keep a durable, minimal runbook of known-good commands/build strings so recovery after context loss is fast and deterministic.

## How to use

- Say: `add to memory: <what worked + when to use it>`.
- I append an entry with:
  - Date/time
  - Command(s)
  - Expected success signal
  - When to use
  - Notes/constraints

## Entry template

### [YYYY-MM-DD HH:MM UTC] <short title>
- Command(s):
  - `...`
- Success signal:
  - `...`
- Use when:
  - `...`
- Notes:
  - `...`

## Entries

### [2026-03-03 00:00 UTC] CUDA kernel source wired to new fatbin
- Command(s):
  - `crates/knox-lattice/src/mining.rs` uses `include_bytes!("kernelcuda.fatbin")`
  - Legacy fatbin moved to `crates/knox-lattice/src/legacy/knox_mining_32.fatbin`
- Success signal:
  - Runtime `cuModuleLoadData` loads `kernelcuda.fatbin` bytes.
- Use when:
  - Verifying the wallet/node uses the new CUDA kernel artifact.
- Notes:
  - Keep `kernelcuda.fatbin` updated after each `kernelcuda.cu` change.

### [2026-03-03 00:00 UTC] VeloxReaper replaces Argon2 mining memory path
- Command(s):
  - `rg -n "argon2|VeloxReaper|velox_reaper" crates/knox-lattice/src crates/knox-node/src`
  - Confirmed `crates/knox-lattice/src/velox_reaper.rs` exists and mining flow references it in `crates/knox-lattice/src/mining.rs`.
- Success signal:
  - Mining memory-hard path resolves to VeloxReaper code, not Argon2.
- Use when:
  - Verifying anti-ASIC lattice memory-hard implementation is active after mining changes.
- Notes:
  - Performance report from live run: ~3.9M H/s GPU after iterative tuning.

### [2026-03-04 00:00 UTC] Lock 6-VM network to one canonical miner lane
- Command(s):
  - `bash scripts/lock-single-miner-6vm.sh 132.226.76.90 d626848546f6511abd38a1ee89610a708d001d53e0c8a27dc509a1e65b964187 launch-mainnet/public-ips.txt`
- Success signal:
  - On all VMs: `knox-node-a=active`, `knox-node-b=inactive`.
  - Canonical (`132.226.76.90`) shows `sealed block` in recent `knox-node-a` logs.
- Use when:
  - Bootstrap/sync instability appears with split lanes or repeated genesis mismatch errors.
- Notes:
  - This script enforces the canonical genesis hash, wipes stale ledgers, and hard-disables `knox-node-b`.

### [2026-03-04 00:00 UTC] Quick 6-VM health check (short output)
- Command(s):
  - `bash scripts/quick-health-6vm.sh launch-mainnet/public-ips.txt`
- Success signal:
  - Matching node binary SHA across all VMs.
  - `errs=0` (no recent `coinbase amounts incorrect`) and nonzero `sealed` on canonical.
- Use when:
  - Verifying whether deploy + lane lock actually stuck, without dumping huge logs.
- Notes:
  - If command hangs, run one VM at a time with direct `ssh -i ~/.ssh/knox_oracle ubuntu@<ip> ...` checks.

### [2026-03-04 00:00 UTC] Tip-0 bootstrap fix for duplicate genesis in sync batch
- Command(s):
  - Patch `crates/knox-ledger/src/lib.rs::append_block` to detect already-stored height first.
  - If stored block hash matches incoming hash: return `block height X already exists`.
  - If stored block hash differs: return conflict error and stop.
- Success signal:
  - Local logs stop repeating `sync stop h=0: unexpected block height: got 0, expected 1`.
  - Sync can continue past genesis when peers send `Blocks` batches that begin with height 0.
- Use when:
  - Node is stuck at tip 0 and requests alternate `h=1`/`h=0` while genesis already exists locally.
- Notes:
  - Root cause: duplicate genesis in a `Blocks` response triggered `unexpected block height` and broke batch processing before block 1 was applied.
