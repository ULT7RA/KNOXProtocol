#!/usr/bin/env bash
set -euo pipefail

PREMINE_ADDR="${1:-}"
IPS_FILE="${2:-launch-mainnet/ips.txt}"
OUT_FILE="${3:-launch-mainnet/cloud-init/node1.yaml}"
RPC_NODES="${4:-9,10,11}"

if [[ -z "$PREMINE_ADDR" ]]; then
  echo "usage: $0 <premine_address> [ips_file] [out_file] [rpc_nodes_csv]"
  exit 1
fi

# Reuse the main generator so node1 has the exact same config model as the full cluster.
bash scripts/gen-oracle-cloud-init.sh 11 "$IPS_FILE" "$PREMINE_ADDR" 8 "$RPC_NODES" >/dev/null

if [[ ! -f "launch-mainnet/cloud-init/node1.yaml" ]]; then
  echo "failed: launch-mainnet/cloud-init/node1.yaml not found"
  exit 1
fi

mkdir -p "$(dirname "$OUT_FILE")"
cp "launch-mainnet/cloud-init/node1.yaml" "$OUT_FILE"
echo "$OUT_FILE"
