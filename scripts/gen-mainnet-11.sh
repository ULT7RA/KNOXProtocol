#!/usr/bin/env bash
set -euo pipefail

PREMINE_ADDR="${1:-}"
IPS_FILE="${2:-launch-mainnet/ips.txt}"
RPC_NODES="${3:-9,10,11}"

if [[ -z "$PREMINE_ADDR" ]]; then
  echo "usage: $0 <premine_address> [ips_file] [rpc_nodes_csv]"
  exit 1
fi

if [[ ! -f "$IPS_FILE" ]]; then
  echo "missing ips file: $IPS_FILE"
  exit 1
fi

mapfile -t IPS < <(awk 'NF {print $1}' "$IPS_FILE")
if [[ "${#IPS[@]}" -ne 11 ]]; then
  echo "ips file must contain exactly 11 IPs (found ${#IPS[@]})"
  exit 1
fi

bash scripts/gen-oracle-cloud-init.sh 11 "$IPS_FILE" "$PREMINE_ADDR" 8 "$RPC_NODES"

echo
echo "Done."
echo "Upload launch-mainnet/cloud-init/node1.yaml .. node11.yaml to OCI VMs."
