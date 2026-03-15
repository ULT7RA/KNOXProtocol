#!/usr/bin/env bash
set -euo pipefail

# ForgeTitan default seed peers (all 6 nodes across 3 VMs)
DEFAULT_PEERS="129.146.133.68:9735,129.146.140.173:9735,161.153.118.97:9735,129.146.133.68:9745,129.146.140.173:9745,161.153.118.97:9745"

data_dir="${KNOX_NODE_DATA_DIR:-/var/lib/knox/node}"
p2p_bind="${KNOX_NODE_P2P_BIND:-0.0.0.0:9735}"
rpc_bind="${KNOX_NODE_RPC_BIND:-0.0.0.0:9736}"
peers="${KNOX_NODE_PEERS:-$DEFAULT_PEERS}"
miner_addr="${KNOX_NODE_MINER_ADDRESS:-}"

# Relay-only by default (set KNOX_NODE_NO_MINE=0 to enable mining)
export KNOX_NODE_NO_MINE="${KNOX_NODE_NO_MINE:-1}"

mkdir -p "$data_dir"

if [[ -n "$miner_addr" ]]; then
  exec /usr/local/bin/knox-node "$data_dir" "$p2p_bind" "$rpc_bind" "$peers" "$miner_addr"
else
  exec /usr/local/bin/knox-node "$data_dir" "$p2p_bind" "$rpc_bind" "$peers"
fi
