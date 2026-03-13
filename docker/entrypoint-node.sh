#!/usr/bin/env bash
set -euo pipefail

data_dir="${KNOX_NODE_DATA_DIR:-/var/lib/knox/node}"
p2p_bind="${KNOX_NODE_P2P_BIND:-0.0.0.0:9735}"
rpc_bind="${KNOX_NODE_RPC_BIND:-0.0.0.0:9736}"
peers="${KNOX_NODE_PEERS:-}"
miner_addr="${KNOX_NODE_MINER_ADDRESS:-}"

mkdir -p "$data_dir"

if [[ -n "$miner_addr" ]]; then
  exec /usr/local/bin/knox-node "$data_dir" "$p2p_bind" "$rpc_bind" "$peers" "$miner_addr"
else
  exec /usr/local/bin/knox-node "$data_dir" "$p2p_bind" "$rpc_bind" "$peers"
fi
