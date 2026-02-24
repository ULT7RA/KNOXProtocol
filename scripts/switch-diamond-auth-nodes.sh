#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

AUTH_NODES="${1:-5,6,7,8}"
QUORUM="${2:-2}"
PUB_FILE="${3:-launch-mainnet/public-ips.txt}"
PRIV_FILE="${4:-launch-mainnet/ips.txt}"
ENV_FILE="${5:-launch-mainnet/mainnet.env}"
KEY_ROOT="${KEY_ROOT:-keys-live}"
PUBLIC_RPC_NODES="${KNOX_PUBLIC_RPC_NODES:-}"
NO_MINE_NODES="${KNOX_NODE_NO_MINE_NODES:-$AUTH_NODES}"

need_file() {
  local p="$1"
  [[ -f "$p" ]] || {
    echo "[FAIL] missing file: $p" >&2
    exit 1
  }
}

need_file "$PUB_FILE"
need_file "$PRIV_FILE"
need_file "$ENV_FILE"

PREMINE_ADDR="$(sed -n 's/^KNOX_MAINNET_PREMINE_ADDRESS=//p' "$ENV_FILE" | tail -n1 | tr -d '\r')"
[[ -n "$PREMINE_ADDR" ]] || {
  echo "[FAIL] KNOX_MAINNET_PREMINE_ADDRESS missing in $ENV_FILE" >&2
  exit 1
}

echo "[INFO] Switching Diamond Authenticators to nodes: $AUTH_NODES (quorum=$QUORUM)"

export KNOX_DIAMOND_AUTH_NODES="$AUTH_NODES"
export KNOX_DIAMOND_AUTH_QUORUM="$QUORUM"

# Keep existing PSK naming if present.
psk_service="$(sed -n 's/^KNOX_P2P_PSK_SERVICE=//p' "$ENV_FILE" | tail -n1 | tr -d '\r')"
psk_account="$(sed -n 's/^KNOX_P2P_PSK_ACCOUNT=//p' "$ENV_FILE" | tail -n1 | tr -d '\r')"
if [[ -n "$psk_service" ]]; then
  export KNOX_P2P_PSK_SERVICE="$psk_service"
fi
if [[ -n "$psk_account" ]]; then
  export KNOX_P2P_PSK_ACCOUNT="$psk_account"
fi

KEY_ROOT="$KEY_ROOT" bash scripts/gen-oracle-cloud-init-6vm.sh "$PRIV_FILE" "$PREMINE_ADDR"

export KNOX_PUBLIC_RPC_NODES="$PUBLIC_RPC_NODES"
export KNOX_NODE_NO_MINE_NODES="$NO_MINE_NODES"

if [[ -z "${KNOX_NODE_BIN_LOCAL:-}" ]]; then
  if [[ -f "$ROOT_DIR/target/release-lite/knox-node" ]]; then
    export KNOX_NODE_BIN_LOCAL="$ROOT_DIR/target/release-lite/knox-node"
  elif [[ -f "$ROOT_DIR/target-desktop/release-lite/knox-node" ]]; then
    export KNOX_NODE_BIN_LOCAL="$ROOT_DIR/target-desktop/release-lite/knox-node"
  fi
fi
if [[ -n "${KNOX_NODE_BIN_LOCAL:-}" ]]; then
  [[ -f "$KNOX_NODE_BIN_LOCAL" ]] || {
    echo "[FAIL] KNOX_NODE_BIN_LOCAL missing: $KNOX_NODE_BIN_LOCAL" >&2
    exit 1
  }
  export KNOX_NODE_BIN_SHA256="$(sha256sum "$KNOX_NODE_BIN_LOCAL" | awk '{print $1}')"
fi

bash scripts/provision-6vm-over-ssh.sh "$PUB_FILE" "$PRIV_FILE"

echo "[OK] switched diamond auth nodes and reprovisioned"
if [[ -n "$PUBLIC_RPC_NODES" ]]; then
  echo "[INFO] public RPC nodes: $PUBLIC_RPC_NODES"
else
  echo "[INFO] public RPC nodes: none (diamond auth RPC is private-only)"
fi
echo "[NEXT] run:"
echo "  bash scripts/check-mainnet-6vm.sh $PUB_FILE"
echo "  bash scripts/audit-live-6vm.sh $PUB_FILE"
