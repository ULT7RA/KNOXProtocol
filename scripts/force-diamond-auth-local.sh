#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PUB_FILE="${1:-launch-mainnet/public-ips.txt}"
PRIV_FILE="${2:-launch-mainnet/ips.txt}"
ENV_FILE="${3:-launch-mainnet/mainnet.env}"
KEY_ROOT="${KEY_ROOT:-keys-live}"
AUTH_NODES="${KNOX_DIAMOND_AUTH_NODES:-1,2,3,4,5,6,7,8,9,10,11,12}"
AUTH_QUORUM="${KNOX_DIAMOND_AUTH_QUORUM:-2}"
LOCAL_ENDPOINTS="127.0.0.1:9736,127.0.0.1:9746"

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
need_file "${KNOX_SSH_PUBKEY_PATH:-$HOME/.ssh/knox_oracle.pub}"

PREMINE_ADDR="$(sed -n 's/^KNOX_MAINNET_PREMINE_ADDRESS=//p' "$ENV_FILE" | tail -n1 | tr -d '\r')"
[[ -n "$PREMINE_ADDR" ]] || {
  echo "[FAIL] KNOX_MAINNET_PREMINE_ADDRESS missing in $ENV_FILE" >&2
  exit 1
}

export KNOX_SSH_PUBKEY="$(cat "${KNOX_SSH_PUBKEY_PATH:-$HOME/.ssh/knox_oracle.pub}")"
export KNOX_DIAMOND_AUTH_NODES="$AUTH_NODES"
export KNOX_DIAMOND_AUTH_QUORUM="$AUTH_QUORUM"

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

echo "[INFO] Regenerating config with auth nodes=$AUTH_NODES quorum=$AUTH_QUORUM"
KEY_ROOT="$KEY_ROOT" bash scripts/gen-oracle-cloud-init-6vm.sh "$PRIV_FILE" "$PREMINE_ADDR"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
awk '!/^KNOX_DIAMOND_AUTH_ENDPOINTS=/' "$ENV_FILE" > "$tmp"
echo "KNOX_DIAMOND_AUTH_ENDPOINTS=$LOCAL_ENDPOINTS" >> "$tmp"
mv "$tmp" "$ENV_FILE"

export KNOX_PUBLIC_RPC_NODES=""
export KNOX_NODE_NO_MINE_NODES="9,10,11,12"

echo "[INFO] Forcing local diamond-auth endpoints: $LOCAL_ENDPOINTS"
bash scripts/provision-6vm-over-ssh.sh "$PUB_FILE" "$PRIV_FILE"

echo "[OK] local diamond-auth mode applied"
echo "[NEXT] verify:"
echo "  bash scripts/check-mainnet-6vm.sh $PUB_FILE"
echo "  bash scripts/audit-live-6vm.sh $PUB_FILE"
