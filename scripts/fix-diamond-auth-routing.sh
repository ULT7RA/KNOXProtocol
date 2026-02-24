#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PUB_FILE="${1:-launch-mainnet/public-ips.txt}"
PRIV_FILE="${2:-launch-mainnet/ips.txt}"
ENV_FILE="${3:-launch-mainnet/mainnet.env}"

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

ip5="$(awk 'NF { gsub(/\r/,"",$1); c++; if (c==5) { print $1; exit } }' "$PRIV_FILE")"
ip6="$(awk 'NF { gsub(/\r/,"",$1); c++; if (c==6) { print $1; exit } }' "$PRIV_FILE")"
[[ -n "$ip5" && -n "$ip6" ]] || {
  echo "[FAIL] could not read node 9/10 and 11/12 private IPs from $PRIV_FILE" >&2
  exit 1
}

da_endpoints="${ip5}:9736,${ip5}:9746,${ip6}:9736,${ip6}:9746"
echo "[INFO] Setting KNOX_DIAMOND_AUTH_ENDPOINTS=$da_endpoints"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
awk '!/^KNOX_DIAMOND_AUTH_ENDPOINTS=/' "$ENV_FILE" > "$tmp"
echo "KNOX_DIAMOND_AUTH_ENDPOINTS=$da_endpoints" >> "$tmp"
mv "$tmp" "$ENV_FILE"

export KNOX_PUBLIC_RPC_NODES="9,10,11,12"
export KNOX_NODE_NO_MINE_NODES="9,10,11,12"

if [[ -z "${KNOX_NODE_BIN_LOCAL:-}" ]]; then
  if [[ -f "$ROOT_DIR/target/release-lite/knox-node" ]]; then
    export KNOX_NODE_BIN_LOCAL="$ROOT_DIR/target/release-lite/knox-node"
  elif [[ -f "$ROOT_DIR/target-desktop/release-lite/knox-node" ]]; then
    export KNOX_NODE_BIN_LOCAL="$ROOT_DIR/target-desktop/release-lite/knox-node"
  fi
fi
if [[ -n "${KNOX_NODE_BIN_LOCAL:-}" ]]; then
  if [[ ! -f "$KNOX_NODE_BIN_LOCAL" ]]; then
    echo "[FAIL] KNOX_NODE_BIN_LOCAL does not exist: $KNOX_NODE_BIN_LOCAL" >&2
    exit 1
  fi
  export KNOX_NODE_BIN_SHA256="$(sha256sum "$KNOX_NODE_BIN_LOCAL" | awk '{print $1}')"
  echo "[INFO] Using local node binary: $KNOX_NODE_BIN_LOCAL"
fi

echo "[INFO] Reprovisioning with signer RPC exposure + no-mine on 9..12"
bash scripts/provision-6vm-over-ssh.sh "$PUB_FILE" "$PRIV_FILE"

echo "[INFO] Done. Run:"
echo "  bash scripts/check-mainnet-6vm.sh $PUB_FILE"
echo "  bash scripts/audit-live-6vm.sh $PUB_FILE"
