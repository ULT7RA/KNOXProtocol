#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${1:-launch-mainnet/mainnet.env}"
PUB_IPS_FILE="${2:-launch-mainnet/public-ips.txt}"
PRIV_IPS_FILE="${3:-launch-mainnet/ips.txt}"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

warn() {
  echo "[WARN] $*" >&2
}

ok() {
  echo "[OK] $*"
}

need_file() {
  local f="$1"
  [[ -f "$f" ]] || fail "missing file: $f"
}

read_env_key() {
  local file="$1"
  local key="$2"
  local line
  line="$(grep -E "^${key}=" "$file" | tail -n 1 || true)"
  [[ -n "$line" ]] || {
    echo ""
    return
  }
  echo "${line#*=}"
}

count_lines() {
  local file="$1"
  awk 'NF > 0 { n++ } END { print n + 0 }' "$file"
}

cd "$ROOT_DIR"

need_file "$ENV_FILE"
need_file "$PUB_IPS_FILE"
need_file "$PRIV_IPS_FILE"

for key in \
  KNOX_P2P_PSK_SERVICE \
  KNOX_P2P_PSK_ACCOUNT \
  KNOX_MAINNET_LOCK \
  KNOX_MAINNET_PREMINE_ADDRESS \
  KNOX_DIAMOND_AUTH_PUBKEYS \
  KNOX_DIAMOND_AUTH_QUORUM \
  KNOX_DIAMOND_AUTH_ENDPOINTS
do
  value="$(read_env_key "$ENV_FILE" "$key")"
  [[ -n "$value" ]] || fail "$key missing/empty in $ENV_FILE"
done

legacy_psk="$(read_env_key "$ENV_FILE" "KNOX_P2P_PSK")"
if [[ -n "$legacy_psk" ]]; then
  fail "KNOX_P2P_PSK must not be set; use OS keyring + KNOX_P2P_PSK_SERVICE/KNOX_P2P_PSK_ACCOUNT"
fi

psk_service="$(read_env_key "$ENV_FILE" "KNOX_P2P_PSK_SERVICE")"
psk_account="$(read_env_key "$ENV_FILE" "KNOX_P2P_PSK_ACCOUNT")"
if command -v secret-tool >/dev/null 2>&1; then
  if ! secret-tool lookup service "$psk_service" account "$psk_account" >/dev/null 2>&1; then
    fail "missing keyring secret for service=$psk_service account=$psk_account"
  fi
  ok "keyring secret lookup succeeded for service=$psk_service account=$psk_account"
else
  warn "secret-tool not found locally; skipped keyring lookup check"
fi

lock_flag="$(read_env_key "$ENV_FILE" "KNOX_MAINNET_LOCK")"
[[ "$lock_flag" == "1" ]] || warn "KNOX_MAINNET_LOCK is not 1"

pub_count="$(count_lines "$PUB_IPS_FILE")"
priv_count="$(count_lines "$PRIV_IPS_FILE")"
[[ "$pub_count" -gt 0 ]] || fail "no public IPs in $PUB_IPS_FILE"
[[ "$priv_count" -gt 0 ]] || fail "no private IPs in $PRIV_IPS_FILE"
[[ "$pub_count" -eq "$priv_count" ]] || {
  fail "public/private IP count mismatch ($pub_count vs $priv_count)"
}

if [[ -n "${KNOX_NODE_BIN_LOCAL:-}" ]]; then
  [[ -f "$KNOX_NODE_BIN_LOCAL" ]] || fail "KNOX_NODE_BIN_LOCAL not found"
fi

if [[ -n "${KNOX_NODE_BIN_LOCAL:-}" && -n "${KNOX_NODE_BIN_SHA256:-}" ]]; then
  got_sha="$(sha256sum "$KNOX_NODE_BIN_LOCAL" | awk '{print $1}')"
  [[ "$got_sha" == "$KNOX_NODE_BIN_SHA256" ]] || {
    fail "binary sha mismatch for KNOX_NODE_BIN_LOCAL"
  }
  ok "binary sha matches KNOX_NODE_BIN_SHA256"
else
  warn "binary hash env not set; export KNOX_NODE_BIN_LOCAL + KNOX_NODE_BIN_SHA256"
fi

ok "running local compile sanity check"
cargo +stable check \
  -p knox-lattice \
  -p knox-types \
  -p knox-ledger \
  -p knox-core \
  -p knox-node \
  -p knox-wallet >/tmp/knox-preflight-cargo.log 2>&1 || {
  tail -n 80 /tmp/knox-preflight-cargo.log >&2
  fail "cargo check failed"
}

ok "preflight checks passed"
