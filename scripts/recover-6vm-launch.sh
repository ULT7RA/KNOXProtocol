#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PUB_FILE="${1:-launch-mainnet/public-ips.txt}"
IPS_FILE="${2:-launch-mainnet/ips.txt}"
ENV_FILE="${3:-launch-mainnet/mainnet.env}"

SSH_KEY="${SSH_KEY:-$HOME/.ssh/knox_oracle}"
SSH_USER="${SSH_USER:-ubuntu}"
KEY_ROOT_LOCAL="${KEY_ROOT_LOCAL:-keys-live}"
SSH_OPTS=(-o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes)

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

need_file() {
  local p="$1"
  [[ -f "$p" ]] || fail "missing file: $p"
}

need_file "$PUB_FILE"
need_file "$SSH_KEY"
mkdir -p launch-mainnet "$KEY_ROOT_LOCAL"

mapfile -t PUB_IPS < <(awk 'NF {gsub(/\r/,"",$1); print $1}' "$PUB_FILE")
[[ "${#PUB_IPS[@]}" -eq 6 ]] || fail "public ips file must have exactly 6 lines"

echo "[1/8] Build knox-node"
if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  cargo build -p knox-node --bin knox-node --profile release-lite
fi
export KNOX_NODE_BIN_LOCAL="${KNOX_NODE_BIN_LOCAL:-$ROOT_DIR/target/release-lite/knox-node}"
[[ -f "$KNOX_NODE_BIN_LOCAL" ]] || fail "missing built binary: $KNOX_NODE_BIN_LOCAL"
export KNOX_NODE_BIN_SHA256="$(sha256sum "$KNOX_NODE_BIN_LOCAL" | awk '{print $1}')"

echo "[2/8] Recover private IP list -> $IPS_FILE"
: > "$IPS_FILE"
for ip in "${PUB_IPS[@]}"; do
  priv="$(ssh -i "$SSH_KEY" "${SSH_OPTS[@]}" "$SSH_USER@$ip" "ip -4 -o addr show scope global | awk '{print \$4}' | cut -d/ -f1 | head -n1" | tr -d '\r')"
  [[ -n "$priv" ]] || fail "failed reading private IP from $ip"
  echo "$priv" >> "$IPS_FILE"
done

echo "[3/8] Pull node keys from VMs -> $KEY_ROOT_LOCAL"
for i in $(seq 1 6); do
  ip="${PUB_IPS[$((i - 1))]}"
  n1=$((2 * i - 1))
  n2=$((2 * i))
  mkdir -p "$KEY_ROOT_LOCAL/node$n1" "$KEY_ROOT_LOCAL/node$n2"
  ssh -i "$SSH_KEY" "${SSH_OPTS[@]}" "$SSH_USER@$ip" "sudo cat /var/lib/knox/node$n1/node.key" | tr -d '\r' > "$KEY_ROOT_LOCAL/node$n1/node.key"
  ssh -i "$SSH_KEY" "${SSH_OPTS[@]}" "$SSH_USER@$ip" "sudo cat /var/lib/knox/node$n2/node.key" | tr -d '\r' > "$KEY_ROOT_LOCAL/node$n2/node.key"
done

echo "[4/8] Recover mainnet env from vm1 -> $ENV_FILE"
FIRST_IP="${PUB_IPS[0]}"
get_remote_env() {
  local key="$1"
  ssh -i "$SSH_KEY" "${SSH_OPTS[@]}" "$SSH_USER@$FIRST_IP" "sudo sed -n 's/^${key}=//p' /etc/default/knox-node-a | tail -n1" | tr -d '\r'
}

PSK_SERVICE="$(get_remote_env KNOX_P2P_PSK_SERVICE)"
PSK_ACCOUNT="$(get_remote_env KNOX_P2P_PSK_ACCOUNT)"
PREMINE_ADDR="$(get_remote_env KNOX_MAINNET_PREMINE_ADDRESS)"
GENESIS_HASH="$(get_remote_env KNOX_MAINNET_GENESIS_HASH)"
DA_PUBKEYS="$(get_remote_env KNOX_DIAMOND_AUTH_PUBKEYS)"
DA_QUORUM="$(get_remote_env KNOX_DIAMOND_AUTH_QUORUM)"
DA_ENDPOINTS="$(get_remote_env KNOX_DIAMOND_AUTH_ENDPOINTS)"

[[ -n "$PREMINE_ADDR" ]] || fail "failed to recover KNOX_MAINNET_PREMINE_ADDRESS from vm1"

cat > "$ENV_FILE" <<EOF
KNOX_P2P_PSK_SERVICE=${PSK_SERVICE:-knox-p2p}
KNOX_P2P_PSK_ACCOUNT=${PSK_ACCOUNT:-mainnet}
KNOX_MAINNET_LOCK=1
KNOX_MAINNET_PREMINE_ADDRESS=$PREMINE_ADDR
KNOX_MAINNET_GENESIS_HASH=$GENESIS_HASH
KNOX_DIAMOND_AUTH_PUBKEYS=$DA_PUBKEYS
KNOX_DIAMOND_AUTH_QUORUM=${DA_QUORUM:-2}
KNOX_DIAMOND_AUTH_ENDPOINTS=$DA_ENDPOINTS
EOF

echo "[5/8] Regenerate cloud-init + env artifacts"
PUBKEY_PATH="${KNOX_SSH_PUBKEY_PATH:-$HOME/.ssh/knox_oracle.pub}"
need_file "$PUBKEY_PATH"
export KNOX_SSH_PUBKEY="$(cat "$PUBKEY_PATH")"
export KNOX_DIAMOND_AUTH_NODES="${KNOX_DIAMOND_AUTH_NODES:-9,10,11,12}"
export KNOX_DIAMOND_AUTH_QUORUM="${KNOX_DIAMOND_AUTH_QUORUM:-2}"
KEY_ROOT="$KEY_ROOT_LOCAL" bash scripts/gen-oracle-cloud-init-6vm.sh "$IPS_FILE" "$PREMINE_ADDR"

echo "[6/8] Re-provision VMs"
KEY_ROOT="$KEY_ROOT_LOCAL" bash scripts/provision-6vm-over-ssh.sh "$PUB_FILE" "$IPS_FILE"

echo "[7/8] Verify genesis consistency"
bash scripts/check-genesis-6vm.sh "$PUB_FILE"

echo "[8/8] Verify services + logs"
bash scripts/audit-live-6vm.sh "$PUB_FILE"
bash scripts/check-mainnet-6vm.sh "$PUB_FILE"

echo "[OK] recovery + redeploy completed"
