#!/usr/bin/env bash
set -euo pipefail

IPS_FILE="${1:-launch-mainnet/public-ips.txt}"
SOURCE_IP="${2:-}"
SOURCE_NODE_DIR="${3:-/var/lib/knox/node2}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/knox_oracle}"
SSH_USER="${SSH_USER:-ubuntu}"
SSH_OPTS=(
  -o ConnectTimeout=10
  -o StrictHostKeyChecking=accept-new
  -o IdentitiesOnly=yes
)

if [[ ! -f "$IPS_FILE" ]]; then
  echo "missing ips file: $IPS_FILE"
  exit 1
fi
if [[ ! -f "$SSH_KEY" ]]; then
  echo "missing ssh key: $SSH_KEY"
  exit 1
fi

mapfile -t IPS < <(awk 'NF{gsub(/\r/,"",$1); print $1}' "$IPS_FILE")
if [[ "${#IPS[@]}" -ne 6 ]]; then
  echo "ips file must contain 6 IPs"
  exit 1
fi
if [[ -z "$SOURCE_IP" ]]; then
  SOURCE_IP="${IPS[0]}"
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
seed_tgz="$tmp_dir/seed-ledger.tgz"

echo "[1/4] snapshot source ledger from $SOURCE_IP:$SOURCE_NODE_DIR"
ssh -n -i "$SSH_KEY" "${SSH_OPTS[@]}" "$SSH_USER@$SOURCE_IP" "sudo bash -lc '
set -euo pipefail
test -d \"$SOURCE_NODE_DIR/ledger\"
tar -C \"$SOURCE_NODE_DIR\" -czf - ledger
'" > "$seed_tgz"

echo "[2/4] stop services on all VMs"
for ip in "${IPS[@]}"; do
  echo "== $ip =="
  ssh -n -i "$SSH_KEY" "${SSH_OPTS[@]}" "$SSH_USER@$ip" \
    "sudo systemctl stop knox-node-a knox-node-b"
done

echo "[3/4] push same ledger to every /var/lib/knox/node*/ledger"
for ip in "${IPS[@]}"; do
  echo "== $ip =="
  scp -i "$SSH_KEY" "${SSH_OPTS[@]}" "$seed_tgz" "$SSH_USER@$ip:/tmp/seed-ledger.tgz" >/dev/null
  ssh -n -i "$SSH_KEY" "${SSH_OPTS[@]}" "$SSH_USER@$ip" "sudo bash -lc '
set -euo pipefail
for d in /var/lib/knox/node*; do
  [[ -d \"\$d\" ]] || continue
  rm -rf \"\$d/ledger\"
  tar -xzf /tmp/seed-ledger.tgz -C \"\$d\"
done
chown -R knox:knox /var/lib/knox
rm -f /tmp/seed-ledger.tgz
'"
done

echo "[4/4] start services on all VMs"
for ip in "${IPS[@]}"; do
  echo "== $ip =="
  ssh -n -i "$SSH_KEY" "${SSH_OPTS[@]}" "$SSH_USER@$ip" "sudo bash -lc '
set -euo pipefail
systemctl start knox-node-a knox-node-b
sleep 2
echo -n a=; systemctl is-active knox-node-a || true
echo -n b=; systemctl is-active knox-node-b || true
'"
done

echo "[OK] seed pass complete"
