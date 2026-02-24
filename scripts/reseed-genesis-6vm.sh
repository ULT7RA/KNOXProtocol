#!/usr/bin/env bash
set -euo pipefail

IPS_FILE="${1:-launch-mainnet/public-ips.txt}"
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

echo "[1/4] clear KNOX_MAINNET_GENESIS_HASH on all VMs"
for ip in "${IPS[@]}"; do
  echo "== $ip =="
  ssh -n -i "$SSH_KEY" "${SSH_OPTS[@]}" "$SSH_USER@$ip" "sudo bash -lc '
set -euo pipefail
for f in /etc/default/knox-node-a /etc/default/knox-node-b; do
  if grep -q \"^KNOX_MAINNET_GENESIS_HASH=\" \"\$f\"; then
    sed -i \"s/^KNOX_MAINNET_GENESIS_HASH=.*/KNOX_MAINNET_GENESIS_HASH=/\" \"\$f\"
  else
    echo \"KNOX_MAINNET_GENESIS_HASH=\" >> \"\$f\"
  fi
done
grep -h \"^KNOX_MAINNET_GENESIS_HASH=\" /etc/default/knox-node-a /etc/default/knox-node-b
'"
done

echo "[2/4] stop services on all VMs"
for ip in "${IPS[@]}"; do
  echo "== $ip =="
  ssh -n -i "$SSH_KEY" "${SSH_OPTS[@]}" "$SSH_USER@$ip" \
    "sudo systemctl stop knox-node-a knox-node-b"
done

echo "[3/4] wipe ledgers on all VMs"
for ip in "${IPS[@]}"; do
  echo "== $ip =="
  ssh -n -i "$SSH_KEY" "${SSH_OPTS[@]}" "$SSH_USER@$ip" \
    "sudo rm -rf /var/lib/knox/node*/ledger"
done

echo "[4/4] start services on all VMs"
for ip in "${IPS[@]}"; do
  echo "== $ip =="
  ssh -n -i "$SSH_KEY" "${SSH_OPTS[@]}" "$SSH_USER@$ip" "sudo bash -lc '
set -euo pipefail
systemctl daemon-reload
systemctl start knox-node-a knox-node-b
sleep 2
echo -n a=; systemctl is-active knox-node-a || true
echo -n b=; systemctl is-active knox-node-b || true
'"
done

echo "[OK] reseed pass complete"
