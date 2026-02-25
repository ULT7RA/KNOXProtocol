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

while read -r ip; do
  [[ -z "${ip// }" ]] && continue
  echo "== $ip =="
  ssh -n -i "$SSH_KEY" "${SSH_OPTS[@]}" "$SSH_USER@$ip" "sudo bash -lc '
set -euo pipefail
systemctl stop knox-node-a knox-node-b
rm -rf /var/lib/knox/node*/ledger
systemctl start knox-node-a knox-node-b
sleep 2
echo -n a=; systemctl is-active knox-node-a || true
echo -n b=; systemctl is-active knox-node-b || true
'"
done < "$IPS_FILE"

echo "[OK] wipe pass complete"
