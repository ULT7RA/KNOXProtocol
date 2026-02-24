#!/usr/bin/env bash
set -euo pipefail

GENESIS_HASH="${1:-}"
IPS_FILE="${2:-launch-mainnet/public-ips.txt}"
MAINNET_ENV="${MAINNET_ENV:-launch-mainnet/mainnet.env}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/knox_oracle}"
SSH_USER="${SSH_USER:-ubuntu}"
SSH_OPTS=(
  -o ConnectTimeout=10
  -o StrictHostKeyChecking=accept-new
  -o IdentitiesOnly=yes
)

if [[ ! "$GENESIS_HASH" =~ ^[0-9a-f]{64}$ ]]; then
  echo "usage: $0 <64-hex-genesis-hash> [ips_file]"
  exit 1
fi
if [[ ! -f "$IPS_FILE" ]]; then
  echo "missing ips file: $IPS_FILE"
  exit 1
fi
if [[ ! -f "$MAINNET_ENV" ]]; then
  echo "missing mainnet env: $MAINNET_ENV"
  exit 1
fi
if [[ ! -f "$SSH_KEY" ]]; then
  echo "missing ssh key: $SSH_KEY"
  exit 1
fi

if grep -q '^KNOX_MAINNET_GENESIS_HASH=' "$MAINNET_ENV"; then
  sed -i "s/^KNOX_MAINNET_GENESIS_HASH=.*/KNOX_MAINNET_GENESIS_HASH=$GENESIS_HASH/" "$MAINNET_ENV"
else
  echo "KNOX_MAINNET_GENESIS_HASH=$GENESIS_HASH" >> "$MAINNET_ENV"
fi

echo "local mainnet.env:"
grep '^KNOX_MAINNET_GENESIS_HASH=' "$MAINNET_ENV"

while read -r ip; do
  [[ -z "${ip// }" ]] && continue
  echo "== $ip =="
  ssh -n -i "$SSH_KEY" "${SSH_OPTS[@]}" "$SSH_USER@$ip" "sudo bash -lc '
set -euo pipefail
for f in /etc/default/knox-node-a /etc/default/knox-node-b; do
  if grep -q \"^KNOX_MAINNET_GENESIS_HASH=\" \"\$f\"; then
    sed -i \"s/^KNOX_MAINNET_GENESIS_HASH=.*/KNOX_MAINNET_GENESIS_HASH=$GENESIS_HASH/\" \"\$f\"
  else
    echo \"KNOX_MAINNET_GENESIS_HASH=$GENESIS_HASH\" >> \"\$f\"
  fi
done
systemctl restart knox-node-a knox-node-b
sleep 2
grep -h \"^KNOX_MAINNET_GENESIS_HASH=\" /etc/default/knox-node-a /etc/default/knox-node-b
echo -n a=; systemctl is-active knox-node-a || true
echo -n b=; systemctl is-active knox-node-b || true
'"
done < "$IPS_FILE"

echo "[OK] pin pass complete"
