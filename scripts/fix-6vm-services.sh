#!/usr/bin/env bash
set -euo pipefail

IPS_FILE="${1:-launch-mainnet/public-ips.txt}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/knox_oracle}"
SSH_USER="${SSH_USER:-ubuntu}"
BIN_URL="${KNOX_NODE_BIN_URL:-https://objectstorage.us-phoenix-1.oraclecloud.com/p/zwNH-5xPHIzNxuLA0pBtcVmC7G4Xe4AkReoLNzKnfawM-nPfwHFHMzxWifLDbQ6r/n/axiq79viclak/b/KNOXAUTO/o/knox-node}"
BIN_SHA256="${KNOX_NODE_BIN_SHA256:-fe8b57efbe6feb4822c4db6984d905e3db203665e1dc0386e298b81ad5976146}"

if [[ ! -f "$IPS_FILE" ]]; then
  echo "missing ips file: $IPS_FILE"
  exit 1
fi

if [[ ! "$BIN_SHA256" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "invalid KNOX_NODE_BIN_SHA256"
  exit 1
fi

while read -r ip; do
  [[ -z "$ip" ]] && continue
  echo "===== FIX $ip ====="
  ssh -i "$SSH_KEY" \
    -o ConnectTimeout=10 \
    -o StrictHostKeyChecking=accept-new \
    -o IdentitiesOnly=yes \
    "$SSH_USER@$ip" \
    "sudo -n bash -lc '
set -euo pipefail
echo [step] check-units
test -f /etc/systemd/system/knox-node-a.service
test -f /etc/systemd/system/knox-node-b.service
echo [step] download-binary
curl -fL --connect-timeout 10 --max-time 120 \"$BIN_URL\" -o /tmp/knox-node
echo [step] verify-binary
echo \"$BIN_SHA256  /tmp/knox-node\" | sha256sum -c -
echo [step] install-binary
install -m 0755 /tmp/knox-node /opt/knox/bin/knox-node
echo [step] restart-services
systemctl daemon-reload
systemctl enable knox-node-a knox-node-b
systemctl restart knox-node-a knox-node-b
sleep 2
echo -n svcA=; systemctl is-active knox-node-a || true
echo -n svcB=; systemctl is-active knox-node-b || true
'"
  echo
done < "$IPS_FILE"

echo "[OK] fix pass complete"
