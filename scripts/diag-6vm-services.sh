#!/usr/bin/env bash
set -euo pipefail

IPS_FILE="${1:-launch-mainnet/public-ips.txt}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/knox_oracle}"
SSH_USER="${SSH_USER:-ubuntu}"

if [[ ! -f "$IPS_FILE" ]]; then
  echo "missing ips file: $IPS_FILE"
  exit 1
fi

while read -r ip; do
  [[ -z "$ip" ]] && continue
  echo "===== DIAG $ip ====="
  ssh -i "$SSH_KEY" \
    -o ConnectTimeout=10 \
    -o StrictHostKeyChecking=accept-new \
    -o IdentitiesOnly=yes \
    "$SSH_USER@$ip" \
    "sudo bash -lc '
set +e
echo host=\$(hostname)
echo arch=\$(uname -m)
echo --- cloud-init ---
cloud-init status --long 2>/dev/null || true
echo --- binary ---
ls -l /opt/knox/bin/knox-node 2>/dev/null || true
file /opt/knox/bin/knox-node 2>/dev/null || true
echo --- knox-node-a ---
systemctl show knox-node-a -p LoadState -p UnitFileState -p ActiveState -p SubState -p Result -p ExecMainCode -p ExecMainStatus
journalctl -u knox-node-a -n 30 --no-pager
echo --- knox-node-b ---
systemctl show knox-node-b -p LoadState -p UnitFileState -p ActiveState -p SubState -p Result -p ExecMainCode -p ExecMainStatus
journalctl -u knox-node-b -n 30 --no-pager
'"
  echo
done < "$IPS_FILE"
