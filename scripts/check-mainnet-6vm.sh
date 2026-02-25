#!/usr/bin/env bash
set -euo pipefail

IPS_FILE="${1:-launch-mainnet/public-ips.txt}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/knox_oracle}"
SSH_USER="${SSH_USER:-ubuntu}"
SSH_OPTS="${SSH_OPTS:--o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes}"

if [[ ! -f "$IPS_FILE" ]]; then
  echo "missing ips file: $IPS_FILE"
  exit 1
fi

mapfile -t IPS < <(awk 'NF {gsub(/\r/,"",$1); print $1}' "$IPS_FILE")
if [[ "${#IPS[@]}" -ne 6 ]]; then
  echo "public ips file must have exactly 6 lines (found ${#IPS[@]})"
  exit 1
fi

declare -A SEEN=()
for ip in "${IPS[@]}"; do
  if [[ -n "${SEEN[$ip]:-}" ]]; then
    echo "duplicate public IP detected in $IPS_FILE: $ip"
    exit 1
  fi
  SEEN[$ip]=1
done

for ip in "${IPS[@]}"; do
  echo "===== $ip ====="
  # Intentionally do not force BatchMode so passphrase-protected keys still work.
  ssh -i "$SSH_KEY" $SSH_OPTS "${SSH_USER}@${ip}" \
    'echo "host=$(hostname)"; \
     echo -n "svcA="; systemctl is-active knox-node-a || true; \
     echo -n "svcB="; systemctl is-active knox-node-b || true; \
     echo "--- logs a ---"; sudo journalctl -u knox-node-a -n 60 --no-pager | grep -E "sealed genesis|sealed block|reject proposal|mainnet lock violation|error" | tail -n 4 || true; \
     echo "--- logs b ---"; sudo journalctl -u knox-node-b -n 60 --no-pager | grep -E "sealed genesis|sealed block|reject proposal|mainnet lock violation|error" | tail -n 4 || true'
  echo
done
