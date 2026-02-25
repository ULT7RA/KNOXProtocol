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

i=0
while read -r ip; do
  [[ -z "${ip// }" ]] && continue
  i=$((i + 1))
  n1=$((2 * i - 1))
  n2=$((2 * i))

  echo "===== $ip (node$n1,node$n2) ====="
  ssh -n -i "$SSH_KEY" "${SSH_OPTS[@]}" "$SSH_USER@$ip" "sudo bash -lc '
set -euo pipefail

for tag in a b; do
  svc=knox-node-\$tag
  echo \"-- \$svc state=\$(systemctl is-active \$svc || true)\"
  echo \"file-env:\"
  grep -E \"^KNOX_\" /etc/default/\$svc || true
  pid=\$(systemctl show -p MainPID --value \$svc)
  if [[ \"\$pid\" =~ ^[0-9]+\$ ]] && (( pid > 1 )); then
    echo \"runtime-env(pid=\$pid):\"
    tr \"\\0\" \"\\n\" < /proc/\$pid/environ | grep -E \"^KNOX_\" | sort || true
  else
    echo \"runtime-env: pid not running\"
  fi
done

for n in $n1 $n2; do
  d=/var/lib/knox/node\$n
  kf=\$d/node.key
  echo \"-- node\$n files\"
  if [[ -f \$kf ]]; then
    echo -n \"node.key sha256=\"; sha256sum \$kf | cut -d\" \" -f1
  else
    echo \"node.key missing\"
  fi
  if [[ -f \$d/validators.txt ]]; then
    echo \"legacy validators.txt present=YES\"
  else
    echo \"legacy validators.txt present=NO\"
  fi
  h=\$(env KNOX_PRINT_GENESIS_HASH=1 /opt/knox/bin/knox-node \$d 2>/dev/null \
      | grep -E \"^[0-9a-f]{64}\$\" | head -n1 || true)
  echo \"genesis=\${h:-NONE}\"
done

echo \"-- recent log flags (a)\" 
journalctl -u knox-node-a -n 80 --no-pager | \
  grep -E \"sealed genesis|mainnet lock violation|genesis hash mismatch|diamond|auth\" || true

echo \"-- recent log flags (b)\"
journalctl -u knox-node-b -n 80 --no-pager | \
  grep -E \"sealed genesis|mainnet lock violation|genesis hash mismatch|diamond|auth\" || true
'"
  echo
done < "$IPS_FILE"
