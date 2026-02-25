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

tmp_out="$(mktemp)"
trap 'rm -f "$tmp_out"' EXIT

while read -r ip; do
  [[ -z "${ip// }" ]] && continue
  echo "== $ip =="
  ssh -n -i "$SSH_KEY" "${SSH_OPTS[@]}" "$SSH_USER@$ip" "bash -lc '
set -euo pipefail
for d in /var/lib/knox/node*; do
  [[ -d \"\$d\" ]] || continue
  n=\$(basename \"\$d\")
  h=\$(sudo env KNOX_PRINT_GENESIS_HASH=1 /opt/knox/bin/knox-node \"\$d\" 2>/dev/null \
    | grep -E \"^[0-9a-f]{64}\$\" | head -n1 || true)
  echo \"\$n \${h:-NONE}\"
done
'"
done < "$IPS_FILE" | tee "$tmp_out"

echo
echo "-- unique hashes --"
awk '
  /^[[:space:]]*node[0-9]+[[:space:]]+/ {
    h=$2
    if (h != "NONE") c[h]++
  }
  END {
    if (length(c) == 0) {
      print "NONE"
      exit 0
    }
    for (h in c) printf "%s %d\n", h, c[h]
  }
' "$tmp_out" | sort
