#!/usr/bin/env bash
set -euo pipefail

SSH_KEY="${SSH_KEY:-$HOME/.ssh/knox_oracle}"
SSH_USER="${SSH_USER:-ubuntu}"
BIN_LOCAL="${KNOX_NODE_BIN_LOCAL:-target/release-lite/knox-node}"
SSH_OPTS=(
  -o ConnectTimeout=10
  -o StrictHostKeyChecking=accept-new
  -o IdentitiesOnly=yes
)

if [[ ! -f "$BIN_LOCAL" ]]; then
  echo "[FAIL] missing local binary: $BIN_LOCAL" >&2
  echo "Build first: cargo build -p knox-node --bin knox-node --profile release-lite" >&2
  exit 1
fi
if [[ ! -f "$SSH_KEY" ]]; then
  echo "[FAIL] missing ssh key: $SSH_KEY" >&2
  exit 1
fi

if [[ "$#" -eq 0 ]]; then
  set -- 129.146.133.68 132.226.119.131
fi

for ip in "$@"; do
  echo "=== REPAIR $ip ==="
  remote_bin="/home/$SSH_USER/knox-node.new"
  scp -i "$SSH_KEY" "${SSH_OPTS[@]}" "$BIN_LOCAL" "$SSH_USER@$ip:$remote_bin"
  ssh -i "$SSH_KEY" "${SSH_OPTS[@]}" "$SSH_USER@$ip" "sudo SSH_USER=$SSH_USER bash -s" <<'EOF'
set -euo pipefail
install -m 0755 /home/$SSH_USER/knox-node.new /opt/knox/bin/knox-node
systemctl daemon-reload
systemctl reset-failed knox-node-a knox-node-b || true
systemctl stop knox-node-a knox-node-b || true
sleep 1
systemctl start knox-node-a knox-node-b

ok=0
for _ in $(seq 1 20); do
  a="$(systemctl is-active knox-node-a || true)"
  b="$(systemctl is-active knox-node-b || true)"
  if [[ "$a" == "active" && "$b" == "active" ]] \
     && ss -ltn 2>/dev/null | grep -q ":9736" \
     && ss -ltn 2>/dev/null | grep -q ":9746"; then
    ok=1
    break
  fi
  sleep 1
done

echo -n "svcA="; systemctl is-active knox-node-a || true
echo -n "svcB="; systemctl is-active knox-node-b || true
echo "-- rpc listeners --"
ss -ltnp | grep -E ":9736|:9746" || true
echo "-- recent node logs --"
journalctl -u knox-node-a -u knox-node-b -n 120 --no-pager | tail -n 120

if [[ "$ok" -ne 1 ]]; then
  echo "[FAIL] services did not become healthy" >&2
  echo "-- systemctl status a --" >&2
  systemctl status knox-node-a --no-pager -l >&2 || true
  echo "-- systemctl status b --" >&2
  systemctl status knox-node-b --no-pager -l >&2 || true
  exit 1
fi
EOF
  echo
done

echo "[OK] repair complete"
