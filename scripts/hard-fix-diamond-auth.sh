#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PUB_FILE="${1:-launch-mainnet/public-ips.txt}"
PRIV_FILE="${2:-launch-mainnet/ips.txt}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/knox_oracle}"
SSH_USER="${SSH_USER:-ubuntu}"
BIN_LOCAL="${KNOX_NODE_BIN_LOCAL:-target/release-lite/knox-node}"
SSH_OPTS=(
  -o ConnectTimeout=10
  -o StrictHostKeyChecking=accept-new
  -o IdentitiesOnly=yes
)

need_file() {
  local p="$1"
  [[ -f "$p" ]] || {
    echo "[FAIL] missing file: $p" >&2
    exit 1
  }
}

need_file "$PUB_FILE"
need_file "$PRIV_FILE"
need_file "$SSH_KEY"
need_file "$BIN_LOCAL"

mapfile -t PUB_IPS < <(awk 'NF {gsub(/\r/,"",$1); print $1}' "$PUB_FILE")
mapfile -t PRIV_IPS_ALL < <(awk 'NF {gsub(/\r/,"",$1); print $1}' "$PRIV_FILE")
PRIV_IPS=("${PRIV_IPS_ALL[@]:0:6}")

[[ "${#PUB_IPS[@]}" -eq 6 ]] || { echo "[FAIL] $PUB_FILE must have 6 lines" >&2; exit 1; }
[[ "${#PRIV_IPS[@]}" -eq 6 ]] || { echo "[FAIL] $PRIV_FILE must have at least 6 lines" >&2; exit 1; }

# Signer topology: nodes 5..8 live on VM3+VM4.
SIGNER_PUBS=("${PUB_IPS[2]}" "${PUB_IPS[3]}")
SIGNER_PRIVS=("${PRIV_IPS[2]}" "${PRIV_IPS[3]}")
CHECKERS=("${PUB_IPS[0]}" "${PUB_IPS[1]}")

echo "[STEP 1/5] Install one binary hash on all 6 VMs"
LOCAL_SHA="$(sha256sum "$BIN_LOCAL" | awk '{print $1}')"
for ip in "${PUB_IPS[@]}"; do
  echo "=== SYNC BIN $ip ==="
  remote_bin="/home/$SSH_USER/knox-node.new"
  scp -i "$SSH_KEY" "${SSH_OPTS[@]}" "$BIN_LOCAL" "$SSH_USER@$ip:$remote_bin"
  ssh -i "$SSH_KEY" "${SSH_OPTS[@]}" "$SSH_USER@$ip" "sudo SSH_USER=$SSH_USER LOCAL_SHA=$LOCAL_SHA bash -s" <<'EOF'
set -euo pipefail
install -m 0755 /home/$SSH_USER/knox-node.new /opt/knox/bin/knox-node
remote_sha="$(sha256sum /opt/knox/bin/knox-node | awk '{print $1}')"
echo "remote_sha=$remote_sha"
if [[ "$remote_sha" != "$LOCAL_SHA" ]]; then
  echo "[FAIL] binary hash mismatch after install" >&2
  exit 1
fi
systemctl daemon-reload
systemctl restart knox-node-a knox-node-b
sleep 2
echo -n "svcA="; systemctl is-active knox-node-a || true
echo -n "svcB="; systemctl is-active knox-node-b || true
EOF
  echo
done

echo "[STEP 2/5] Force signer RPC env + unit bind on VM3/VM4"
for ip in "${SIGNER_PUBS[@]}"; do
  echo "=== PATCH $ip ==="
  ssh -i "$SSH_KEY" "${SSH_OPTS[@]}" "$SSH_USER@$ip" "sudo bash -s" <<'EOF'
set -euo pipefail

for f in /etc/default/knox-node-a /etc/default/knox-node-b; do
  if grep -q '^KNOX_NODE_RPC_ALLOW_REMOTE=' "$f"; then
    sed -i 's/^KNOX_NODE_RPC_ALLOW_REMOTE=.*/KNOX_NODE_RPC_ALLOW_REMOTE=1/' "$f"
  else
    echo 'KNOX_NODE_RPC_ALLOW_REMOTE=1' >> "$f"
  fi
done

# Signer RPC must bind non-loopback for Diamond Auth requests.
sed -i 's/127\.0\.0\.1:9736/0.0.0.0:9736/g' /etc/systemd/system/knox-node-a.service || true
sed -i 's/127\.0\.0\.1:9746/0.0.0.0:9746/g' /etc/systemd/system/knox-node-b.service || true

systemctl daemon-reload
systemctl reset-failed knox-node-a knox-node-b || true
systemctl restart knox-node-a knox-node-b
sleep 3

if ! command -v ufw >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y ufw
fi
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 9735/tcp
ufw allow 9745/tcp
ufw allow from 10.0.0.0/24 to any port 9736 proto tcp
ufw allow from 10.0.0.0/24 to any port 9746 proto tcp
ufw --force enable

echo -n "svcA="; systemctl is-active knox-node-a || true
echo -n "svcB="; systemctl is-active knox-node-b || true
echo "-- env --"
grep '^KNOX_NODE_RPC_ALLOW_REMOTE=' /etc/default/knox-node-a /etc/default/knox-node-b || true
echo "-- listeners --"
ss -ltnp | grep -E ':9736|:9746' || true
echo "-- ufw --"
ufw status numbered || true
EOF
  echo
done

echo "[STEP 3/5] Validate private-path TCP reachability from VM1/VM2 to signer RPC ports"
for src in "${CHECKERS[@]}"; do
  echo "=== PROBE from $src ==="
  ssh -i "$SSH_KEY" "${SSH_OPTS[@]}" "$SSH_USER@$src" "bash -s" <<EOF
set -euo pipefail
for ep in \
  ${SIGNER_PRIVS[0]}:9736 ${SIGNER_PRIVS[0]}:9746 \
  ${SIGNER_PRIVS[1]}:9736 ${SIGNER_PRIVS[1]}:9746
do
  host="\${ep%:*}"
  port="\${ep#*:}"
  if timeout 2 bash -c "exec 3<>/dev/tcp/\$host/\$port" >/dev/null 2>&1; then
    echo "ok   \$ep"
  else
    echo "FAIL \$ep" >&2
    exit 1
  fi
done
EOF
  echo
done

echo "[STEP 4/5] Check cluster services are active"
for ip in "${PUB_IPS[@]}"; do
  echo "=== HEALTH $ip ==="
  ssh -i "$SSH_KEY" "${SSH_OPTS[@]}" "$SSH_USER@$ip" \
    'echo -n "svcA="; systemctl is-active knox-node-a; echo -n "svcB="; systemctl is-active knox-node-b'
done
echo

echo "[STEP 5/5] Fail fast if current logs still show auth-path errors"
had_err=0
for ip in "${PUB_IPS[@]}"; do
  out="$(ssh -i "$SSH_KEY" "${SSH_OPTS[@]}" "$SSH_USER@$ip" \
    "sudo journalctl -u knox-node-a -u knox-node-b --since '-90 sec' --no-pager \
      | grep -E 'rpc bind error|quorum unmet|endpoint .* failed' || true")"
  if [[ -n "$out" ]]; then
    had_err=1
    echo "=== ERRORS $ip ==="
    echo "$out"
    echo
  fi
done

if [[ "$had_err" -ne 0 ]]; then
  echo "[FAIL] Diamond auth path still unhealthy (see ERRORS sections above)." >&2
  exit 1
fi

echo "[OK] Diamond auth path is healthy (no bind/quorum/endpoint errors in the last 90s)."
