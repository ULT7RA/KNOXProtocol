#!/usr/bin/env bash
set -euo pipefail

DIR="${1:-launch-mainnet/cloud-init-6vm}"

fail() {
  echo "[FAIL] $1"
  exit 1
}

test -d "$DIR" || fail "missing directory: $DIR"

for vm in 1 2 3 4 5 6; do
  f="$DIR/vm${vm}.yaml"
  test -f "$f" || fail "missing file: $f"
  grep -q '^#cloud-config$' "$f" || fail "not cloud-config: $f"
  grep -q 'users:' "$f" || fail "missing users block: $f"
  grep -q '  - default' "$f" || fail "missing default user passthrough: $f"
  grep -q '  - name: knox' "$f" || fail "missing knox user: $f"
  grep -q '/home/ubuntu/.ssh/authorized_keys' "$f" || fail "missing ubuntu authorized_keys file: $f"
  grep -q 'ExecStart=/opt/knox/bin/knox-node /var/lib/knox/node' "$f" || fail "missing ExecStart: $f"
  grep -q 'EnvironmentFile=/etc/default/knox-node-a' "$f" || fail "missing node-a env: $f"
  grep -q 'EnvironmentFile=/etc/default/knox-node-b' "$f" || fail "missing node-b env: $f"
done

for vm in 1 2 3 4; do
  f="$DIR/vm${vm}.yaml"
  grep -q 'KNOX_NODE_RPC_ALLOW_REMOTE=0' "$f" || fail "validator VM has wrong RPC remote setting: $f"
done

for vm in 5 6; do
  f="$DIR/vm${vm}.yaml"
  grep -q 'KNOX_NODE_RPC_ALLOW_REMOTE=1' "$f" || fail "rpc/explorer VM missing remote RPC setting: $f"
done

test -f "$DIR/cluster-map.txt" || fail "missing cluster map"
grep -q '^vm1 ' "$DIR/cluster-map.txt" || fail "cluster map missing vm1"
grep -q '^vm6 ' "$DIR/cluster-map.txt" || fail "cluster map missing vm6"

echo "[OK] cloud-init 6VM files validated: $DIR"
