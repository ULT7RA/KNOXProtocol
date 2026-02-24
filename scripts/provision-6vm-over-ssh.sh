#!/usr/bin/env bash
set -euo pipefail

PUB_IPS_FILE="${1:-launch-mainnet/public-ips.txt}"
PRIV_IPS_FILE="${2:-launch-mainnet/ips.txt}"

SSH_KEY="${SSH_KEY:-$HOME/.ssh/knox_oracle}"
SSH_USER="${SSH_USER:-ubuntu}"
if [[ -n "${KEY_ROOT:-}" ]]; then
  KEY_ROOT="$KEY_ROOT"
elif [[ -d "keys-live" ]]; then
  KEY_ROOT="keys-live"
else
  KEY_ROOT="testnet"
fi
MAINNET_ENV="${MAINNET_ENV:-launch-mainnet/mainnet.env}"
BIN_URL="${KNOX_NODE_BIN_URL:-https://objectstorage.us-phoenix-1.oraclecloud.com/p/zwNH-5xPHIzNxuLA0pBtcVmC7G4Xe4AkReoLNzKnfawM-nPfwHFHMzxWifLDbQ6r/n/axiq79viclak/b/KNOXAUTO/o/knox-node}"
BIN_SHA256="${KNOX_NODE_BIN_SHA256:-fe8b57efbe6feb4822c4db6984d905e3db203665e1dc0386e298b81ad5976146}"
BIN_LOCAL="${KNOX_NODE_BIN_LOCAL:-}"
# Comma-separated 1..12 node ids to expose RPC publicly (example: "9,10").
PUBLIC_RPC_NODES="${KNOX_PUBLIC_RPC_NODES:-}"
# Comma-separated 1..12 node ids to disable mining on (default empty = mine everywhere).
NO_MINE_NODES="${KNOX_NODE_NO_MINE_NODES:-}"
SSH_OPTS=(-o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes)

fail() {
  echo "[FAIL] $1"
  exit 1
}

require_file() {
  local p="$1"
  [[ -f "$p" ]] || fail "missing file: $p"
}

get_env_var() {
  local name="$1"
  sed -n "s/^${name}=//p" "$MAINNET_ENV" | tr -d '\r\n'
}

node_in_csv() {
  local csv="$1"
  local needle="$2"
  IFS=',' read -r -a items <<< "$csv"
  for raw in "${items[@]}"; do
    local item
    item="$(echo "$raw" | tr -d '[:space:]')"
    [[ -z "$item" ]] && continue
    [[ "$item" == "$needle" ]] && return 0
  done
  return 1
}

endpoint_in_csv() {
  local csv="$1"
  local needle="$2"
  IFS=',' read -r -a items <<< "$csv"
  for raw in "${items[@]}"; do
    local item
    item="$(echo "$raw" | tr -d '[:space:]')"
    [[ -z "$item" ]] && continue
    [[ "$item" == "$needle" ]] && return 0
  done
  return 1
}

require_file "$PUB_IPS_FILE"
require_file "$PRIV_IPS_FILE"
require_file "$MAINNET_ENV"

[[ -f "$SSH_KEY" ]] || fail "missing ssh key: $SSH_KEY"
[[ "$BIN_SHA256" =~ ^[0-9a-fA-F]{64}$ ]] || fail "invalid BIN_SHA256"
if [[ -n "$BIN_LOCAL" ]]; then
  [[ -f "$BIN_LOCAL" ]] || fail "KNOX_NODE_BIN_LOCAL not found: $BIN_LOCAL"
fi

mapfile -t PUB_IPS < <(awk 'NF {gsub(/\r/,"",$1); print $1}' "$PUB_IPS_FILE")
mapfile -t PRIV_IPS_ALL < <(awk 'NF {gsub(/\r/,"",$1); print $1}' "$PRIV_IPS_FILE")
PRIV_IPS=("${PRIV_IPS_ALL[@]:0:6}")

[[ "${#PUB_IPS[@]}" -eq 6 ]] || fail "public ips file must have 6 lines"
[[ "${#PRIV_IPS[@]}" -eq 6 ]] || fail "private ips file must have at least 6 lines"

declare -A seen_pub=()
for ip in "${PUB_IPS[@]}"; do
  [[ -n "${seen_pub[$ip]:-}" ]] && fail "duplicate public IP: $ip"
  seen_pub[$ip]=1
done

for n in $(seq 1 12); do
  require_file "$KEY_ROOT/node$n/node.key"
done

PSK_SERVICE="$(get_env_var KNOX_P2P_PSK_SERVICE)"
PSK_ACCOUNT="$(get_env_var KNOX_P2P_PSK_ACCOUNT)"
PREMINE_ADDR="$(get_env_var KNOX_MAINNET_PREMINE_ADDRESS)"
GENESIS_HASH="$(get_env_var KNOX_MAINNET_GENESIS_HASH)"
DIAMOND_AUTH_PUBKEYS="$(get_env_var KNOX_DIAMOND_AUTH_PUBKEYS)"
DIAMOND_AUTH_QUORUM="$(get_env_var KNOX_DIAMOND_AUTH_QUORUM)"
DIAMOND_AUTH_ENDPOINTS="$(get_env_var KNOX_DIAMOND_AUTH_ENDPOINTS)"

[[ -n "$PSK_SERVICE" ]] || fail "KNOX_P2P_PSK_SERVICE missing in $MAINNET_ENV"
[[ -n "$PSK_ACCOUNT" ]] || fail "KNOX_P2P_PSK_ACCOUNT missing in $MAINNET_ENV"
[[ -n "$PREMINE_ADDR" ]] || fail "KNOX_MAINNET_PREMINE_ADDRESS missing in $MAINNET_ENV"
[[ -n "$DIAMOND_AUTH_PUBKEYS" ]] || fail "KNOX_DIAMOND_AUTH_PUBKEYS missing in $MAINNET_ENV"
[[ -n "$DIAMOND_AUTH_QUORUM" ]] || fail "KNOX_DIAMOND_AUTH_QUORUM missing in $MAINNET_ENV"
[[ -n "$DIAMOND_AUTH_ENDPOINTS" ]] || fail "KNOX_DIAMOND_AUTH_ENDPOINTS missing in $MAINNET_ENV"
declare -a ENDPOINTS
for n in $(seq 1 12); do
  vm=$(( (n - 1) / 2 + 1 ))
  slot=$(( (n - 1) % 2 + 1 ))
  if [[ "$slot" -eq 1 ]]; then
    p2p_port=9735
  else
    p2p_port=9745
  fi
  ENDPOINTS[$n]="${PRIV_IPS[$((vm - 1))]}:$p2p_port"
done

make_service() {
  local out="$1"
  local node="$2"
  local p2p="$3"
  local rpc_bind="$4"
  local peers_csv="$5"
  local tag="$6"
  cat > "$out" <<EOF
[Unit]
Description=KNOX Node ${tag} (n${node})
After=network-online.target
Wants=network-online.target

[Service]
User=knox
Group=knox
EnvironmentFile=/etc/default/knox-node-${tag}
ExecStart=/opt/knox/bin/knox-node /var/lib/knox/node${node} 0.0.0.0:${p2p} ${rpc_bind} "${peers_csv}" "${PREMINE_ADDR}"
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
}

tmp_root="$(mktemp -d)"
trap 'rm -rf "$tmp_root"' EXIT

for vm in $(seq 1 6); do
  n1=$((2 * vm - 1))
  n2=$((2 * vm))
  pub_ip="${PUB_IPS[$((vm - 1))]}"

  p2p1=9735
  p2p2=9745
  rpc1=9736
  rpc2=9746
  bind1="127.0.0.1:${rpc1}"
  bind2="127.0.0.1:${rpc2}"
  remote1=0
  remote2=0
  public1=0
  public2=0
  auth1=0
  auth2=0
  no_mine1=0
  no_mine2=0

  # Mirror cloud-init defaults: nodes 9..12 are Diamond Authenticator RPC nodes.
  if [[ "$n1" -ge 9 ]]; then
    bind1="0.0.0.0:${rpc1}"
    remote1=1
    no_mine1=1
  fi
  if [[ "$n2" -ge 9 ]]; then
    bind2="0.0.0.0:${rpc2}"
    remote2=1
    no_mine2=1
  fi

  if node_in_csv "$PUBLIC_RPC_NODES" "$n1"; then
    bind1="0.0.0.0:${rpc1}"
    remote1=1
    public1=1
  fi
  if node_in_csv "$PUBLIC_RPC_NODES" "$n2"; then
    bind2="0.0.0.0:${rpc2}"
    remote2=1
    public2=1
  fi
  # Diamond auth endpoints must be reachable cluster-wide even when not public.
  if endpoint_in_csv "$DIAMOND_AUTH_ENDPOINTS" "${PRIV_IPS[$((vm - 1))]}:${rpc1}" \
    || endpoint_in_csv "$DIAMOND_AUTH_ENDPOINTS" "${PUB_IPS[$((vm - 1))]}:${rpc1}"; then
    bind1="0.0.0.0:${rpc1}"
    remote1=1
    auth1=1
    no_mine1=1
  fi
  if endpoint_in_csv "$DIAMOND_AUTH_ENDPOINTS" "${PRIV_IPS[$((vm - 1))]}:${rpc2}" \
    || endpoint_in_csv "$DIAMOND_AUTH_ENDPOINTS" "${PUB_IPS[$((vm - 1))]}:${rpc2}"; then
    bind2="0.0.0.0:${rpc2}"
    remote2=1
    auth2=1
    no_mine2=1
  fi
  if node_in_csv "$NO_MINE_NODES" "$n1"; then
    no_mine1=1
  fi
  if node_in_csv "$NO_MINE_NODES" "$n2"; then
    no_mine2=1
  fi

  peers1=()
  peers2=()
  for j in $(seq 1 12); do
    [[ "$j" -ne "$n1" ]] && peers1+=("${ENDPOINTS[$j]}")
    [[ "$j" -ne "$n2" ]] && peers2+=("${ENDPOINTS[$j]}")
  done
  peers1_csv="$(IFS=,; echo "${peers1[*]}")"
  peers2_csv="$(IFS=,; echo "${peers2[*]}")"

  vm_dir="$tmp_root/vm$vm"
  mkdir -p "$vm_dir"

  cat > "$vm_dir/knox-node-a.env" <<EOF
KNOX_NODE_RPC_ALLOW_REMOTE=$remote1
KNOX_MAINNET_LOCK=1
KNOX_MAINNET_PREMINE_ADDRESS=$PREMINE_ADDR
KNOX_MAINNET_GENESIS_HASH=$GENESIS_HASH
KNOX_DIAMOND_AUTH_PUBKEYS=$DIAMOND_AUTH_PUBKEYS
KNOX_DIAMOND_AUTH_QUORUM=$DIAMOND_AUTH_QUORUM
KNOX_DIAMOND_AUTH_ENDPOINTS=$DIAMOND_AUTH_ENDPOINTS
EOF
  if [[ "$no_mine1" -eq 1 ]]; then
    echo "KNOX_NODE_NO_MINE=1" >> "$vm_dir/knox-node-a.env"
  fi

  cat > "$vm_dir/knox-node-b.env" <<EOF
KNOX_NODE_RPC_ALLOW_REMOTE=$remote2
KNOX_MAINNET_LOCK=1
KNOX_MAINNET_PREMINE_ADDRESS=$PREMINE_ADDR
KNOX_MAINNET_GENESIS_HASH=$GENESIS_HASH
KNOX_DIAMOND_AUTH_PUBKEYS=$DIAMOND_AUTH_PUBKEYS
KNOX_DIAMOND_AUTH_QUORUM=$DIAMOND_AUTH_QUORUM
KNOX_DIAMOND_AUTH_ENDPOINTS=$DIAMOND_AUTH_ENDPOINTS
EOF
  if [[ "$no_mine2" -eq 1 ]]; then
    echo "KNOX_NODE_NO_MINE=1" >> "$vm_dir/knox-node-b.env"
  fi

  make_service "$vm_dir/knox-node-a.service" "$n1" "$p2p1" "$bind1" "$peers1_csv" "a"
  make_service "$vm_dir/knox-node-b.service" "$n2" "$p2p2" "$bind2" "$peers2_csv" "b"

  cp "$KEY_ROOT/node$n1/node.key" "$vm_dir/node$n1.key"
  cp "$KEY_ROOT/node$n2/node.key" "$vm_dir/node$n2.key"
  if [[ -n "$BIN_LOCAL" ]]; then
    cp "$BIN_LOCAL" "$vm_dir/knox-node"
    chmod 0755 "$vm_dir/knox-node"
  fi

  echo "===== PROVISION vm${vm} ${pub_ip} (n${n1},n${n2}) ====="

  ssh -i "$SSH_KEY" "${SSH_OPTS[@]}" "$SSH_USER@$pub_ip" "mkdir -p /home/$SSH_USER/knox-bootstrap && rm -f /home/$SSH_USER/knox-bootstrap/* && sudo mkdir -p /opt/knox/bin /etc/default /etc/systemd/system /var/lib/knox/node$n1 /var/lib/knox/node$n2"
  scp -i "$SSH_KEY" "${SSH_OPTS[@]}" "$vm_dir/"* "$SSH_USER@$pub_ip:/home/$SSH_USER/knox-bootstrap/"

  private_allow_csv="$(IFS=,; echo "${PRIV_IPS[*]}")"
  ssh -i "$SSH_KEY" "${SSH_OPTS[@]}" "$SSH_USER@$pub_ip" "sudo bash -lc '
set -euo pipefail
private_allow_csv=\"$private_allow_csv\"
rpc1_public=\"$public1\"
rpc2_public=\"$public2\"
rpc1_auth=\"$auth1\"
rpc2_auth=\"$auth2\"
id -u knox >/dev/null 2>&1 || useradd -m -s /bin/bash -G sudo knox
install -m 0640 /home/$SSH_USER/knox-bootstrap/knox-node-a.env /etc/default/knox-node-a
install -m 0640 /home/$SSH_USER/knox-bootstrap/knox-node-b.env /etc/default/knox-node-b
install -m 0644 /home/$SSH_USER/knox-bootstrap/knox-node-a.service /etc/systemd/system/knox-node-a.service
install -m 0644 /home/$SSH_USER/knox-bootstrap/knox-node-b.service /etc/systemd/system/knox-node-b.service
install -m 0600 /home/$SSH_USER/knox-bootstrap/node$n1.key /var/lib/knox/node$n1/node.key
install -m 0600 /home/$SSH_USER/knox-bootstrap/node$n2.key /var/lib/knox/node$n2/node.key
chown -R knox:knox /var/lib/knox
if [[ -f /home/$SSH_USER/knox-bootstrap/knox-node ]]; then
  cp /home/$SSH_USER/knox-bootstrap/knox-node /tmp/knox-node
else
  curl -fL --connect-timeout 10 --max-time 120 \"$BIN_URL\" -o /tmp/knox-node
fi
echo \"$BIN_SHA256  /tmp/knox-node\" | sha256sum -c -
install -m 0755 /tmp/knox-node /opt/knox/bin/knox-node
if ! command -v ufw >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y ufw
fi
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow $p2p1/tcp
ufw allow $p2p2/tcp
if [[ \"\$rpc1_public\" == \"1\" ]]; then
  ufw allow $rpc1/tcp
elif [[ \"\$rpc1_auth\" == \"1\" ]]; then
  IFS=\",\" read -r -a ips <<< \"\$private_allow_csv\"
  for src in \"\${ips[@]}\"; do
    [[ -z \"\$src\" ]] && continue
    ufw allow from \"\$src\" to any port $rpc1 proto tcp
  done
fi
if [[ \"\$rpc2_public\" == \"1\" ]]; then
  ufw allow $rpc2/tcp
elif [[ \"\$rpc2_auth\" == \"1\" ]]; then
  IFS=\",\" read -r -a ips <<< \"\$private_allow_csv\"
  for src in \"\${ips[@]}\"; do
    [[ -z \"\$src\" ]] && continue
    ufw allow from \"\$src\" to any port $rpc2 proto tcp
  done
fi
ufw --force enable
systemctl daemon-reload
systemctl enable knox-node-a knox-node-b
systemctl restart knox-node-a knox-node-b
sleep 2
echo -n svcA=; systemctl is-active knox-node-a || true
echo -n svcB=; systemctl is-active knox-node-b || true
'"
  echo
done

echo "[OK] provision pass complete"
