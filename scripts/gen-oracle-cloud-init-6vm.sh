#!/usr/bin/env bash
set -euo pipefail

IPS_FILE="${1:-launch-mainnet/ips.txt}"
PREMINE_ADDR="${2:-}"
PSK_SERVICE="${KNOX_P2P_PSK_SERVICE:-knox-p2p}"
PSK_ACCOUNT="${KNOX_P2P_PSK_ACCOUNT:-mainnet}"
GENESIS_HASH="${KNOX_MAINNET_GENESIS_HASH:-}"
NODE_BIN_URL="${KNOX_NODE_BIN_URL:-}"
NODE_BIN_SHA256="${KNOX_NODE_BIN_SHA256:-}"
SSH_PUBKEY="${KNOX_SSH_PUBKEY:-}"
KEY_ROOT="${KEY_ROOT:-testnet}"
OUT_DIR="${OUT_DIR:-launch-mainnet/cloud-init-6vm}"
AUTH_NODES_CSV="${KNOX_DIAMOND_AUTH_NODES:-9,10,11,12}"
AUTH_QUORUM="${KNOX_DIAMOND_AUTH_QUORUM:-2}"
TOOLCHAIN="${KNOX_TESTNET_TOOLCHAIN:-stable}"

if [[ -z "$PREMINE_ADDR" ]]; then
  echo "usage: $0 <ips_file> <premine_address>"
  exit 1
fi
if [[ ! "$PREMINE_ADDR" =~ ^knox1[0-9a-fA-F]{32,}$ ]]; then
  echo "invalid premine address format: expected knox1 + hex payload"
  exit 1
fi

if [[ ! -f "$IPS_FILE" ]]; then
  echo "missing ips file: $IPS_FILE"
  exit 1
fi

if [[ -n "$GENESIS_HASH" ]] && [[ ! "$GENESIS_HASH" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "KNOX_MAINNET_GENESIS_HASH must be 64 hex chars when set"
  exit 1
fi
if [[ -n "$NODE_BIN_SHA256" ]] && [[ ! "$NODE_BIN_SHA256" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "KNOX_NODE_BIN_SHA256 must be 64 hex chars when set"
  exit 1
fi
if [[ -z "$SSH_PUBKEY" ]]; then
  echo "KNOX_SSH_PUBKEY is required (export your ssh public key before generating)"
  exit 1
fi
if [[ ! "$SSH_PUBKEY" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)[[:space:]] ]]; then
  echo "KNOX_SSH_PUBKEY format invalid"
  exit 1
fi

mapfile -t IPS_ALL < <(awk 'NF {gsub(/\r/,"",$1); print $1}' "$IPS_FILE")
if [[ "${#IPS_ALL[@]}" -lt 6 ]]; then
  echo "ips file must contain at least 6 lines (found ${#IPS_ALL[@]})"
  exit 1
fi
IPS=("${IPS_ALL[@]:0:6}")

declare -A IP_SEEN=()
for ip in "${IPS[@]}"; do
  if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "invalid IP in $IPS_FILE: $ip"
    exit 1
  fi
  if [[ -n "${IP_SEEN[$ip]:-}" ]]; then
    echo "duplicate IP in first 6 entries: $ip"
    exit 1
  fi
  IP_SEEN[$ip]=1
done

for n in $(seq 1 12); do
  if [[ ! -f "$KEY_ROOT/node$n/node.key" ]]; then
    echo "missing key: $KEY_ROOT/node$n/node.key"
    exit 1
  fi
done

if [[ ! "$AUTH_QUORUM" =~ ^[0-9]+$ ]] || [[ "$AUTH_QUORUM" -lt 1 ]]; then
  echo "KNOX_DIAMOND_AUTH_QUORUM must be an integer >= 1"
  exit 1
fi

mkdir -p "$OUT_DIR"
mkdir -p launch-mainnet

declare -a ENDPOINTS
for n in $(seq 1 12); do
  vm=$(( (n - 1) / 2 + 1 ))
  slot=$(( (n - 1) % 2 + 1 ))
  if [[ "$slot" -eq 1 ]]; then
    p2p_port=9735
  else
    p2p_port=9745
  fi
  ENDPOINTS[$n]="${IPS[$((vm - 1))]}:$p2p_port"
done

auth_nodes=()
IFS=',' read -r -a raw_auth_nodes <<< "$AUTH_NODES_CSV"
for raw in "${raw_auth_nodes[@]}"; do
  node="$(echo "$raw" | tr -d '[:space:]')"
  [[ -z "$node" ]] && continue
  if [[ ! "$node" =~ ^[0-9]+$ ]] || [[ "$node" -lt 1 ]] || [[ "$node" -gt 12 ]]; then
    echo "invalid authenticator node id: $node (expected 1..12)"
    exit 1
  fi
  auth_nodes+=("$node")
done
if [[ "${#auth_nodes[@]}" -eq 0 ]]; then
  echo "no authenticator nodes configured (KNOX_DIAMOND_AUTH_NODES)"
  exit 1
fi
if [[ "$AUTH_QUORUM" -gt "${#auth_nodes[@]}" ]]; then
  echo "KNOX_DIAMOND_AUTH_QUORUM ($AUTH_QUORUM) exceeds authenticator count (${#auth_nodes[@]})"
  exit 1
fi
declare -A AUTH_LOOKUP=()
for node in "${auth_nodes[@]}"; do
  AUTH_LOOKUP["$node"]=1
done

auth_pubkeys=()
auth_endpoints=()
for node in "${auth_nodes[@]}"; do
  key_file="$KEY_ROOT/node$node/node.key"
  key_hex="$(tr -d '\r\n[:space:]' < "$key_file")"
  if [[ "${#key_hex}" -ne 128 ]]; then
    echo "invalid node key format in $key_file (expected 128 hex chars)"
    exit 1
  fi
  sk_hex="${key_hex:0:64}"
  auth_pk="$(cargo +"$TOOLCHAIN" run -p knox-keygen --quiet -- --consensus-public-from-secret "$sk_hex")"
  if [[ -z "$auth_pk" ]]; then
    echo "failed deriving authenticator key for node$node"
    exit 1
  fi
  auth_pubkeys+=("$auth_pk")

  vm=$(( (node - 1) / 2 + 1 ))
  slot=$(( (node - 1) % 2 + 1 ))
  if [[ "$slot" -eq 1 ]]; then
    auth_rpc_port=9736
  else
    auth_rpc_port=9746
  fi
  auth_endpoints+=("${IPS[$((vm - 1))]}:${auth_rpc_port}")
done

AUTH_PUBKEYS_CSV="$(IFS=,; echo "${auth_pubkeys[*]}")"
AUTH_ENDPOINTS_CSV="$(IFS=,; echo "${auth_endpoints[*]}")"

{
  echo "KNOX_P2P_PSK_SERVICE=$PSK_SERVICE"
  echo "KNOX_P2P_PSK_ACCOUNT=$PSK_ACCOUNT"
  echo "KNOX_MAINNET_LOCK=1"
  echo "KNOX_MAINNET_PREMINE_ADDRESS=$PREMINE_ADDR"
  echo "KNOX_MAINNET_GENESIS_HASH=$GENESIS_HASH"
  echo "KNOX_DIAMOND_AUTH_PUBKEYS=$AUTH_PUBKEYS_CSV"
  echo "KNOX_DIAMOND_AUTH_QUORUM=$AUTH_QUORUM"
  echo "KNOX_DIAMOND_AUTH_ENDPOINTS=$AUTH_ENDPOINTS_CSV"
} > launch-mainnet/mainnet.env

node_role() {
  local n="$1"
  if [[ "$n" -le 8 ]]; then
    echo "miner"
  elif [[ "$n" -le 10 ]]; then
    echo "rpc"
  else
    echo "explorer"
  fi
}

{
  echo "# Auto-generated by scripts/gen-oracle-cloud-init-6vm.sh"
  echo "# vm1..vm4: 8 miners, vm5: 2 rpc, vm6: 2 explorer"
  for vm in $(seq 1 6); do
    n1=$((2 * vm - 1))
    n2=$((2 * vm))
    r1="$(node_role "$n1")"
    r2="$(node_role "$n2")"
    echo "vm${vm} ${IPS[$((vm - 1))]} n${n1}(${r1}) n${n2}(${r2})"
  done
} > "$OUT_DIR/cluster-map.txt"

emit_env_file() {
  local n="$1"
  local remote="$2"
  local no_mine="$3"
  echo "      KNOX_P2P_PSK_SERVICE=$PSK_SERVICE"
  echo "      KNOX_P2P_PSK_ACCOUNT=$PSK_ACCOUNT"
  echo "      KNOX_NODE_RPC_ALLOW_REMOTE=$remote"
  if [[ "$no_mine" -eq 1 ]]; then
    echo "      KNOX_NODE_NO_MINE=1"
  fi
  echo "      KNOX_MAINNET_LOCK=1"
  echo "      KNOX_MAINNET_PREMINE_ADDRESS=$PREMINE_ADDR"
  echo "      KNOX_MAINNET_GENESIS_HASH=$GENESIS_HASH"
  echo "      KNOX_DIAMOND_AUTH_PUBKEYS=$AUTH_PUBKEYS_CSV"
  echo "      KNOX_DIAMOND_AUTH_QUORUM=$AUTH_QUORUM"
  echo "      KNOX_DIAMOND_AUTH_ENDPOINTS=$AUTH_ENDPOINTS_CSV"
}

for vm in $(seq 1 6); do
  n1=$((2 * vm - 1))
  n2=$((2 * vm))

  p2p1=9735
  p2p2=9745
  rpc1=9736
  rpc2=9746

  role1="$(node_role "$n1")"
  role2="$(node_role "$n2")"

  remote1=0
  remote2=0
  no_mine1=0
  no_mine2=0
  auth1=0
  auth2=0
  bind1="127.0.0.1:$rpc1"
  bind2="127.0.0.1:$rpc2"
  if [[ "$n1" -ge 9 ]]; then
    remote1=1
    no_mine1=1
    bind1="0.0.0.0:$rpc1"
  fi
  if [[ "$n2" -ge 9 ]]; then
    remote2=1
    no_mine2=1
    bind2="0.0.0.0:$rpc2"
  fi
  if [[ -n "${AUTH_LOOKUP[$n1]:-}" ]]; then
    auth1=1
    remote1=1
    bind1="0.0.0.0:$rpc1"
    no_mine1=1
  fi
  if [[ -n "${AUTH_LOOKUP[$n2]:-}" ]]; then
    auth2=1
    remote2=1
    bind2="0.0.0.0:$rpc2"
    no_mine2=1
  fi

  peers1=()
  peers2=()
  for j in $(seq 1 12); do
    if [[ "$j" -ne "$n1" ]]; then
      peers1+=("${ENDPOINTS[$j]}")
    fi
    if [[ "$j" -ne "$n2" ]]; then
      peers2+=("${ENDPOINTS[$j]}")
    fi
  done
  peers1_csv="$(IFS=,; echo "${peers1[*]}")"
  peers2_csv="$(IFS=,; echo "${peers2[*]}")"

  key1="$(tr -d '\r\n' < "$KEY_ROOT/node$n1/node.key")"
  key2="$(tr -d '\r\n' < "$KEY_ROOT/node$n2/node.key")"

  out="$OUT_DIR/vm${vm}.yaml"
  {
    echo "#cloud-config"
    echo "package_update: true"
    echo "package_upgrade: true"
    echo "packages:"
    echo "  - ca-certificates"
    echo "  - curl"
    echo "  - ufw"
    echo "users:"
    echo "  - default"
    echo "  - name: knox"
    echo "    shell: /bin/bash"
    echo "    groups: [sudo]"
    echo "    sudo: [\"ALL=(ALL) NOPASSWD:ALL\"]"
    echo "write_files:"
    echo "  - path: /etc/default/knox-node-a"
    echo "    permissions: \"0640\""
    echo "    owner: root:root"
    echo "    content: |"
    emit_env_file "$n1" "$remote1" "$no_mine1"
    echo "  - path: /etc/default/knox-node-b"
    echo "    permissions: \"0640\""
    echo "    owner: root:root"
    echo "    content: |"
    emit_env_file "$n2" "$remote2" "$no_mine2"
    echo "  - path: /var/lib/knox/node$n1/node.key"
    echo "    permissions: \"0600\""
    echo "    owner: knox:knox"
    echo "    content: |"
    echo "      $key1"
    echo "  - path: /var/lib/knox/node$n2/node.key"
    echo "    permissions: \"0600\""
    echo "    owner: knox:knox"
    echo "    content: |"
    echo "      $key2"
    echo "  - path: /etc/systemd/system/knox-node-a.service"
    echo "    permissions: \"0644\""
    echo "    owner: root:root"
    echo "    content: |"
    echo "      [Unit]"
    echo "      Description=KNOX Node A (n$n1, role=$role1)"
    echo "      After=network-online.target"
    echo "      Wants=network-online.target"
    echo "      [Service]"
    echo "      User=knox"
    echo "      Group=knox"
    echo "      EnvironmentFile=/etc/default/knox-node-a"
    echo "      ExecStart=/opt/knox/bin/knox-node /var/lib/knox/node$n1 0.0.0.0:$p2p1 $bind1 \"$peers1_csv\" \"$PREMINE_ADDR\""
    echo "      Restart=always"
    echo "      RestartSec=2"
    echo "      LimitNOFILE=1048576"
    echo "      [Install]"
    echo "      WantedBy=multi-user.target"
    echo "  - path: /etc/systemd/system/knox-node-b.service"
    echo "    permissions: \"0644\""
    echo "    owner: root:root"
    echo "    content: |"
    echo "      [Unit]"
    echo "      Description=KNOX Node B (n$n2, role=$role2)"
    echo "      After=network-online.target"
    echo "      Wants=network-online.target"
    echo "      [Service]"
    echo "      User=knox"
    echo "      Group=knox"
    echo "      EnvironmentFile=/etc/default/knox-node-b"
    echo "      ExecStart=/opt/knox/bin/knox-node /var/lib/knox/node$n2 0.0.0.0:$p2p2 $bind2 \"$peers2_csv\" \"$PREMINE_ADDR\""
    echo "      Restart=always"
    echo "      RestartSec=2"
    echo "      LimitNOFILE=1048576"
    echo "      [Install]"
    echo "      WantedBy=multi-user.target"
    echo "  - path: /home/ubuntu/.ssh/authorized_keys"
    echo "    permissions: \"0600\""
    echo "    owner: root:root"
    echo "    content: |"
    echo "      $SSH_PUBKEY"
    echo "runcmd:"
    echo "  - mkdir -p /opt/knox/bin /var/lib/knox/node$n1 /var/lib/knox/node$n2"
    echo "  - mkdir -p /home/ubuntu/.ssh"
    echo "  - chown -R knox:knox /var/lib/knox"
    echo "  - chown -R ubuntu:ubuntu /home/ubuntu/.ssh"
    echo "  - chmod 700 /home/ubuntu/.ssh"
    echo "  - chmod 600 /home/ubuntu/.ssh/authorized_keys"
    if [[ -n "$NODE_BIN_URL" ]]; then
      echo "  - bash -lc 'curl -fsSL \"$NODE_BIN_URL\" -o /opt/knox/bin/knox-node'"
      echo "  - chmod 0755 /opt/knox/bin/knox-node"
      if [[ -n "$NODE_BIN_SHA256" ]]; then
        echo "  - bash -lc 'echo \"$NODE_BIN_SHA256  /opt/knox/bin/knox-node\" | sha256sum -c -'"
      fi
    fi
    echo "  - test -x /opt/knox/bin/knox-node || (echo \"Missing /opt/knox/bin/knox-node\" && exit 1)"
    echo "  - ufw --force reset"
    echo "  - ufw default deny incoming"
    echo "  - ufw default allow outgoing"
    echo "  - ufw allow 22/tcp"
    echo "  - ufw allow $p2p1/tcp"
    echo "  - ufw allow $p2p2/tcp"
    if [[ "$remote1" -eq 1 ]]; then
      if [[ "$n1" -ge 9 ]]; then
        echo "  - ufw allow $rpc1/tcp"
      elif [[ "$auth1" -eq 1 ]]; then
        for src_ip in "${IPS[@]}"; do
          echo "  - ufw allow from $src_ip to any port $rpc1 proto tcp"
        done
      fi
    fi
    if [[ "$remote2" -eq 1 ]]; then
      if [[ "$n2" -ge 9 ]]; then
        echo "  - ufw allow $rpc2/tcp"
      elif [[ "$auth2" -eq 1 ]]; then
        for src_ip in "${IPS[@]}"; do
          echo "  - ufw allow from $src_ip to any port $rpc2 proto tcp"
        done
      fi
    fi
    echo "  - ufw --force enable"
    echo "  - systemctl daemon-reload"
    echo "  - systemctl enable knox-node-a knox-node-b"
    echo "  - systemctl restart knox-node-a knox-node-b"
  } > "$out"
done

echo "generated: $OUT_DIR/vm1.yaml .. vm6.yaml"
echo "topology: 8 miners (n1..n8), 2 rpc (n9..n10), 2 explorer (n11..n12)"
echo "wrote launch-mainnet/mainnet.env"
echo "diamond authenticators: nodes=${AUTH_NODES_CSV} quorum=${AUTH_QUORUM}"
echo "diamond endpoints: $AUTH_ENDPOINTS_CSV"
echo "cluster map: $OUT_DIR/cluster-map.txt"
