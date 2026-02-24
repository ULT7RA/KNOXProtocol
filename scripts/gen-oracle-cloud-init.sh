#!/usr/bin/env bash
set -euo pipefail

NODES="${1:-14}"
IPS_FILE="${2:-launch-mainnet/ips.txt}"
PREMINE_ADDR="${3:-}"
MINING_NODES="${4:-$NODES}"
RPC_NODES="${5:-}"
PSK_SERVICE="${KNOX_P2P_PSK_SERVICE:-knox-p2p}"
PSK_ACCOUNT="${KNOX_P2P_PSK_ACCOUNT:-mainnet}"
GENESIS_HASH="${KNOX_MAINNET_GENESIS_HASH:-}"
NODE_BIN_URL="${KNOX_NODE_BIN_URL:-}"
NODE_BIN_SHA256="${KNOX_NODE_BIN_SHA256:-}"
KEY_ROOT="${KEY_ROOT:-testnet}"
OUT_DIR="${OUT_DIR:-launch-mainnet/cloud-init}"
DIAMOND_AUTH_PUBKEYS="${KNOX_DIAMOND_AUTH_PUBKEYS:-}"
DIAMOND_AUTH_QUORUM="${KNOX_DIAMOND_AUTH_QUORUM:-2}"
DIAMOND_AUTH_ENDPOINTS="${KNOX_DIAMOND_AUTH_ENDPOINTS:-}"

if [[ -z "$PREMINE_ADDR" ]]; then
  echo "usage: $0 <nodes> <ips_file> <premine_address> [mining_nodes] [rpc_nodes_csv]"
  exit 1
fi

if [[ "$MINING_NODES" -lt 1 ]] || [[ "$MINING_NODES" -gt "$NODES" ]]; then
  echo "mining_nodes must be between 1 and $NODES"
  exit 1
fi

if [[ -z "$RPC_NODES" ]]; then
  if [[ "$NODES" -ge 2 ]]; then
    RPC_NODES="$((NODES-1)),$NODES"
  else
    RPC_NODES="1"
  fi
fi

if [[ ! -f "$IPS_FILE" ]]; then
  echo "missing ips file: $IPS_FILE"
  exit 1
fi
if [[ -z "$DIAMOND_AUTH_PUBKEYS" ]]; then
  echo "KNOX_DIAMOND_AUTH_PUBKEYS is required"
  exit 1
fi
if [[ -z "$DIAMOND_AUTH_ENDPOINTS" ]]; then
  echo "KNOX_DIAMOND_AUTH_ENDPOINTS is required"
  exit 1
fi
if [[ ! "$DIAMOND_AUTH_QUORUM" =~ ^[0-9]+$ ]] || [[ "$DIAMOND_AUTH_QUORUM" -lt 1 ]]; then
  echo "KNOX_DIAMOND_AUTH_QUORUM must be an integer >= 1"
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

mapfile -t IPS < <(awk 'NF {print $1}' "$IPS_FILE")
if [[ "${#IPS[@]}" -ne "$NODES" ]]; then
  echo "ips count (${#IPS[@]}) does not match nodes ($NODES)"
  exit 1
fi

for i in $(seq 1 "$NODES"); do
  if [[ ! -f "$KEY_ROOT/node$i/node.key" ]]; then
    echo "missing key: $KEY_ROOT/node$i/node.key"
    exit 1
  fi
done

mkdir -p "$OUT_DIR"
mkdir -p launch-mainnet

{
  echo "KNOX_P2P_PSK_SERVICE=$PSK_SERVICE"
  echo "KNOX_P2P_PSK_ACCOUNT=$PSK_ACCOUNT"
  echo "KNOX_MAINNET_LOCK=1"
  echo "KNOX_MAINNET_PREMINE_ADDRESS=$PREMINE_ADDR"
  echo "KNOX_MAINNET_GENESIS_HASH=$GENESIS_HASH"
  echo "KNOX_DIAMOND_AUTH_PUBKEYS=$DIAMOND_AUTH_PUBKEYS"
  echo "KNOX_DIAMOND_AUTH_QUORUM=$DIAMOND_AUTH_QUORUM"
  echo "KNOX_DIAMOND_AUTH_ENDPOINTS=$DIAMOND_AUTH_ENDPOINTS"
} > launch-mainnet/mainnet.env

is_in_csv() {
  local needle="$1"
  local haystack="$2"
  case ",$haystack," in
    *",$needle,"*) return 0 ;;
    *) return 1 ;;
  esac
}

for i in $(seq 1 "$NODES"); do
  idx=$((i - 1))
  peers=()
  for j in $(seq 1 "$NODES"); do
    if [[ "$j" -eq "$i" ]]; then
      continue
    fi
    jdx=$((j - 1))
    peers+=("${IPS[$jdx]}:9735")
  done
  peers_csv="$(IFS=,; echo "${peers[*]}")"
  node_key="$(tr -d '\r\n' < "$KEY_ROOT/node$i/node.key")"
  out="$OUT_DIR/node$i.yaml"
  rpc_remote=0
  rpc_bind="127.0.0.1:9736"
  if is_in_csv "$i" "$RPC_NODES"; then
    rpc_remote=1
    rpc_bind="0.0.0.0:9736"
  fi

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
    echo "  - path: /etc/default/knox-node"
    echo "    permissions: \"0640\""
    echo "    owner: root:root"
    echo "    content: |"
    echo "      KNOX_P2P_PSK_SERVICE=$PSK_SERVICE"
    echo "      KNOX_P2P_PSK_ACCOUNT=$PSK_ACCOUNT"
    echo "      KNOX_NODE_RPC_ALLOW_REMOTE=$rpc_remote"
    if [[ "$i" -gt "$MINING_NODES" ]]; then
      echo "      KNOX_NODE_NO_MINE=1"
    fi
    echo "      KNOX_MAINNET_LOCK=1"
    echo "      KNOX_MAINNET_PREMINE_ADDRESS=$PREMINE_ADDR"
    echo "      KNOX_MAINNET_GENESIS_HASH=$GENESIS_HASH"
    echo "      KNOX_DIAMOND_AUTH_PUBKEYS=$DIAMOND_AUTH_PUBKEYS"
    echo "      KNOX_DIAMOND_AUTH_QUORUM=$DIAMOND_AUTH_QUORUM"
    echo "      KNOX_DIAMOND_AUTH_ENDPOINTS=$DIAMOND_AUTH_ENDPOINTS"
    echo "  - path: /var/lib/knox/node.key"
    echo "    permissions: \"0600\""
    echo "    owner: knox:knox"
    echo "    content: |"
    echo "      $node_key"
    echo "  - path: /etc/systemd/system/knox-node.service"
    echo "    permissions: \"0644\""
    echo "    owner: root:root"
    echo "    content: |"
    echo "      [Unit]"
    echo "      Description=KNOX Node"
    echo "      After=network-online.target"
    echo "      Wants=network-online.target"
    echo "      [Service]"
    echo "      User=knox"
    echo "      Group=knox"
    echo "      EnvironmentFile=/etc/default/knox-node"
    echo "      ExecStart=/opt/knox/bin/knox-node /var/lib/knox 0.0.0.0:9735 $rpc_bind \"$peers_csv\" \"$PREMINE_ADDR\""
    echo "      Restart=always"
    echo "      RestartSec=2"
    echo "      LimitNOFILE=1048576"
    echo "      [Install]"
    echo "      WantedBy=multi-user.target"
    echo "runcmd:"
    echo "  - mkdir -p /opt/knox/bin /var/lib/knox"
    echo "  - chown -R knox:knox /var/lib/knox"
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
    echo "  - ufw allow 9735/tcp"
    if [[ "$rpc_remote" -eq 1 ]]; then
      echo "  - ufw allow 9736/tcp"
    fi
    echo "  - ufw --force enable"
    echo "  - systemctl daemon-reload"
    echo "  - systemctl enable knox-node"
    echo "  - systemctl restart knox-node"
    if [[ "$i" -eq 1 ]]; then
      echo "  - bash -lc 'for n in \$(seq 1 60); do h=\$(env KNOX_PRINT_GENESIS_HASH=1 /opt/knox/bin/knox-node /var/lib/knox 2>/dev/null || true); if echo \"\$h\" | grep -Eq \"^[0-9a-f]{64}$\"; then echo \"KNOX_GENESIS_HASH=\$h\"; echo \"\$h\" > /var/lib/knox/genesis.hash; break; fi; sleep 2; done'"
    fi
  } > "$out"
done

echo "generated cloud-init files: $OUT_DIR/node1.yaml .. node${NODES}.yaml"
echo "wrote launch-mainnet/mainnet.env"
echo "mining nodes: 1..$MINING_NODES"
echo "rpc nodes: $RPC_NODES"
