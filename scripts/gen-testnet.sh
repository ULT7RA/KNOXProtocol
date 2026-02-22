#!/usr/bin/env bash
set -euo pipefail

NODES=${1:-5}
REGIONS=${2:-1}
OUT=${3:-docker/docker-compose.testnet.yml}
DATA_DIR=${4:-testnet}
VALIDATOR_COUNT=${KNOX_VALIDATOR_COUNT:-$NODES}
TOOLCHAIN=${KNOX_TESTNET_TOOLCHAIN:-stable}

if [ "$VALIDATOR_COUNT" -lt 1 ] || [ "$VALIDATOR_COUNT" -gt "$NODES" ]; then
  echo "KNOX_VALIDATOR_COUNT must be between 1 and $NODES"
  exit 1
fi

mkdir -p "${DATA_DIR}"
mkdir -p "$(dirname "$OUT")"

validators_file="${DATA_DIR}/validators.txt"
: > "$validators_file"

keys=()
for i in $(seq 1 "$NODES"); do
  key_hex=$(cargo +"$TOOLCHAIN" run -p knox-keygen --quiet -- --full-keypair)
  if [ "${#key_hex}" -ne 128 ]; then
    echo "knox-keygen returned invalid keypair length for node${i}"
    exit 1
  fi
  keys+=($key_hex)
done

for key_hex in "${keys[@]:0:$VALIDATOR_COUNT}"; do
  sk_hex=${key_hex:0:64}
  lattice_pk_hex="$(cargo +"$TOOLCHAIN" run -p knox-keygen --quiet -- --consensus-public-from-secret "$sk_hex")"
  if [ -z "$lattice_pk_hex" ]; then
    echo "failed to derive lattice validator key from secret"
    exit 1
  fi
  echo "$lattice_pk_hex" >> "$validators_file"
done

for i in $(seq 1 "$NODES"); do
  node_dir="${DATA_DIR}/node${i}"
  mkdir -p "$node_dir"
  echo -n "${keys[$((i-1))]}" > "$node_dir/node.key"
  cp "$validators_file" "$node_dir/validators.txt"
done

cat > "$OUT" <<'YAML'
services:
YAML

for i in $(seq 1 "$NODES"); do
  region=$(( (i - 1) % REGIONS + 1 ))
  port=9735
  rpc=9736
  host_rpc=$((10735 + i))
  peers=""
  for j in $(seq 1 "$NODES"); do
    if [ "$j" -eq "$i" ]; then
      continue
    fi
    peer="node${j}:9735"
    if [ -z "$peers" ]; then
      peers="$peer"
    else
      peers="${peers},${peer}"
    fi
  done
  cat >> "$OUT" <<YAML
  node${i}:
    build:
      context: ..
      dockerfile: docker/Dockerfile
    command: ["/data", "0.0.0.0:${port}", "0.0.0.0:${rpc}", "${peers}", "/data/validators.txt"]
    environment:
      - KNOX_NODE_RPC_ALLOW_REMOTE=1
      - KNOX_ALLOW_UNSAFE_OVERRIDES=1
      - KNOX_P2P_ALLOW_PLAINTEXT=1
$(if [ "$i" -gt "$VALIDATOR_COUNT" ]; then echo "      - KNOX_NODE_NO_MINE=1"; fi)
    volumes:
      - ../${DATA_DIR}/node${i}:/data
    ports:
      - "${host_rpc}:9736"
    networks:
      - backbone
      - region${region}
YAML
done

cat >> "$OUT" <<'YAML'
networks:
  backbone:
    driver: bridge
YAML

for r in $(seq 1 "$REGIONS"); do
  cat >> "$OUT" <<YAML
  region${r}:
    driver: bridge
YAML
 done

echo "Generated ${OUT} with ${NODES} nodes across ${REGIONS} regions."
