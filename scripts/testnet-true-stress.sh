#!/usr/bin/env bash
set -euo pipefail

RPC=${1:-127.0.0.1:10736}
WALLET=${2:-wallet-bench.bin}
DURATION=${3:-180}
TPS=${4:-300}
AMOUNT=${5:-0.0001}
FEE=${6:-0.000001}
RING=${7:-15}
SERVICE=${8:-node1}

cd /mnt/d/KNOX

start_iso=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
start_epoch=$(date +%s)

KNOX_TESTNET_FORCE_CARGO=1 KNOX_TESTNET_TOOLCHAIN=stable \
  bash scripts/testnet-bench.sh "$RPC" "$WALLET" "$DURATION" "$TPS" "$AMOUNT" "$FEE" "$RING"

end_epoch=$(date +%s)
elapsed=$((end_epoch - start_epoch))
if [ "$elapsed" -le 0 ]; then
  elapsed=1
fi

logs=$(docker compose -f docker/docker-compose.testnet.yml logs --since "$start_iso" "$SERVICE" || true)
sealed=$(printf "%s\n" "$logs" | grep -E "sealed block [0-9]+ txs=[0-9]+" || true)

if [ -z "$sealed" ]; then
  echo "No sealed block lines captured for $SERVICE since $start_iso"
  exit 1
fi

blocks=$(printf "%s\n" "$sealed" | wc -l | awk '{print $1}')
sum_txs=$(printf "%s\n" "$sealed" | sed -n 's/.* txs=\([0-9]\+\).*/\1/p' | awk '{s+=$1} END{print s+0}')
user_txs=$((sum_txs - blocks))
if [ "$user_txs" -lt 0 ]; then
  user_txs=0
fi

accepted_tps=$(awk -v n="$user_txs" -v d="$elapsed" 'BEGIN{printf "%.2f", n/d}')
echo "True stress result ($SERVICE)"
echo "  duration_s=$elapsed"
echo "  sealed_blocks=$blocks"
echo "  accepted_user_txs=$user_txs"
echo "  accepted_tps=$accepted_tps"
