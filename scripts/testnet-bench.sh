#!/usr/bin/env bash
set -euo pipefail

RPC=${1:-127.0.0.1:9736}
WALLET=${2:-wallet.bin}
DURATION=${3:-86400}
TPS=${4:-200}
AMOUNT=${5:-0.0001}
FEE=${6:-0.000001}
RING=${7:-31}
TOOLCHAIN=${KNOX_TESTNET_TOOLCHAIN:-stable}

if [ "${KNOX_TESTNET_FORCE_CARGO:-0}" = "1" ]; then
  CLI="cargo +$TOOLCHAIN run -p knox-wallet --bin knox-wallet-cli --"
elif [ -x ./target/debug/knox-wallet-cli ]; then
  CLI="./target/debug/knox-wallet-cli"
elif [ -f ./target-msvc-clean/x86_64-pc-windows-msvc/debug/knox-wallet-cli.exe ]; then
  CLI="./target-msvc-clean/x86_64-pc-windows-msvc/debug/knox-wallet-cli.exe"
else
  CLI="cargo +$TOOLCHAIN run -p knox-wallet --bin knox-wallet-cli --"
fi

run_cli() {
  if [[ "$CLI" == cargo* ]]; then
    cargo +"$TOOLCHAIN" run -p knox-wallet --bin knox-wallet-cli -- "$@"
  else
    "$CLI" "$@"
  fi
}

if [ ! -f "$WALLET" ]; then
  run_cli create "$WALLET"
fi

ADDR=$(run_cli address "$WALLET")

echo "Using wallet: $WALLET"
echo "Address: $ADDR"

echo "Syncing..."
run_cli sync "$WALLET" "$RPC"

start_ts=$(date +%s)
end_ts=$((start_ts + DURATION))

while [ $(date +%s) -lt $end_ts ]; do
  for i in $(seq 1 $TPS); do
    run_cli send "$WALLET" "$RPC" "$ADDR" "$AMOUNT" "$FEE" "$RING" >/dev/null 2>&1 || true
  done
  sleep 1
 done

echo "Benchmark window complete."
