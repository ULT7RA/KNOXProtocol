#!/usr/bin/env bash
set -euo pipefail

KEY_ROOT="${1:-testnet}"
VALIDATOR_COUNT="${2:-8}"
OUT_FILE="${3:-$KEY_ROOT/validators.txt}"
TOOLCHAIN="${KNOX_TESTNET_TOOLCHAIN:-stable}"

if [[ "$VALIDATOR_COUNT" -lt 1 ]]; then
  echo "validator count must be >= 1"
  exit 1
fi

mkdir -p "$(dirname "$OUT_FILE")"
: > "$OUT_FILE"

for n in $(seq 1 "$VALIDATOR_COUNT"); do
  key_file="$KEY_ROOT/node$n/node.key"
  if [[ ! -f "$key_file" ]]; then
    echo "missing node key: $key_file"
    exit 1
  fi
  key_hex="$(tr -d '\r\n[:space:]' < "$key_file")"
  if [[ "${#key_hex}" -ne 128 ]]; then
    echo "invalid node key format in $key_file (expected 128 hex chars)"
    exit 1
  fi
  sk_hex="${key_hex:0:64}"
  lattice_pk_hex="$(cargo +"$TOOLCHAIN" run -p knox-keygen --quiet -- --consensus-public-from-secret "$sk_hex")"
  if [[ -z "$lattice_pk_hex" ]]; then
    echo "failed to derive lattice validator key for node$n"
    exit 1
  fi
  echo "$lattice_pk_hex" >> "$OUT_FILE"
done

echo "wrote lattice validators: $OUT_FILE"
