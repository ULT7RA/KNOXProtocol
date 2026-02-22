#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$ROOT/apps/knox-wallet-desktop/bin"
CERT_DIR="$BIN_DIR/certs"
mkdir -p "$BIN_DIR"
mkdir -p "$CERT_DIR"

if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
  export CARGO_TARGET_DIR="$ROOT/target-desktop"
fi

cargo build -p knox-node --bin knox-node --profile release-lite
cargo build -p knox-walletd --bin knox-wallet --profile release-lite
cargo build -p knox-wallet --bin knox-wallet-cli --profile release-lite

copy_bin() {
  local name="$1"
  local direct="$CARGO_TARGET_DIR/release-lite/$name"
  local targeted="$CARGO_TARGET_DIR/x86_64-pc-windows-msvc/release-lite/$name"
  if [[ -f "$direct" ]]; then
    cp "$direct" "$BIN_DIR/"
  elif [[ -f "$targeted" ]]; then
    cp "$targeted" "$BIN_DIR/"
  else
    echo "ERROR: could not find built binary: $name under $CARGO_TARGET_DIR"
    exit 1
  fi
}

copy_bin "knox-node"
copy_bin "knox-wallet"
copy_bin "knox-wallet-cli"

CERT="$CERT_DIR/walletd.crt"
KEY="$CERT_DIR/walletd.key"
if [[ ! -f "$CERT" || ! -f "$KEY" ]]; then
  if command -v openssl >/dev/null 2>&1; then
    echo "Generating self-signed TLS cert for walletd..."
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
      -keyout "$KEY" -out "$CERT" -subj "/CN=localhost"
  else
    echo "ERROR: openssl not found. Install openssl or set KNOX_WALLETD_TLS_CERT/KNOX_WALLETD_TLS_KEY manually."
    exit 1
  fi
fi

echo "Desktop binaries copied to $BIN_DIR"
