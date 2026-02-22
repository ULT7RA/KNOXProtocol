#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"
cd "$ROOT"

fail=0

echo "[audit] scanning for committed secret material..."

check_paths() {
  local pattern="$1"
  local label="$2"
  local hits
  hits="$(find . \
    -path './.git' -prune -o \
    -path './target*' -prune -o \
    -path './apps/*/node_modules' -prune -o \
    -type f -name "$pattern" -print)"
  if [[ -n "$hits" ]]; then
    echo "[FAIL] $label"
    echo "$hits"
    fail=1
  fi
}

check_dir() {
  local dir_pattern="$1"
  local label="$2"
  local hits
  hits="$(find . -type d -name "$dir_pattern" -print)"
  if [[ -n "$hits" ]]; then
    echo "[FAIL] $label"
    echo "$hits"
    fail=1
  fi
}

check_paths "node.key" "validator private keys are present in repository paths"
check_paths "db.key" "database encryption keys are present in repository paths"
check_paths "wallet*.bin" "wallet binary files are present in repository paths"
check_paths "walletd.key" "wallet daemon TLS private keys are present in repository paths"
check_paths "*.pem" "PEM files are present in repository paths"
check_paths "*nodekeys*.tgz" "archived validator key bundles are present in repository paths"
check_paths "*-knox-keys.tgz" "per-node key archive bundles are present in repository paths"

check_dir "TO_REMOVE_FROM_REPO_*" "staging directories for secrets still exist"
check_dir ".secrets" "hidden secret directory exists"
check_dir "secrets" "secret directory exists"
check_dir "nodekeys-*" "node key backup directories exist"

if rg -n --no-heading --glob '!**/node_modules/**' \
  --glob '!target*/**' \
  'KNOX_P2P_PSK=|KNOX_MAINNET_PREMINE_ADDRESS=|KNOX_MAINNET_GENESIS_HASH=' \
  launch-mainnet testnet 2>/dev/null; then
  echo "[FAIL] launch/testnet env-like files contain pinned deployment secrets"
  fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  echo "[audit] FAILED"
  exit 1
fi

echo "[audit] OK"
