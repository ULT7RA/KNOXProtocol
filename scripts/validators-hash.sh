#!/usr/bin/env bash
set -euo pipefail

FILE="${1:-}"
if [[ -z "$FILE" ]]; then
  echo "usage: $0 <validators.txt>"
  exit 1
fi
if [[ ! -f "$FILE" ]]; then
  echo "missing file: $FILE"
  exit 1
fi

# Prefer native b3sum when available.
if command -v b3sum >/dev/null 2>&1; then
  b3sum "$FILE" | awk '{print $1}'
  exit 0
fi

# Fallback: use workspace utility command.
cargo +stable run -q -p knox-keygen -- --blake3 "$FILE"
