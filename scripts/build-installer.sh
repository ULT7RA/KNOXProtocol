#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

bash "$ROOT/scripts/build-desktop.sh"

pushd "$ROOT/apps/knox-wallet-desktop" >/dev/null
if [[ ! -d node_modules ]]; then
  npm install
fi
# Guard against stale env flags from prior sessions.
unset ELECTRON_BUILDER_SKIP_ICON_CONVERSION || true
unset ELECTRON_BUILDER_DISABLE_ICON_COMPRESSION || true
unset ELECTRON_BUILDER_DISABLE_APP_BUILDER || true
export ELECTRON_BUILDER_COMPRESSION_LEVEL=0
npm run ensure:icon
npm run dist
popd >/dev/null
