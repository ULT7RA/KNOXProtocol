#!/usr/bin/env bash
set -euo pipefail

cd /opt/knox-wallet-desktop

if [[ -z "${DISPLAY:-}" ]]; then
  echo "DISPLAY is not set. Export DISPLAY and mount /tmp/.X11-unix when running the GUI container."
  exit 1
fi

if [[ "${KNOX_ELECTRON_NO_SANDBOX:-0}" == "1" ]]; then
  exec ./node_modules/.bin/electron . --no-sandbox
fi

exec ./node_modules/.bin/electron .
