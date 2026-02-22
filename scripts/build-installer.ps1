$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot

& "$PSScriptRoot/build-desktop.ps1"

Push-Location (Join-Path $root "apps/knox-wallet-desktop")
if (-not (Test-Path "node_modules")) {
  npm.cmd install
}

# Guard against stale shell env flags from prior sessions.
Remove-Item Env:ELECTRON_BUILDER_SKIP_ICON_CONVERSION -ErrorAction SilentlyContinue
Remove-Item Env:ELECTRON_BUILDER_DISABLE_ICON_COMPRESSION -ErrorAction SilentlyContinue
Remove-Item Env:ELECTRON_BUILDER_DISABLE_APP_BUILDER -ErrorAction SilentlyContinue

$env:ELECTRON_BUILDER_COMPRESSION_LEVEL = "0"

npm.cmd run ensure:icon
npm.cmd run dist
Pop-Location
