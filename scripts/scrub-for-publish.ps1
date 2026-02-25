param(
  [switch]$Apply
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$paths = @(
  "nonpublic",
  "data",
  "data-smoke",
  "launch-mainnet",
  "target",
  "target-*",
  "tmp-smoke",
  "wallet*.bin",
  "node-wallet.bin",
  "walletd-build.log",
  "*.log",
  "*.dmp",
  "certs/*.key",
  "certs/*.crt",
  "certs/*.pfx",
  "apps/*/dist",
  "apps/*/out",
  "apps/*/node_modules",
  "fuzz/target",
  "fuzz/corpus"
)

$items = foreach ($pattern in $paths) {
  Get-ChildItem -Path $pattern -Force -ErrorAction SilentlyContinue
}

if (-not $items) {
  Write-Host "No scrub targets found."
  exit 0
}

Write-Host "Scrub targets:"
$items | ForEach-Object { Write-Host (" - " + $_.FullName) }

if (-not $Apply) {
  Write-Host ""
  Write-Host "Dry-run only. Re-run with -Apply to delete these files/directories."
  exit 0
}

$items | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Scrub complete."
