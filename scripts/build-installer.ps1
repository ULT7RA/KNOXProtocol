$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$desktopDir = Join-Path $root "apps/knox-wallet-desktop"
$mainJs = Join-Path $desktopDir "main.js"
$pkgJson = Join-Path $desktopDir "package.json"

if (!(Test-Path $mainJs)) {
  throw "Missing desktop main.js at $mainJs"
}
if (!(Test-Path $pkgJson)) {
  throw "Missing desktop package.json at $pkgJson"
}

# Hard-fail if core launch guards are missing.
$mainText = Get-Content -Raw $mainJs
if ($mainText -notmatch "const USE_LOCAL_RPC_WHEN_NODE_RUNNING") {
  throw "Refusing to build: missing USE_LOCAL_RPC_WHEN_NODE_RUNNING in main.js"
}
if ($mainText -notmatch "const FORCE_REMOTE_WALLET_MODE") {
  throw "Refusing to build: missing FORCE_REMOTE_WALLET_MODE in main.js"
}
if ($mainText -notmatch "remote-rpc mode active; walletd bound to") {
  throw "Refusing to build: remote RPC quick-start path missing in main.js"
}

# Syntax sanity check before packaging.
node --check $mainJs
if ($LASTEXITCODE -ne 0) {
  throw "node --check failed for $mainJs"
}

& "$PSScriptRoot/build-desktop.ps1"

Push-Location $desktopDir
if (-not (Test-Path "node_modules")) {
  npm.cmd install
  if ($LASTEXITCODE -ne 0) {
    throw "npm install failed in $desktopDir"
  }
}

# Guard against stale shell env flags from prior sessions.
Remove-Item Env:ELECTRON_BUILDER_SKIP_ICON_CONVERSION -ErrorAction SilentlyContinue
Remove-Item Env:ELECTRON_BUILDER_DISABLE_ICON_COMPRESSION -ErrorAction SilentlyContinue
Remove-Item Env:ELECTRON_BUILDER_DISABLE_APP_BUILDER -ErrorAction SilentlyContinue

$env:ELECTRON_BUILDER_COMPRESSION_LEVEL = "0"

npm.cmd run ensure:icon
if ($LASTEXITCODE -ne 0) {
  throw "npm run ensure:icon failed"
}
npm.cmd run dist
if ($LASTEXITCODE -ne 0) {
  throw "npm run dist failed"
}
Pop-Location

$distDir = Join-Path $desktopDir "dist"
$candidates = @()
$candidates += Get-ChildItem $distDir -File -Filter "*.msi" -ErrorAction SilentlyContinue
$candidates += Get-ChildItem $distDir -File -Filter "*Setup*.exe" -ErrorAction SilentlyContinue
$latestInstaller = $candidates | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $latestInstaller) {
  Write-Host "Dist directory contents:" -ForegroundColor Yellow
  Get-ChildItem $distDir -File -ErrorAction SilentlyContinue | Select-Object Name,Length,LastWriteTime | Format-Table -AutoSize
  throw "Build did not produce an installer (.msi or Setup .exe) in $distDir"
}
Write-Host "Installer build OK: $($latestInstaller.FullName)"
