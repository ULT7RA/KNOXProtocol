$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$desktopDir = Join-Path $root "apps/knox-wallet-desktop"
$mainJs = Join-Path $desktopDir "main.js"
$pkgJson = Join-Path $desktopDir "package.json"
$desktopBinDir = Join-Path $desktopDir "bin"
$distBinDir = Join-Path $desktopDir "dist/win-unpacked/resources/bin"
$installedBinDir = Join-Path $env:LOCALAPPDATA "Programs/knox-wallet-desktop/resources/bin"

function Stop-DesktopWalletProcesses() {
  Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and $_.Path -like "*knox-wallet-desktop*" } |
    Stop-Process -Force -ErrorAction SilentlyContinue
}

function Remove-DesktopBuildDir([string]$dir) {
  if (!(Test-Path $dir)) { return }
  Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
}

function Remove-StaleRuntimeBinaries([string]$dir, [switch]$KeepCanonicalExeNames) {
  if (!(Test-Path $dir)) { return }
  Get-ChildItem $dir -File -ErrorAction SilentlyContinue |
    Where-Object {
      $isKnoxRuntimeBinary = (
        $_.Name -like "knox-node*.exe" -or
        $_.Name -like "knox-node*.dll" -or
        $_.Name -like "knox-node*.pdb" -or
        $_.Name -like "knox-wallet*.exe" -or
        $_.Name -like "knox-wallet*.dll" -or
        $_.Name -like "knox-wallet*.pdb"
      )
      if (-not $isKnoxRuntimeBinary) { return $false }
      if (
        $KeepCanonicalExeNames -and
        $_.Extension -ieq ".exe" -and
        $_.Name -in @("knox-node.exe", "knox-wallet.exe", "knox-wallet-cli.exe")
      ) {
        return $false
      }
      return $true
    } |
    Remove-Item -Force -ErrorAction SilentlyContinue
}

function Assert-OnlyCanonicalRuntimeBinaries([string]$dir) {
  if (!(Test-Path $dir)) { return }

  $allowedExe = @("knox-node.exe", "knox-wallet.exe", "knox-wallet-cli.exe")
  $bad = Get-ChildItem $dir -File -ErrorAction SilentlyContinue |
    Where-Object {
      $isKnoxRuntimeBinary = (
        $_.Name -like "knox-node*.exe" -or
        $_.Name -like "knox-node*.dll" -or
        $_.Name -like "knox-node*.pdb" -or
        $_.Name -like "knox-wallet*.exe" -or
        $_.Name -like "knox-wallet*.dll" -or
        $_.Name -like "knox-wallet*.pdb"
      )
      if (-not $isKnoxRuntimeBinary) { return $false }
      if ($_.Extension -ieq ".exe" -and $_.Name -in $allowedExe) { return $false }
      return $true
    }

  if ($bad -and $bad.Count -gt 0) {
    $names = ($bad | Select-Object -ExpandProperty Name) -join ", "
    throw "Refusing to package: stale runtime binaries found in ${dir}: $names"
  }
}

function Purge-InstallerBuildArtifacts() {
  Write-Host "[purge] enforcing hard cleanup before installer build"
  Stop-DesktopWalletProcesses
  Remove-DesktopBuildDir (Join-Path $desktopDir "dist")
  Remove-DesktopBuildDir (Join-Path $desktopDir "out")
  Remove-DesktopBuildDir (Join-Path $desktopDir "win-unpacked")
  Remove-StaleRuntimeBinaries $desktopBinDir
  Remove-StaleRuntimeBinaries $distBinDir
  Remove-StaleRuntimeBinaries $installedBinDir
}

if (!(Test-Path $mainJs)) {
  throw "Missing desktop main.js at $mainJs"
}
if (!(Test-Path $pkgJson)) {
  throw "Missing desktop package.json at $pkgJson"
}

Purge-InstallerBuildArtifacts

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

Assert-OnlyCanonicalRuntimeBinaries $desktopBinDir

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

Assert-OnlyCanonicalRuntimeBinaries (Join-Path $desktopDir "dist/win-unpacked/resources/bin")

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
