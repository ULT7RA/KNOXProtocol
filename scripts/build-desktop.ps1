$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$binDir = Join-Path $root "apps/knox-wallet-desktop/bin"
$certDir = Join-Path $binDir "certs"
$target = "x86_64-pc-windows-msvc"
$embeddedGenesis = Join-Path $root "crates/knox-node/src/genesis.bin"
New-Item -ItemType Directory -Force -Path $binDir | Out-Null
New-Item -ItemType Directory -Force -Path $certDir | Out-Null

function Remove-StaleDesktopBinaries([string]$dir) {
  if (!(Test-Path $dir)) { return }
  Get-ChildItem $dir -File -ErrorAction SilentlyContinue |
    Where-Object {
      ($_.Name -like "knox-node*.exe" -and $_.Name -ne "knox-node.exe") -or
      ($_.Name -like "knox-wallet*.exe" -and $_.Name -notin @("knox-wallet.exe", "knox-wallet-cli.exe"))
    } |
    Remove-Item -Force -ErrorAction SilentlyContinue
}

function Stop-DesktopWalletProcesses() {
  Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -like "*knox-wallet-desktop*" } |
    Stop-Process -Force -ErrorAction SilentlyContinue
}

function Copy-CanonicalDesktopBinaries([string]$srcDir, [string]$dstDir) {
  New-Item -ItemType Directory -Force -Path $dstDir | Out-Null
  Copy-Item -Force (Join-Path $srcDir "knox-node.exe") $dstDir
  Copy-Item -Force (Join-Path $srcDir "knox-wallet.exe") $dstDir
  Copy-Item -Force (Join-Path $srcDir "knox-wallet-cli.exe") $dstDir
}

$genesisCandidates = @()
if ($env:KNOX_GENESIS_BIN) { $genesisCandidates += $env:KNOX_GENESIS_BIN }
$genesisCandidates += (Join-Path $root "genesis.bin")
$selectedGenesis = $null
foreach ($candidate in $genesisCandidates) {
  if ($candidate -and (Test-Path $candidate)) {
    $selectedGenesis = $candidate
    break
  }
}
if ($selectedGenesis) {
  Copy-Item -Force $selectedGenesis $embeddedGenesis
  $g = Get-Item $embeddedGenesis
  $h = (Get-FileHash -Algorithm SHA256 $embeddedGenesis).Hash.ToLower()
  Write-Host "Embedded genesis synced from $selectedGenesis (sha256=$h bytes=$($g.Length))"
} elseif (!(Test-Path $embeddedGenesis)) {
  throw "Missing embedded genesis at $embeddedGenesis and no source genesis provided"
}

$env:RUSTUP_TOOLCHAIN = "stable-x86_64-pc-windows-msvc"
$env:CARGO_TARGET_DIR = Join-Path $root "target-msvc-clean"

# Prevent accidental toolchain/linker contamination from shell env.
Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
Remove-Item Env:CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue
Remove-Item Env:CC -ErrorAction SilentlyContinue
Remove-Item Env:CXX -ErrorAction SilentlyContinue
Remove-Item Env:AR -ErrorAction SilentlyContinue

rustup target add $target --toolchain $env:RUSTUP_TOOLCHAIN
rustup run $env:RUSTUP_TOOLCHAIN cargo build --target $target -p knox-node --bin knox-node --profile release-lite
rustup run $env:RUSTUP_TOOLCHAIN cargo build --target $target -p knox-walletd --bin knox-wallet --profile release-lite
rustup run $env:RUSTUP_TOOLCHAIN cargo build --target $target -p knox-wallet --bin knox-wallet-cli --profile release-lite

function Resolve-BuiltExe([string]$name) {
  $paths = @(
    (Join-Path $env:CARGO_TARGET_DIR "release-lite/$name"),
    (Join-Path $env:CARGO_TARGET_DIR "$target/release-lite/$name")
  )
  foreach ($p in $paths) {
    if (Test-Path $p) { return $p }
  }
  throw "Could not find built binary: $name under $env:CARGO_TARGET_DIR"
}

Copy-Item -Force (Resolve-BuiltExe "knox-node.exe") $binDir
Copy-Item -Force (Resolve-BuiltExe "knox-wallet.exe") $binDir
Copy-Item -Force (Resolve-BuiltExe "knox-wallet-cli.exe") $binDir
Remove-StaleDesktopBinaries $binDir

$cert = Join-Path $certDir "walletd.crt"
$key = Join-Path $certDir "walletd.key"
if (!(Test-Path $cert) -or !(Test-Path $key)) {
  $openssl = Get-Command openssl -ErrorAction SilentlyContinue
  if (-not $openssl) {
    Write-Error "openssl not found. Install openssl or set KNOX_WALLETD_TLS_CERT/KNOX_WALLETD_TLS_KEY manually."
    exit 1
  }
  Write-Host "Generating self-signed TLS cert for walletd..."
  & $openssl.Path req -x509 -newkey rsa:2048 -nodes -days 365 `
    -keyout $key -out $cert -subj "/CN=localhost"
}

# Copy to dist/win-unpacked (dev/unpacked build location).
$distBin = Join-Path $root "apps/knox-wallet-desktop/dist/win-unpacked/resources/bin"
if (Test-Path $distBin) {
  try {
    Remove-StaleDesktopBinaries $distBin
    Copy-CanonicalDesktopBinaries $binDir $distBin
    Write-Host "Desktop binaries copied to dist at $distBin"
  } catch {
    Write-Warning "dist binaries are in use; close KNOX WALLET first, then copy manually:"
    Write-Warning "  copy $binDir\*.exe $distBin\"
  }
}

# Also copy to the installed MSI location so the running app picks up changes.
$installedBin = Join-Path $env:LOCALAPPDATA "Programs/knox-wallet-desktop/resources/bin"
if (Test-Path $installedBin) {
  try {
    Stop-DesktopWalletProcesses
    Remove-StaleDesktopBinaries $installedBin
    Copy-CanonicalDesktopBinaries $binDir $installedBin
    Write-Host "Desktop binaries also copied to installed app at $installedBin"
  } catch {
    Write-Warning "Installed app binaries are in use; close KNOX WALLET first, then copy manually:"
    Write-Warning "  copy $binDir\*.exe $installedBin\"
  }
}

Write-Host "Desktop binaries copied to $binDir"
