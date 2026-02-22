$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$binDir = Join-Path $root "apps/knox-wallet-desktop/bin"
$certDir = Join-Path $binDir "certs"
$target = "x86_64-pc-windows-msvc"
New-Item -ItemType Directory -Force -Path $binDir | Out-Null
New-Item -ItemType Directory -Force -Path $certDir | Out-Null

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

Write-Host "Desktop binaries copied to $binDir"
