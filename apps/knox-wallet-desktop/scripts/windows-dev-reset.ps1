param(
  [string]$RepoRoot = "D:\KNOX"
)

$ErrorActionPreference = "Stop"
if ($PSVersionTable.PSVersion.Major -ge 7) {
  $PSNativeCommandUseErrorActionPreference = $false
}

$Toolchain = "stable-x86_64-pc-windows-msvc"
$RustTarget = "x86_64-pc-windows-msvc"
$RustupExe = Join-Path $env:USERPROFILE ".cargo\bin\rustup.exe"
$ToolchainRoot = Join-Path $env:USERPROFILE ".rustup\toolchains\$Toolchain"
$RustcExe = Join-Path $ToolchainRoot "bin\rustc.exe"
$CargoExe = Join-Path $ToolchainRoot "bin\cargo.exe"

$cargoToml = Join-Path $RepoRoot "Cargo.toml"
$appDir = Join-Path $RepoRoot "apps\knox-wallet-desktop"
$binDir = Join-Path $appDir "bin"
$targetDir = Join-Path $RepoRoot ("target-msvc-run-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
$userDataDir = Join-Path $env:APPDATA "knox-wallet-desktop"
$tlsDir = Join-Path $userDataDir "tls"
$nodeDataDir = Join-Path $userDataDir "data\node"

if (!(Test-Path $RustupExe)) { throw "Missing rustup shim: $RustupExe" }
if (!(Test-Path $cargoToml)) { throw "Missing Cargo.toml: $cargoToml" }
if (!(Test-Path $appDir)) { throw "Missing app dir: $appDir" }

Write-Host "[1/9] Stop running processes..."
Get-Process electron,knox-node,knox-wallet,knox-wallet-cli -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host "[2/9] Clear conflicting Rust env vars..."
Remove-Item Env:RUSTC,Env:RUSTDOC,Env:RUSTFLAGS,Env:CARGO_BUILD_TARGET,Env:CARGO_TARGET_DIR,Env:RUSTUP_TOOLCHAIN,Env:RUSTC_WRAPPER,Env:CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue

Write-Host "[3/9] Reset rustup override + ensure MSVC toolchain..."
$overrideLines = & $RustupExe override list 2>$null
$hasOverride = $false
if ($overrideLines) {
  foreach ($line in $overrideLines) {
    if ($line -match ("^\s*" + [regex]::Escape($RepoRoot) + "\s")) {
      $hasOverride = $true
      break
    }
  }
}
if ($hasOverride) {
  & $RustupExe override unset --path $RepoRoot 2>$null | Out-Null
} else {
  Write-Host "No rustup override at $RepoRoot (skip unset)"
}
& $RustupExe default $Toolchain | Out-Null
& $RustupExe toolchain install $Toolchain --profile default | Out-Null
& $RustupExe target add --toolchain $Toolchain $RustTarget | Out-Null
& $RustupExe component add --toolchain $Toolchain rust-std --target $RustTarget | Out-Null

if (!(Test-Path $RustcExe)) { throw "Missing toolchain rustc: $RustcExe" }
if (!(Test-Path $CargoExe)) { throw "Missing toolchain cargo: $CargoExe" }

Write-Host "[4/9] Verify compiler/target..."
$rustcInfo = & $RustcExe -vV
$rustcInfo | ForEach-Object { Write-Host $_ }
if (-not ($rustcInfo -match "host:\s*x86_64-pc-windows-msvc")) {
  throw "Wrong rustc host detected. Expected x86_64-pc-windows-msvc."
}
$targetLibDir = & $RustcExe --print target-libdir --target $RustTarget
if (!(Test-Path $targetLibDir)) { throw "Missing target libdir: $targetLibDir" }
Write-Host "Target build dir: $targetDir"

Write-Host "[5/9] Clean fresh target dir..."
if (Test-Path $targetDir) { Remove-Item $targetDir -Recurse -Force }

Write-Host "[6/9] Build node/wallet/wallet-cli with MSVC cargo directly..."
& $CargoExe build --manifest-path $cargoToml --target $RustTarget --target-dir $targetDir -p knox-node --bin knox-node
& $CargoExe build --manifest-path $cargoToml --target $RustTarget --target-dir $targetDir -p knox-walletd --bin knox-wallet
& $CargoExe build --manifest-path $cargoToml --target $RustTarget --target-dir $targetDir -p knox-wallet --bin knox-wallet-cli

Write-Host "[7/9] Copy fresh binaries..."
New-Item -ItemType Directory -Force -Path $binDir | Out-Null
Copy-Item (Join-Path $targetDir "$RustTarget\debug\knox-node.exe") (Join-Path $binDir "knox-node.exe") -Force
Copy-Item (Join-Path $targetDir "$RustTarget\debug\knox-wallet.exe") (Join-Path $binDir "knox-wallet.exe") -Force
Copy-Item (Join-Path $targetDir "$RustTarget\debug\knox-wallet-cli.exe") (Join-Path $binDir "knox-wallet-cli.exe") -Force

Write-Host "[8/9] Reset TLS + node bootstrap files..."
New-Item -ItemType Directory -Force -Path $tlsDir | Out-Null
Remove-Item (Join-Path $tlsDir "walletd.crt"),(Join-Path $tlsDir "walletd.key") -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $nodeDataDir | Out-Null
if (!(Test-Path (Join-Path $nodeDataDir "validators.txt"))) {
  Set-Content -Path (Join-Path $nodeDataDir "validators.txt") -Value ""
}
$repoValidators = Join-Path $RepoRoot "testnet\validators.txt"
if (Test-Path $repoValidators) {
  Copy-Item $repoValidators (Join-Path $nodeDataDir "validators.txt") -Force
  Write-Host "Seeded validators from $repoValidators"
}

Write-Host "[9/9] Reinstall desktop deps + launch..."
Set-Location $appDir
if (Test-Path (Join-Path $appDir "node_modules")) {
  Remove-Item (Join-Path $appDir "node_modules") -Recurse -Force
}
npm install
npm run dev
