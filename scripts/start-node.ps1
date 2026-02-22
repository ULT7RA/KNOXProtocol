param(
  [string]$DataDir = ".\data",
  [string]$Bind = "127.0.0.1:9736",
  [string]$RpcBind = "-",
  [string]$Peers = "",
  [string]$ValidatorsFile = "",
  [string]$MinerAddress = "",
  [switch]$NoMine,
  [switch]$ForceMinerChange
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Resolve-NodeExe {
  $root = Split-Path -Parent $PSScriptRoot
  $candidates = @(
    (Join-Path $root "target-msvc-clean\x86_64-pc-windows-msvc\debug\knox-node.exe"),
    (Join-Path $root "target-msvc-clean\x86_64-pc-windows-msvc\release-lite\knox-node.exe"),
    (Join-Path $root "target-msvc-clean\debug\knox-node.exe"),
    (Join-Path $root "target-msvc-clean\release-lite\knox-node.exe")
  )
  foreach ($p in $candidates) {
    if (Test-Path $p) { return $p }
  }
  throw "knox-node.exe not found. Build it first."
}

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not $MinerAddress) {
  $MinerAddress = $env:KNOX_MINER_ADDRESS
}
if (-not $MinerAddress) {
  throw "Miner address not set. Pass -MinerAddress or set KNOX_MINER_ADDRESS."
}
if ($MinerAddress -notmatch '^knox1[a-f0-9]{128}$') {
  throw "Invalid miner address format. Expected knox1 + 128 lowercase hex chars."
}

$resolvedDataDir = [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $DataDir))
New-Item -ItemType Directory -Force -Path $resolvedDataDir | Out-Null

if (-not $ValidatorsFile) {
  $ValidatorsFile = Join-Path $resolvedDataDir "validators.txt"
}
$resolvedValidators = [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $ValidatorsFile))
if (-not (Test-Path $resolvedValidators)) {
  throw "Validators file not found: $resolvedValidators"
}

$minerLock = Join-Path $resolvedDataDir "miner-address.lock"
if (Test-Path $minerLock) {
  $locked = (Get-Content -Raw $minerLock).Trim()
  if ($locked -and $locked -ne $MinerAddress -and -not $ForceMinerChange) {
    throw "Miner address mismatch for this data dir. Locked=$locked Requested=$MinerAddress. Use -ForceMinerChange to override."
  }
}
Set-Content -NoNewline -Path $minerLock -Value $MinerAddress

$nodeExe = Resolve-NodeExe
$args = @($resolvedDataDir, $RpcBind, $Bind, $Peers, $resolvedValidators, $MinerAddress)
$env:KNOX_NODE_NO_MINE = if ($NoMine) { "1" } else { "0" }

Write-Host "Starting KNOX node..."
Write-Host " - node: $nodeExe"
Write-Host " - data: $resolvedDataDir"
Write-Host " - bind: $Bind"
Write-Host " - rpc: $RpcBind"
Write-Host " - validators: $resolvedValidators"
Write-Host " - miner: $MinerAddress"
Write-Host " - mine: " -NoNewline
Write-Host ($(if ($NoMine) { "off" } else { "on" }))

Start-Process -FilePath $nodeExe -ArgumentList $args -NoNewWindow -Wait
