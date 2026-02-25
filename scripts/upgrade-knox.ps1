param(
  [string]$InstallerPath = "",
  [string]$SetupExe = ""
)

$ErrorActionPreference = "Stop"

function Stop-KnoxProcesses {
  Get-Process -ErrorAction SilentlyContinue |
    Where-Object {
      $n = $_.ProcessName.ToLowerInvariant()
      ($n -like "*knox*") -or
      ($n -like "*electron*") -or
      ($n -like "*node*")
    } |
    Stop-Process -Force -ErrorAction SilentlyContinue
}

function Get-UninstallCommand {
  $entries = Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "*KNOX WALLET*" } |
    Select-Object -First 1
  if ($entries -and $entries.UninstallString) {
    return [string]$entries.UninstallString
  }
  $fallback = Join-Path $env:LOCALAPPDATA "Programs\KNOX WALLET\Uninstall KNOX WALLET.exe"
  if (Test-Path $fallback) {
    return "`"$fallback`""
  }
  return ""
}

function Invoke-SilentUninstall([string]$cmd) {
  if (-not $cmd) { return }
  if ($cmd -match '^\s*"([^"]+)"\s*(.*)$') {
    $exe = $matches[1]
    $args = $matches[2]
  } else {
    $parts = $cmd.Split(" ", 2)
    $exe = $parts[0]
    $args = if ($parts.Count -gt 1) { $parts[1] } else { "" }
  }
  $args = "$args /S".Trim()
  Write-Host "Running silent uninstall..."
  Start-Process -FilePath $exe -ArgumentList $args -Wait -NoNewWindow
}

function Resolve-Installer([string]$explicit) {
  if ($explicit -and (Test-Path $explicit)) {
    return (Resolve-Path $explicit).Path
  }
  $root = Split-Path -Parent $PSScriptRoot
  $dist = Join-Path $root "apps\knox-wallet-desktop\dist"
  $candidates = @()
  $candidates += Get-ChildItem $dist -File -Filter "*.msi" -ErrorAction SilentlyContinue
  $candidates += Get-ChildItem $dist -File -Filter "*Setup*.exe" -ErrorAction SilentlyContinue
  $installer = $candidates | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if (-not $installer) {
    throw "No installer (.msi or Setup .exe) found in $dist. Build first with scripts/build-installer.ps1."
  }
  return $installer.FullName
}

Stop-KnoxProcesses
Start-Sleep -Milliseconds 500

$uninstallCmd = Get-UninstallCommand
if ($uninstallCmd) {
  Invoke-SilentUninstall $uninstallCmd
  Start-Sleep -Seconds 1
}

Stop-KnoxProcesses
$resolvedInput = if ($InstallerPath) { $InstallerPath } else { $SetupExe }
$installer = Resolve-Installer $resolvedInput
Write-Host "Launching installer: $installer"
if ($installer.ToLowerInvariant().EndsWith(".msi")) {
  Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$installer`" /qn /norestart" -Wait -NoNewWindow
} else {
  Start-Process -FilePath $installer -Wait
}

Write-Host "Upgrade complete."
