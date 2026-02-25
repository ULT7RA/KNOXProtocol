param()

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$fail = $false
$rg = Get-Command rg -ErrorAction SilentlyContinue

function Check-ForbiddenPattern {
  param(
    [string]$Pattern,
    [string]$Label
  )

  $matches = @()
  if ($rg) {
    $matches = rg -n --hidden `
      --glob '!apps/**/node_modules/**' `
      --glob '!apps/**/dist/**' `
      --glob '!target*/**' `
      --glob '!.git/**' `
      --glob '!nonpublic/**' `
      --glob '!_release_quarantine_*/**' `
      --glob '!*.log' `
      --glob '!*.dmp' `
      --glob '!.gitignore' `
      --glob '!scripts/release-audit.ps1' `
      --glob '!scripts/scrub-for-publish.ps1' `
      --glob '!Cargo.lock' `
      --glob '!package-lock.json' `
      $Pattern .
  } else {
    $files = Get-ChildItem -Recurse -File -ErrorAction SilentlyContinue |
      Where-Object {
        $_.FullName -notmatch '\\node_modules\\' -and
        $_.FullName -notmatch '\\dist\\' -and
        $_.FullName -notmatch '\\target' -and
        $_.FullName -notmatch '\\.git\\' -and
        $_.FullName -notmatch '\\nonpublic\\' -and
        $_.FullName -notmatch '\\_release_quarantine_' -and
        $_.Extension -ne ".log" -and
        $_.Extension -ne ".dmp" -and
        $_.Name -ne ".gitignore" -and
        $_.Name -ne "release-audit.ps1" -and
        $_.Name -ne "scrub-for-publish.ps1" -and
        $_.Name -ne "Cargo.lock" -and
        $_.Name -ne "package-lock.json"
      }
    $matches = Select-String -Path ($files.FullName) -Pattern $Pattern -AllMatches -ErrorAction SilentlyContinue |
      ForEach-Object { "{0}:{1}:{2}" -f $_.Path, $_.LineNumber, $_.Line.Trim() }
  }

  if ($matches -and $matches.Count -gt 0) {
    Write-Host "[FAIL] $Label" -ForegroundColor Red
    $matches | ForEach-Object { Write-Host "  $_" }
    $script:fail = $true
  } else {
    Write-Host "[OK] $Label"
  }
}

function Check-ForbiddenPath {
  param(
    [string]$PathToCheck,
    [string]$Label
  )

  if (Test-Path $PathToCheck) {
    Write-Host ("[FAIL] {0}: {1} exists" -f $Label, $PathToCheck) -ForegroundColor Red
    $script:fail = $true
  } else {
    Write-Host "[OK] $Label"
  }
}

Write-Host "Running KNOX release audit..."

Check-ForbiddenPattern "smoke-wallet|data-smoke|pc-node|pc-wallet|pc-wallet-cli|Private Coin Wallet" "No legacy branding/dev names"
Check-ForbiddenPattern "change-me-now" "No default auth token placeholder"
Check-ForbiddenPattern '(?m)(\$env:(KNOX_WALLETD_ALLOW_INSECURE|KNOX_P2P_ALLOW_PLAINTEXT)\s*=\s*(1|"1")|^\s*export\s+(KNOX_WALLETD_ALLOW_INSECURE|KNOX_P2P_ALLOW_PLAINTEXT)\s*=\s*1\s*$|^\s*(KNOX_WALLETD_ALLOW_INSECURE|KNOX_P2P_ALLOW_PLAINTEXT)\s*=\s*1\s*$)' "No insecure mode usage in committed scripts/docs"

Check-ForbiddenPath ".\launch-mainnet" "No local launch secrets"
Check-ForbiddenPath ".\data" "No local chain data"
Check-ForbiddenPath ".\data-smoke" "No smoke chain data"
Check-ForbiddenPath ".\certs" "No local TLS material"
Check-ForbiddenPath ".\smoke-wallet.bin" "No local wallet file"
Check-ForbiddenPath ".\wallet-b.bin" "No test wallet file"

if ($fail) {
  Write-Host ""
  Write-Host "Release audit failed." -ForegroundColor Red
  exit 1
}

Write-Host ""
Write-Host "Release audit passed." -ForegroundColor Green
exit 0
