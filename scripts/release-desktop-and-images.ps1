param(
  [string]$Version = "",
  [ValidateSet("patch", "minor", "major", "prepatch", "preminor", "premajor", "prerelease", "")]
  [string]$Bump = "",
  [string]$Tag = "",
  [string]$GhRepo = "ULT7RA/KNOXProtocol",
  [string]$GhcrOwner = "ult7ra",
  [string]$DockerhubOrg = "ult7ra",
  [switch]$CommitVersion,
  [switch]$PushGit,
  [string]$GitRemote = "origin",
  [string]$GitBranch = "",
  [switch]$PushImages,
  [switch]$PublishRelease,
  [switch]$SkipInstaller,
  [switch]$SkipDocker
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$desktopDir = Join-Path $root "apps/knox-wallet-desktop"
$distDir = Join-Path $desktopDir "dist"

function Require-Command([string]$name) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
    throw "Missing required command: $name"
  }
}

function Get-GitCurrentBranch {
  $branch = ((& git rev-parse --abbrev-ref HEAD) | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($branch) -or $branch -eq "HEAD") {
    throw "Could not determine current git branch"
  }
  return $branch
}

if (-not [string]::IsNullOrWhiteSpace($Version) -and -not [string]::IsNullOrWhiteSpace($Bump)) {
  throw "Use either -Version or -Bump, not both"
}

$doGitReleaseOps = $CommitVersion -or $PushGit
if ($doGitReleaseOps) {
  Require-Command "git"
  $dirty = (& git status --porcelain=v1 -uno)
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to inspect git working tree"
  }
  if ($dirty) {
    throw "Git working tree must be clean before using -CommitVersion or -PushGit"
  }
}

if (-not [string]::IsNullOrWhiteSpace($Bump)) {
  Require-Command "npm.cmd"
  Write-Host ""
  Write-Host "[pre] bumping desktop version ($Bump)"
  Push-Location $desktopDir
  try {
    npm.cmd version $Bump --no-git-tag-version
    if ($LASTEXITCODE -ne 0) {
      throw "Version bump failed"
    }
  } finally {
    Pop-Location
  }
}

if ([string]::IsNullOrWhiteSpace($Version)) {
  $pkg = Get-Content -Raw (Join-Path $desktopDir "package.json") | ConvertFrom-Json
  $Version = $pkg.version
}
if ([string]::IsNullOrWhiteSpace($Tag)) {
  $Tag = "v$Version"
}

$notesFile = Join-Path $root "release-notes-v$Version.md"

Write-Host "release version: $Version"
Write-Host "release tag:     $Tag"
Write-Host "github repo:     $GhRepo"
Write-Host "ghcr owner:      $GhcrOwner"
Write-Host "dockerhub org:   $DockerhubOrg"
Write-Host "git remote:      $GitRemote"
if (-not [string]::IsNullOrWhiteSpace($Bump)) {
  Write-Host "version bump:    $Bump"
}

$installer = $null
$installerSha = $null

if (-not $SkipInstaller) {
  Require-Command "powershell.exe"
  Write-Host ""
  Write-Host "[1/5] building MSI installer"
  & powershell.exe -NoProfile -File (Join-Path $root "scripts/build-installer.ps1")

  $candidates = @()
  $candidates += Get-ChildItem $distDir -File -Filter "*.msi" -ErrorAction SilentlyContinue
  $candidates += Get-ChildItem $distDir -File -Filter "*Setup*.exe" -ErrorAction SilentlyContinue
  $installer = $candidates | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if (-not $installer) {
    throw "Installer build completed but no MSI/Setup artifact was found in $distDir"
  }
  $installerSha = "$($installer.FullName).sha256"
  $hash = (Get-FileHash $installer.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  "$hash  $($installer.Name)" | Set-Content -NoNewline $installerSha
  Write-Host "installer: $($installer.FullName)"
  Write-Host "sha256:    $installerSha"
} else {
  Write-Host ""
  Write-Host "[1/5] skipping installer build"
}

$nodeGhcr = "ghcr.io/$GhcrOwner/knox-node"
$guiGhcr = "ghcr.io/$GhcrOwner/knox-gui"
$nodeDh = "$DockerhubOrg/knox-node"
$guiDh = "$DockerhubOrg/knox-gui"

if (-not $SkipDocker) {
  Require-Command "docker"
  Write-Host ""
  Write-Host "[2/5] building Docker images"
  & docker build -f (Join-Path $root "docker/Dockerfile.node") `
    -t "${nodeGhcr}:${Version}" `
    -t "${nodeGhcr}:latest" `
    -t "${nodeDh}:${Version}" `
    -t "${nodeDh}:latest" `
    $root

  & docker build -f (Join-Path $root "docker/Dockerfile.gui") `
    -t "${guiGhcr}:${Version}" `
    -t "${guiGhcr}:latest" `
    -t "${guiDh}:${Version}" `
    -t "${guiDh}:latest" `
    $root
} else {
  Write-Host ""
  Write-Host "[2/5] skipping Docker build"
}

if ($PushImages) {
  Require-Command "docker"
  Write-Host ""
  Write-Host "[3/5] pushing Docker images"
  @(
    "${nodeGhcr}:${Version}",
    "${nodeGhcr}:latest",
    "${nodeDh}:${Version}",
    "${nodeDh}:latest",
    "${guiGhcr}:${Version}",
    "${guiGhcr}:latest",
    "${guiDh}:${Version}",
    "${guiDh}:latest"
  ) | ForEach-Object {
    & docker push $_
  }
} else {
  Write-Host ""
  Write-Host "[3/5] skipping Docker push"
}

if ($doGitReleaseOps) {
  Write-Host ""
  Write-Host "[4/5] committing/tagging Git release metadata"
  & git add -- "apps/knox-wallet-desktop/package.json" "apps/knox-wallet-desktop/package-lock.json"
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to stage desktop version files"
  }

  & git diff --cached --quiet --exit-code
  if ($LASTEXITCODE -eq 0) {
    Write-Host "[git] no staged version file changes to commit"
  } else {
    & git commit -m "chore(release): v$Version"
    if ($LASTEXITCODE -ne 0) {
      throw "Git commit failed"
    }
  }

  & git rev-parse --verify --quiet "refs/tags/$Tag" *> $null
  if ($LASTEXITCODE -eq 0) {
    $tagCommit = ((& git rev-list -n 1 $Tag) | Out-String).Trim()
    $headCommit = ((& git rev-parse HEAD) | Out-String).Trim()
    if ($tagCommit -ne $headCommit) {
      throw "Tag $Tag already exists at $tagCommit (HEAD is $headCommit)"
    }
    Write-Host "[git] tag $Tag already exists at HEAD"
  } else {
    & git tag -a $Tag -m "KNOX v$Version"
    if ($LASTEXITCODE -ne 0) {
      throw "Failed to create git tag $Tag"
    }
  }

  if ($PushGit) {
    if ([string]::IsNullOrWhiteSpace($GitBranch)) {
      $GitBranch = Get-GitCurrentBranch
    }
    Write-Host "[git] pushing branch $GitBranch to $GitRemote"
    & git push $GitRemote $GitBranch
    if ($LASTEXITCODE -ne 0) {
      throw "Failed to push branch $GitBranch to $GitRemote"
    }
    Write-Host "[git] pushing tag $Tag to $GitRemote"
    & git push $GitRemote $Tag
    if ($LASTEXITCODE -ne 0) {
      throw "Failed to push tag $Tag to $GitRemote"
    }
  } else {
    Write-Host "[git] push skipped (use -PushGit to push branch/tag)"
  }
} else {
  Write-Host ""
  Write-Host "[4/5] skipping Git commit/tag/push"
}

if ($PublishRelease) {
  Require-Command "gh"
  if (-not $installer) {
    throw "--PublishRelease requires an installer artifact; do not use -SkipInstaller"
  }

  Write-Host ""
  Write-Host "[5/5] publishing GitHub release asset(s)"
  & gh release view $Tag --repo $GhRepo *> $null
  if ($LASTEXITCODE -eq 0) {
    & gh release upload $Tag $installer.FullName $installerSha --repo $GhRepo --clobber
  } else {
    if (Test-Path $notesFile) {
      & gh release create $Tag $installer.FullName $installerSha `
        --repo $GhRepo `
        --title "KNOX v$Version" `
        --notes-file $notesFile
    } else {
      & gh release create $Tag $installer.FullName $installerSha `
        --repo $GhRepo `
        --title "KNOX v$Version" `
        --notes "KNOX v$Version"
    }
  }
} else {
  Write-Host ""
  Write-Host "[5/5] skipping GitHub release publish"
}

Write-Host ""
Write-Host "done"
if ($installer) {
  Write-Host "installer artifact: $($installer.FullName)"
  Write-Host "installer sha256:   $installerSha"
}
Write-Host "docker tags:"
Write-Host "  ${nodeGhcr}:${Version}"
Write-Host "  ${nodeGhcr}:latest"
Write-Host "  ${nodeDh}:${Version}"
Write-Host "  ${nodeDh}:latest"
Write-Host "  ${guiGhcr}:${Version}"
Write-Host "  ${guiGhcr}:latest"
Write-Host "  ${guiDh}:${Version}"
Write-Host "  ${guiDh}:latest"
