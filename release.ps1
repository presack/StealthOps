# release.ps1 — build both binaries, tag, and publish a GitHub release
# Usage:  .\release.ps1 v1.2.3 ["Release notes here"]
#
# Requires: gh CLI authenticated, WSL2 with build-linux.sh dependencies available

param(
    [Parameter(Mandatory)][string]$Version,
    [string]$Notes = ""
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# Validate version format
if ($Version -notmatch '^v\d+\.\d+\.\d+$') {
    Write-Error "Version must be in the form v1.2.3"
    exit 1
}

# Ensure no uncommitted changes (untracked files are fine)
$status = git status --porcelain | Where-Object { $_ -notmatch '^\?\?' }
if ($status) {
    Write-Error "Working tree has uncommitted changes. Commit or stash first.`n$status"
    exit 1
}

# Ensure tag doesn't already exist
if (git tag -l $Version) {
    Write-Error "Tag $Version already exists."
    exit 1
}

$WinBin   = Join-Path $ScriptDir "dist\windows\stealthops.exe"
$LinuxBin = Join-Path $ScriptDir "dist\linux\stealthops"

# ── Build Windows ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Building Windows EXE ===" -ForegroundColor Cyan
& "$ScriptDir\build.ps1"
if (-not (Test-Path $WinBin)) { Write-Error "Windows build failed — $WinBin not found"; exit 1 }

# ── Build Linux ──────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Building Linux binary (via WSL) ===" -ForegroundColor Cyan
wsl bash ./build-linux.sh
if (-not (Test-Path $LinuxBin)) { Write-Error "Linux build failed — $LinuxBin not found"; exit 1 }

# ── Tag and release ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Creating release $Version ===" -ForegroundColor Cyan

git tag $Version
git push origin $Version

$ReleaseNotes = if ($Notes) { $Notes } else {
    "StealthOps $Version`n`nPrivacy-hardened OSINT/reconnaissance utility.`n`n**Downloads**`n- ``stealthops.exe`` — Windows x64`n- ``stealthops`` — Linux x64 (glibc)"
}

gh release create $Version `
    --title "StealthOps $Version" `
    --notes $ReleaseNotes `
    "$WinBin#stealthops-windows-x64.exe" `
    "$LinuxBin#stealthops-linux-x64"

Write-Host ""
Write-Host "Release $Version published." -ForegroundColor Green
gh release view $Version --web
