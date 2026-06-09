# release.ps1 — build both binaries, tag, and publish a GitHub release
# Usage:  .\scripts\release.ps1 v1.2.3 ["Release notes here"]
#
# Requires: gh CLI authenticated, WSL2 with build-linux.sh dependencies available

param(
    [Parameter(Mandatory)][string]$Version,
    [string]$Notes = ""
)

$ErrorActionPreference = "Stop"
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
Set-Location $ProjectRoot

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

$WinBin       = Join-Path $ProjectRoot "dist\windows\stealthops.exe"
$LinuxBin     = Join-Path $ProjectRoot "dist\linux\stealthops"
$WinUpload    = Join-Path $ProjectRoot "dist\stealthops-windows-x64.exe"
$LinuxUpload  = Join-Path $ProjectRoot "dist\stealthops-linux-x64"
$ChecksumFile = Join-Path $ProjectRoot "dist\checksums.txt"

# Locate gh CLI (check PATH, then common install locations)
$GhExe = (Get-Command gh -ErrorAction SilentlyContinue)?.Source
if (-not $GhExe) {
    foreach ($candidate in @(
        "C:\Program Files\GitHub CLI\gh.exe",
        "$env:LOCALAPPDATA\Programs\GitHub CLI\gh.exe",
        "$env:ProgramFiles\GitHub CLI\gh.exe"
    )) {
        if (Test-Path $candidate) { $GhExe = $candidate; break }
    }
}
if (-not $GhExe) {
    Write-Error ("gh CLI not found. Install from https://cli.github.com/ then run:`n" +
        "  gh release create $Version --title 'StealthOps $Version' ``
        --notes 'StealthOps $Version' ``
        '${WinBin}#stealthops-windows-x64.exe' ``
        '${LinuxBin}#stealthops-linux-x64'")
    exit 1
}

# ── Stamp version ────────────────────────────────────────────────────────────
$VersionNum = $Version.TrimStart("v")
Set-Content (Join-Path $ProjectRoot "_version.py") "__version__ = `"$VersionNum`"`n"
git add "_version.py"
git commit -m "Bump version to $Version"
git push

# ── Build Windows ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Building Windows EXE ===" -ForegroundColor Cyan
& "$ScriptDir\build.ps1"
if (-not (Test-Path $WinBin)) { Write-Error "Windows build failed — $WinBin not found"; exit 1 }

# ── Build Linux ──────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Building Linux binary (via WSL) ===" -ForegroundColor Cyan
wsl bash scripts/build-linux.sh
if (-not (Test-Path $LinuxBin)) { Write-Error "Linux build failed — $LinuxBin not found"; exit 1 }

# ── Checksums ────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Generating checksums ===" -ForegroundColor Cyan
Copy-Item $WinBin   $WinUpload   -Force
Copy-Item $LinuxBin $LinuxUpload -Force
$WinHash   = (Get-FileHash $WinUpload   -Algorithm SHA256).Hash.ToLower()
$LinuxHash = (Get-FileHash $LinuxUpload -Algorithm SHA256).Hash.ToLower()
"$WinHash  stealthops-windows-x64.exe`n$LinuxHash  stealthops-linux-x64" | Set-Content $ChecksumFile
Write-Host "  $WinHash  stealthops-windows-x64.exe"
Write-Host "  $LinuxHash  stealthops-linux-x64"

# ── Tag and release ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Creating release $Version ===" -ForegroundColor Cyan

git tag $Version
git push origin $Version

$InstallLine      = "irm https://github.com/presack/StealthOps/releases/latest/download/install.ps1 | iex"
$LinuxInstallLine = "curl -fsSL https://github.com/presack/StealthOps/releases/latest/download/install.sh | bash"
$ReleaseNotes = if ($Notes) { $Notes } else {
@"
StealthOps $Version

Privacy-hardened OSINT/reconnaissance utility.

**Install (Windows — no admin required)**

Open PowerShell and run:

``````powershell
$InstallLine
``````

**Install (Linux x86_64)**

```bash
$LinuxInstallLine
```

**Downloads**
- ``stealthops-windows-x64.exe`` — Windows x64
- ``stealthops-linux-x64`` — Linux x64 (glibc)
"@
}

$InstallPs1 = Join-Path $ProjectRoot "install.ps1"
$InstallSh  = Join-Path $ProjectRoot "install.sh"

& $GhExe release create $Version `
    --title "StealthOps $Version" `
    --notes $ReleaseNotes `
    $WinUpload `
    $LinuxUpload `
    "$ChecksumFile#checksums.txt" `
    "$InstallPs1#install.ps1" `
    "$InstallSh#install.sh"

Write-Host ""
Write-Host "Release $Version published." -ForegroundColor Green
& $GhExe release view $Version --web
