# StealthOps installer for Windows (+ WSL2)
# Usage: irm https://github.com/presack/StealthOps/releases/latest/download/install.ps1 | iex

[CmdletBinding()]
param(
    [string]$Version = "",          # pin to a specific tag, e.g. "v1.0.2"; default = latest
    [switch]$NoWsl,                  # skip WSL2 Linux binary setup
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Programs\StealthOps")
)

$ErrorActionPreference = "Stop"
$Repo = "presack/StealthOps"

function Write-Step { param([string]$Msg) Write-Host "  $Msg" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Msg) Write-Host "  + $Msg" -ForegroundColor Green }
function Write-Warn { param([string]$Msg) Write-Host "  ! $Msg" -ForegroundColor Yellow }

Write-Host ""
Write-Host "  StealthOps Installer" -ForegroundColor White
Write-Host ("  " + ([string][char]0x2500) * 38)
Write-Host ""

# ── Fetch release metadata ────────────────────────────────────────────────────
$ApiBase = "https://api.github.com/repos/$Repo/releases"
$ApiUrl  = if ($Version) { "$ApiBase/tags/$Version" } else { "$ApiBase/latest" }

Write-Step "Fetching release info..."
try {
    $Release = Invoke-RestMethod -Uri $ApiUrl -Headers @{ "User-Agent" = "StealthOps-Installer" }
} catch {
    Write-Host "  ERROR: Could not reach GitHub API. Check network and try again." -ForegroundColor Red
    exit 1
}

$Tag    = $Release.tag_name
$Assets = @{}
foreach ($a in $Release.assets) { $Assets[$a.name] = $a }
Write-Ok "Release: $Tag"

# ── Resolve asset URLs ────────────────────────────────────────────────────────
$WinAsset      = "stealthops-windows-x64.exe"
$LinuxAsset    = "stealthops-linux-x64"
$ChecksumAsset = "checksums.txt"

if (-not $Assets.ContainsKey($WinAsset)) {
    Write-Host "  ERROR: Windows binary '$WinAsset' not found in release $Tag." -ForegroundColor Red
    exit 1
}

$WinUrl      = $Assets[$WinAsset].browser_download_url
$LinuxUrl    = if ($Assets.ContainsKey($LinuxAsset)) { $Assets[$LinuxAsset].browser_download_url } else { $null }
$ChecksumUrl = if ($Assets.ContainsKey($ChecksumAsset)) { $Assets[$ChecksumAsset].browser_download_url } else { $null }

# ── Download and parse checksums ──────────────────────────────────────────────
$Checksums = @{}
if ($ChecksumUrl) {
    Write-Step "Fetching checksums..."
    try {
        $Raw = (Invoke-WebRequest -Uri $ChecksumUrl -Headers @{ "User-Agent" = "StealthOps-Installer" }).Content
        foreach ($Line in ($Raw -split "`n")) {
            $Line = $Line.Trim()
            if ($Line) {
                $Parts = $Line -split '\s+', 2
                if ($Parts.Count -eq 2) { $Checksums[$Parts[1]] = $Parts[0] }
            }
        }
    } catch {
        Write-Warn "Could not fetch checksums — SHA256 verification will be skipped."
    }
}

# ── Helper: download + verify + place ────────────────────────────────────────
function Install-Asset {
    param(
        [string]$Url,
        [string]$AssetName,
        [string]$DestPath
    )
    $Tmp = "$DestPath.tmp"
    Write-Step "Downloading $AssetName..."
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Tmp -Headers @{ "User-Agent" = "StealthOps-Installer" }
    } catch {
        Write-Host "  ERROR: Download failed for $AssetName`: $_" -ForegroundColor Red
        if (Test-Path $Tmp) { Remove-Item $Tmp -Force }
        exit 1
    }

    $Expected = $Checksums[$AssetName]
    if ($Expected) {
        $Actual = (Get-FileHash $Tmp -Algorithm SHA256).Hash.ToLower()
        if ($Actual -ne $Expected) {
            Remove-Item $Tmp -Force
            Write-Host "  ERROR: SHA256 mismatch for $AssetName" -ForegroundColor Red
            Write-Host "    expected: $Expected"
            Write-Host "    got:      $Actual"
            exit 1
        }
        Write-Ok "SHA256 verified"
    } else {
        Write-Warn "No checksum entry for $AssetName — skipping verification"
    }

    Move-Item -Path $Tmp -Destination $DestPath -Force
}

# ── Create install directory ──────────────────────────────────────────────────
Write-Step "Installing to $InstallDir ..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# ── Install Windows binary ────────────────────────────────────────────────────
$WinDest = Join-Path $InstallDir "stealthops.exe"
Install-Asset -Url $WinUrl -AssetName $WinAsset -DestPath $WinDest
Write-Ok "stealthops.exe installed"

# ── Install Linux binary ──────────────────────────────────────────────────────
$LinuxDest = $null
if ($LinuxUrl) {
    $LinuxDest = Join-Path $InstallDir "stealthops"
    Install-Asset -Url $LinuxUrl -AssetName $LinuxAsset -DestPath $LinuxDest
    Write-Ok "stealthops (Linux) installed"
} else {
    Write-Warn "Linux binary not found in release $Tag — skipping"
}

# ── Add to Windows PATH (HKCU, no admin required) ────────────────────────────
Write-Step "Updating PATH..."
$RegPath     = "HKCU:\Environment"
$CurrentPath = (Get-ItemProperty -Path $RegPath -Name Path -ErrorAction SilentlyContinue).Path
if (-not $CurrentPath) { $CurrentPath = "" }

$PathParts = $CurrentPath -split ";" | Where-Object { $_ -ne "" }
if ($PathParts -notcontains $InstallDir) {
    $NewPath = ($PathParts + $InstallDir) -join ";"
    Set-ItemProperty -Path $RegPath -Name Path -Value $NewPath
    # Also update current session so `stealthops` works without reopening terminal
    $env:PATH = ($env:PATH.TrimEnd(";") + ";" + $InstallDir)
    Write-Ok "Added to user PATH"
} else {
    Write-Ok "Already on PATH"
}

# Broadcast WM_SETTINGCHANGE so Explorer/taskbar pick up the new PATH without a reboot
try {
    $sig = '[DllImport("user32.dll")] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);'
    $Type = Add-Type -MemberDefinition $sig -Name WinApi -Namespace Win32 -PassThru
    $result = [UIntPtr]::Zero
    $Type::SendMessageTimeout([IntPtr]0xffff, 0x1a, [UIntPtr]::Zero, "Environment", 2, 5000, [ref]$result) | Out-Null
} catch { }

# ── WSL2: symlink Linux binary into ~/.local/bin ──────────────────────────────
if (-not $NoWsl -and $LinuxDest -and (Get-Command wsl -ErrorAction SilentlyContinue)) {
    Write-Step "Configuring WSL2..."
    try {
        # Convert Windows path to WSL mount path
        $WslSrc = wsl wslpath -u ($LinuxDest -replace '\\', '/')
        # Symlink, chmod, ensure ~/.local/bin is in PATH
        $WslCmd = @"
set -e
chmod +x '$WslSrc'
mkdir -p ~/.local/bin
ln -sf '$WslSrc' ~/.local/bin/stealthops
grep -qxF 'export PATH=\$HOME/.local/bin:\$PATH' ~/.bashrc 2>/dev/null || echo 'export PATH=\$HOME/.local/bin:\$PATH' >> ~/.bashrc
grep -qxF 'export PATH=\$HOME/.local/bin:\$PATH' ~/.zshrc  2>/dev/null || true
"@
        wsl bash -c $WslCmd
        Write-Ok "Symlinked in WSL2 ~/.local/bin/stealthops"
    } catch {
        Write-Warn "WSL2 setup skipped: $_"
    }
} elseif (-not (Get-Command wsl -ErrorAction SilentlyContinue)) {
    Write-Warn "WSL2 not detected — Linux binary installed but not linked"
}

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  StealthOps $Tag installed successfully." -ForegroundColor Green
Write-Host ""
Write-Host "  Open a new terminal, then run:" -ForegroundColor White
Write-Host "    stealthops --console" -ForegroundColor Cyan
Write-Host "    stealthops example.com" -ForegroundColor Cyan
Write-Host "    stealthops --web" -ForegroundColor Cyan
Write-Host ""
Write-Host "  To configure API keys:" -ForegroundColor White
Write-Host "    stealthops --configure-keys" -ForegroundColor Cyan
Write-Host ""
