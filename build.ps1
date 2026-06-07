$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvDir   = Join-Path $ScriptDir ".venv-build-windows"
$PythonExe = Join-Path $VenvDir "Scripts\python.exe"
$PipExe    = Join-Path $VenvDir "Scripts\pip.exe"
$DistDir   = Join-Path $ScriptDir "dist\windows"
$BuildDir  = Join-Path $ScriptDir "build\windows"
$ReqFile   = Join-Path $ScriptDir "requirements.txt"
$HashFile  = Join-Path $VenvDir ".req_hash"
$PyiExe    = Join-Path $VenvDir "Scripts\pyinstaller.exe"

Set-Location $ScriptDir

# Create venv only if it doesn't exist
if (-not (Test-Path $PythonExe)) {
    Write-Host "==> Creating build venv"
    py -3.12 -m venv $VenvDir
    & $PipExe install --upgrade pip --quiet
}

# Reinstall dependencies only when requirements.txt changes or PyInstaller is missing
$CurrentHash = (Get-FileHash $ReqFile -Algorithm SHA256).Hash
$StoredHash  = if (Test-Path $HashFile) { (Get-Content $HashFile).Trim() } else { "" }

if ($CurrentHash -ne $StoredHash -or -not (Test-Path $PyiExe)) {
    Write-Host "==> Installing/updating dependencies"
    & $PipExe install --upgrade pip --quiet
    & $PipExe install -r $ReqFile pyinstaller --quiet
    Set-Content $HashFile $CurrentHash
} else {
    Write-Host "==> Dependencies up to date, skipping install"
}

$pyiArgs = @(
    "--noconfirm",
    "--onefile",
    "--name", "stealthops",
    "--distpath", $DistDir,
    "--workpath", $BuildDir,
    "--collect-data", "whois",
    "--collect-submodules", "uvicorn",
    "--collect-submodules", "fastapi",
    "--collect-submodules", "starlette"
)
if (Test-Path ".\vendor\tor") {
    Write-Host "Bundling Tor runtime from .\vendor\tor"
    $pyiArgs += @("--add-data", "vendor\tor;tor")
} else {
    Write-Warning "vendor\\tor not found. Building lean EXE without bundled Tor runtime."
}
$pyiArgs += "main.py"

& $PythonExe -m PyInstaller @pyiArgs

Write-Host "Build complete: $(Join-Path $DistDir 'stealthops.exe')"
