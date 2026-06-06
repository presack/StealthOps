$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvDir = Join-Path $ScriptDir ".venv-build-windows"
$PythonExe = Join-Path $VenvDir "Scripts\python.exe"
$DistDir = Join-Path $ScriptDir "dist\windows"
$BuildDir = Join-Path $ScriptDir "build\windows"

Set-Location $ScriptDir

py -3.12 -m venv $VenvDir

& $PythonExe -m pip install --upgrade pip
& $PythonExe -m pip install -r (Join-Path $ScriptDir "requirements.txt") pyinstaller

$pyiArgs = @(
    "--noconfirm",
    "--onefile",
    "--name",
    "stealthops",
    "--distpath",
    $DistDir,
    "--workpath",
    $BuildDir,
    "--collect-data",
    "whois",
    "--collect-submodules",
    "uvicorn",
    "--collect-submodules",
    "fastapi",
    "--collect-submodules",
    "starlette"
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
