$ErrorActionPreference = "Stop"

python -m pip install --upgrade pyinstaller

$pyiArgs = @("--noconfirm", "--onefile", "--name", "StealthOps", "--collect-data", "whois")
if (Test-Path ".\vendor\tor") {
    Write-Host "Bundling Tor runtime from .\vendor\tor"
    $pyiArgs += @("--add-data", "vendor\tor;tor")
} else {
    Write-Warning "vendor\\tor not found. Building lean EXE without bundled Tor runtime."
}
$pyiArgs += "main.py"

pyinstaller @pyiArgs

Write-Host "Build complete: .\dist\StealthOps.exe"
