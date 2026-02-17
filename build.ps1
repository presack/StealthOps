$ErrorActionPreference = "Stop"

if (-not (Test-Path ".\vendor\tor")) {
    Write-Warning "vendor\\tor not found. EXE will build, but no bundled Tor runtime will be included."
}

python -m pip install --upgrade pyinstaller
pyinstaller --noconfirm --onefile --name StealthOps --add-data "vendor\tor;tor" main.py

Write-Host "Build complete: .\dist\StealthOps.exe"
