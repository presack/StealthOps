#!/usr/bin/env bash
set -euo pipefail

mkdir -p ./dist/linux ./build/linux

python3 -m pip install --upgrade pyinstaller
python3 -m pip install -r requirements.txt

pyinstaller \
  --noconfirm \
  --onefile \
  --name stealthops \
  --distpath ./dist/linux \
  --workpath ./build/linux \
  --collect-data whois \
  --collect-submodules uvicorn \
  --collect-submodules fastapi \
  --collect-submodules starlette \
  main.py

echo "Build complete: ./dist/linux/stealthops"
