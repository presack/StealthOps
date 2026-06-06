#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv-build-linux"

mkdir -p "$SCRIPT_DIR/dist/linux" "$SCRIPT_DIR/build/linux"

echo "==> Setting up build venv at $VENV_DIR"
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip --quiet
"$VENV_DIR/bin/pip" install --upgrade pyinstaller --quiet
"$VENV_DIR/bin/pip" install -r "$SCRIPT_DIR/requirements.txt" --quiet

echo "==> Running PyInstaller"
"$VENV_DIR/bin/pyinstaller" \
  --noconfirm \
  --onefile \
  --name stealthops \
  --distpath "$SCRIPT_DIR/dist/linux" \
  --workpath "$SCRIPT_DIR/build/linux" \
  --collect-data whois \
  --collect-submodules uvicorn \
  --collect-submodules fastapi \
  --collect-submodules starlette \
  "$SCRIPT_DIR/main.py"

echo "Build complete: $SCRIPT_DIR/dist/linux/stealthops"
