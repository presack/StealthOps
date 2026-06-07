#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv-build-linux"
REQ_FILE="$SCRIPT_DIR/requirements.txt"
HASH_FILE="$VENV_DIR/.req_hash"

mkdir -p "$SCRIPT_DIR/dist/linux" "$SCRIPT_DIR/build/linux"

# Create venv only if it doesn't exist
if [ ! -f "$VENV_DIR/bin/python" ]; then
    echo "==> Creating build venv at $VENV_DIR"
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --upgrade pip --quiet
fi

# Reinstall dependencies only when requirements.txt changes or PyInstaller is missing
CURRENT_HASH=$(sha256sum "$REQ_FILE" | cut -d' ' -f1)
STORED_HASH=$(cat "$HASH_FILE" 2>/dev/null || echo "")

if [ "$CURRENT_HASH" != "$STORED_HASH" ] || ! "$VENV_DIR/bin/python" -c "import PyInstaller" 2>/dev/null; then
    echo "==> Installing/updating dependencies"
    "$VENV_DIR/bin/pip" install pyinstaller --quiet
    "$VENV_DIR/bin/pip" install -r "$REQ_FILE" --quiet
    echo "$CURRENT_HASH" > "$HASH_FILE"
else
    echo "==> Dependencies up to date, skipping install"
fi

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
  --hidden-import _version \
  "$SCRIPT_DIR/main.py"

echo "Build complete: $SCRIPT_DIR/dist/linux/stealthops"
