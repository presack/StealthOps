#!/usr/bin/env bash
# StealthOps installer for Linux and macOS
# Usage: curl -fsSL https://github.com/presack/StealthOps/releases/latest/download/install.sh | bash

set -euo pipefail

REPO="presack/StealthOps"
INSTALL_DIR="${HOME}/.local/bin"
BIN_NAME="stealthops"

# ── Helpers ───────────────────────────────────────────────────────────────────

step()  { printf "  \033[36m%s\033[0m\n" "$*"; }
ok()    { printf "  \033[32m+ %s\033[0m\n" "$*"; }
warn()  { printf "  \033[33m! %s\033[0m\n" "$*"; }
die()   { printf "  \033[31mERROR: %s\033[0m\n" "$*" >&2; exit 1; }

printf "\n  \033[1mStealthOps Installer\033[0m\n"
printf "  %s\n\n" "--------------------------------------"

# ── Platform detection ────────────────────────────────────────────────────────

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux*)
    case "$ARCH" in
      x86_64) ASSET="stealthops-linux-x64" ;;
      *)
        die "Unsupported architecture '$ARCH'. Only x86_64 Linux is currently supported.
  To run from source: https://github.com/${REPO}#build-from-source"
        ;;
    esac
    ;;
  Darwin*)
    die "macOS binaries are not yet available.
  To run from source: https://github.com/${REPO}#build-from-source"
    ;;
  *)
    die "Unsupported OS '$OS'."
    ;;
esac

# ── Dependencies ──────────────────────────────────────────────────────────────

command -v curl >/dev/null 2>&1 || die "curl is required but not installed."

# ── Fetch release metadata ────────────────────────────────────────────────────

step "Fetching latest release..."

API_URL="https://api.github.com/repos/${REPO}/releases/latest"
RELEASE_JSON="$(curl -fsSL -H "User-Agent: StealthOps-Installer" "$API_URL")"

# Extract tag name and asset URLs using python3 (available on all modern Linux)
# Falls back to grep/sed if python3 is absent.
_json_get() {
  local key="$1" json="$2"
  if command -v python3 >/dev/null 2>&1; then
    echo "$json" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('$key', ''))
except Exception:
    pass
"
  else
    echo "$json" | grep "\"${key}\"" | head -1 | sed 's/.*"'"${key}"'": *"\([^"]*\)".*/\1/'
  fi
}

_asset_url() {
  local name="$1" json="$2"
  if command -v python3 >/dev/null 2>&1; then
    echo "$json" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for a in d.get('assets', []):
        if a.get('name') == '${name}':
            print(a.get('browser_download_url', ''))
            break
except Exception:
    pass
"
  else
    # grep for the asset block; assumes name precedes browser_download_url
    echo "$json" | grep -A5 "\"name\": \"${name}\"" | grep "browser_download_url" | head -1 \
      | sed 's/.*"browser_download_url": *"\([^"]*\)".*/\1/'
  fi
}

TAG="$(_json_get tag_name "$RELEASE_JSON")"
[ -n "$TAG" ] || die "Could not parse release tag. Check network and try again."
ok "Release: $TAG"

ASSET_URL="$(_asset_url "$ASSET" "$RELEASE_JSON")"
[ -n "$ASSET_URL" ] || die "Asset '$ASSET' not found in release $TAG."

CHECKSUM_URL="$(_asset_url "checksums.txt" "$RELEASE_JSON")"

# ── Download checksums ────────────────────────────────────────────────────────

EXPECTED_SHA=""
if [ -n "$CHECKSUM_URL" ]; then
  step "Fetching checksums..."
  CHECKSUMS="$(curl -fsSL -H "User-Agent: StealthOps-Installer" "$CHECKSUM_URL")" || true
  EXPECTED_SHA="$(echo "$CHECKSUMS" | grep "$ASSET" | awk '{print $1}')"
fi

# ── Download binary ───────────────────────────────────────────────────────────

mkdir -p "$INSTALL_DIR"
TMP_FILE="$(mktemp)"
trap 'rm -f "$TMP_FILE"' EXIT

step "Downloading $ASSET..."
curl -fsSL --progress-bar -H "User-Agent: StealthOps-Installer" "$ASSET_URL" -o "$TMP_FILE"

# ── SHA256 verification ───────────────────────────────────────────────────────

if [ -n "$EXPECTED_SHA" ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_SHA="$(sha256sum "$TMP_FILE" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    ACTUAL_SHA="$(shasum -a 256 "$TMP_FILE" | awk '{print $1}')"
  else
    warn "No sha256sum or shasum found — skipping verification"
    ACTUAL_SHA="$EXPECTED_SHA"
  fi

  if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
    printf "  \033[31mERROR: SHA256 mismatch for %s\033[0m\n" "$ASSET" >&2
    printf "    expected: %s\n" "$EXPECTED_SHA" >&2
    printf "    got:      %s\n" "$ACTUAL_SHA" >&2
    exit 1
  fi
  ok "SHA256 verified"
else
  warn "No checksum available — skipping verification"
fi

# ── Install ───────────────────────────────────────────────────────────────────

chmod +x "$TMP_FILE"
mv "$TMP_FILE" "${INSTALL_DIR}/${BIN_NAME}"
trap - EXIT
ok "Installed ${INSTALL_DIR}/${BIN_NAME}"

# ── Add ~/.local/bin to PATH ──────────────────────────────────────────────────

PATH_LINE='export PATH="$HOME/.local/bin:$PATH"'
ADDED_PATH=false

for RC in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
  # Only touch .profile if neither .bashrc nor .zshrc exist
  [ "$RC" = "$HOME/.profile" ] && [ "$ADDED_PATH" = true ] && continue
  [ -f "$RC" ] || continue
  if ! grep -qF ".local/bin" "$RC" 2>/dev/null; then
    printf '\n%s\n' "$PATH_LINE" >> "$RC"
    ok "Added ~/.local/bin to PATH in $(basename "$RC")"
    ADDED_PATH=true
  fi
done

# Also update the current session if running interactively (not piped)
if [ -t 1 ]; then
  export PATH="${HOME}/.local/bin:${PATH}"
  ok "Added to current session PATH"
fi

# ── Done ──────────────────────────────────────────────────────────────────────

printf "\n  \033[32mStealthOps %s installed.\033[0m\n\n" "$TAG"
printf "  \033[1mRun (open a new terminal first, or: source ~/.bashrc):\033[0m\n"
printf "    \033[36mstealthops --console\033[0m\n"
printf "    \033[36mstealthops example.com\033[0m\n"
printf "\n  \033[1mConfigure API keys:\033[0m\n"
printf "    \033[36mstealthops --configure-keys\033[0m\n\n"
