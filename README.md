# StealthOps

StealthOps is a privacy-hardened reconnaissance utility inspired by CentralOps.
It supports both CLI and web dashboard workflows and defaults to Tor-routed operations.

## Features

- Dual mode execution:
  - CLI mode when `--query` is provided
  - Web mode when no query argument is provided
- Automated Tor lifecycle with `stem`:
  - Detect existing Tor SOCKS proxy (`127.0.0.1:9050` or `127.0.0.1:9150`)
  - Attempt background Tor launch if unavailable
  - Verify Tor circuit before routed requests
- Managed Tor runtime:
  - Uses app-managed Tor at `%LOCALAPPDATA%\StealthOps\tor\current` when available
  - Can bootstrap managed runtime from bundled Tor files
  - Optional update checks with modes: `auto`, `force`, `off`
- Query engine modules:
  - DNS lookup (A, AAAA, NS, TXT, CNAME, CAA, SOA)
  - MX lookup
  - WHOIS lookup
  - HTTP header inspection
- Privacy UI indicator:
  - Green shield: Tor verified
  - Red shield: Tor unavailable, standard route in use
  - `Block Non-Tor Traffic` toggle to hard-fail if Tor is down

## Project Structure

- `main.py`: entrypoint, CLI/web mode switching
- `tor_engine.py`: Tor discovery, launch, verification, lifecycle
- `tor_updater.py`: managed runtime bootstrap + update checks
- `core_ops.py`: DNS/MX/WHOIS/header logic
- `web_ui.py`: FastAPI app + Tailwind dashboard
- `requirements.txt`: runtime dependencies

## Tor Runtime Selection Order

1. `TOR_PATH` override (if set and valid)
2. Managed Tor runtime (`%LOCALAPPDATA%\StealthOps\tor\current`)
3. Bundled Tor (copied into managed runtime on first use)
4. System Tor in PATH/common install locations

Use `--prefer-system-tor` to prioritize system Tor over managed runtime.

## Requirements

- Python 3.10+
- Tor executable available by one of:
  - Bundled with app (recommended for standalone builds)
  - In `PATH` as `tor`/`tor.exe`
  - Via environment variable `TOR_PATH`

## Install

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage

### Web mode (default)

```powershell
python main.py
```

This starts FastAPI on `127.0.0.1:5000`.

Web controls:

- `Run Stealth Query (Tor)`: attempts Tor-routed requests.
- `Run Fast Query (Public)`: bypasses Tor for speed.
- `Block Non-Tor Traffic`: fail closed when Tor mode is selected and Tor is unavailable.
- `Install / Update Managed Tor`: appears when Tor is not verified and triggers managed runtime bootstrap/update.
- `Update Manifest URL`: optional field in Tor Setup panel for runtime updates when no bundled runtime is present.

### CLI mode

```powershell
python main.py --query example.com
```

Default CLI output is formatted for readability. Use raw JSON when needed:

```powershell
python main.py --query example.com --json
```

Force strict privacy behavior:

```powershell
python main.py --query example.com --block-non-tor
```

Tor update controls:

```powershell
python main.py --query example.com --tor-update auto
python main.py --query example.com --tor-update force
python main.py --query example.com --tor-update off
```

Provide update manifest URL:

```powershell
python main.py --query example.com --tor-update-manifest https://example.com/tor-manifest.json
```

Prefer system Tor:

```powershell
python main.py --query example.com --prefer-system-tor
```

## Update Manifest Format

Expected JSON keys:

```json
{
  "version": "14.5.2",
  "windows_url": "https://example.com/tor-expert-bundle-windows-x86_64-14.5.2.zip",
  "sha256": "<sha256-lowercase-hex>"
}
```

- `sha256` is required and enforced before activation.
- In `auto` mode, update checks are TTL-based (default 24 hours).
- If no manifest is provided, updater attempts to discover latest Windows Tor Expert Bundle directly from `torproject.org` and resolves SHA256 from `sha256sums-signed-build.txt`.

## PyInstaller (single EXE)

Build a standalone executable and bundle Tor folder contents:

```powershell
pyinstaller --onefile --name StealthOps --add-data "vendor\tor;tor" main.py
```

Notes:

- Bundle the Tor directory, not only `tor.exe`, so companion files remain available.
- On first run, bundled files are copied to managed runtime and launched from there.

## Privacy Notes

- DNS/MX attempts are Tor-first via DoH when Tor is verified.
- If `Block Non-Tor Traffic` is enabled and Tor is unavailable, queries fail closed.
- WHOIS behavior depends on upstream libraries and registry responses; errors are surfaced in output.

## License

MIT
