# StealthOps

StealthOps is a privacy-hardened reconnaissance utility inspired by CentralOps.
It supports both CLI and web dashboard workflows and defaults to Tor-routed operations.

## Features

- Dual mode execution:
  - CLI mode when `--query` is provided
  - Web mode when no query argument is provided
- Automated Tor lifecycle with `stem`:
  - Detect existing Tor SOCKS proxy (`127.0.0.1:9050`)
  - Attempt background Tor launch if unavailable
  - Verify Tor circuit before routed requests
- Query engine modules:
  - DNS lookup
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
- `core_ops.py`: DNS/MX/WHOIS/header logic
- `web_ui.py`: FastAPI app + Tailwind dashboard
- `requirements.txt`: runtime dependencies

## Requirements

- Python 3.10+
- Tor executable available by one of:
  - In `PATH` as `tor`/`tor.exe`
  - At `./tor/tor.exe` or `./bin/tor.exe`
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

### CLI mode

```powershell
python main.py --query example.com
```

Force strict privacy behavior:

```powershell
python main.py --query example.com --block-non-tor
```

Custom web bind:

```powershell
python main.py --host 127.0.0.1 --port 5000
```

## PyInstaller (single EXE)

Build a standalone executable:

```powershell
pyinstaller --onefile --name StealthOps main.py
```

If bundling a Tor Expert Bundle with your app, ship the Tor binary in a known relative path (`.\tor\tor.exe` or `.\bin\tor.exe`) or set `TOR_PATH` at runtime.

## Privacy Notes

- DNS/MX attempts are Tor-first via DoH when Tor is verified.
- If `Block Non-Tor Traffic` is enabled and Tor is unavailable, queries fail closed.
- WHOIS behavior depends on upstream libraries and registry responses; errors are surfaced in output.

## License

MIT
