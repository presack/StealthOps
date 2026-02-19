# StealthOps

StealthOps is a privacy-hardened reconnaissance utility inspired by CentralOps.
It supports both CLI and web dashboard workflows and defaults to fast public-route queries unless stealth mode is selected.

## Features

- Dual mode execution:
  - CLI mode when target is provided (`stealthops <target>`)
  - Interactive console mode via `--console`
  - Web mode via `--web`
- Automated Tor lifecycle with `stem`:
  - Detect existing Tor SOCKS proxy (`127.0.0.1:9050` or `127.0.0.1:9150`)
  - Attempt background Tor launch if unavailable
  - Verify Tor circuit before routed requests
- Managed Tor runtime:
  - Uses app-managed Tor at `%LOCALAPPDATA%\StealthOps\tor\current` when available
  - Can bootstrap managed runtime from bundled Tor files
  - Optional update checks with modes: `auto`, `force`, `off`
- Query engine modules:
  - Address lookup (canonical name, aliases, addresses)
  - Accepts domain, URL, or IP targets
  - DNS lookup (A, AAAA, NS, TXT, CNAME, CAA, SOA)
  - MX lookup
  - WHOIS lookup
  - Network WHOIS lookup (RDAP for resolved IPs)
  - HTTP header inspection
  - Raw record views:
    - Domain WHOIS record transcript (when available from provider/library)
    - Network WHOIS transcript-style record
- Privacy UI indicator:
  - Public/Stealth mode status shown in header
  - Stealth mode is fail-closed by default in web mode
  - Results stream into the page progressively as each section completes

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

### Startup behavior

With no arguments, StealthOps prints help and an interactive quick menu:

- `1` Start Web Server
- `2` Start Console
- `3` or `Enter` Exit

### Web mode

```powershell
python main.py --web
```

Custom bind:

```powershell
python main.py --web --host 127.0.0.1 --port 5000
```

Web controls:

- Header controls:
  - `Public Mode` (default, fast route)
  - `Stealth Mode` (Tor-routed when available)
- Stealth mode is fail-closed by default in web mode (non-Tor fallback disabled).
- `Install / Update Managed Tor`: appears when Stealth Mode is selected and Tor is not verified.
- Install/update flow shows the official source URL first and requires confirmation before downloading.

### CLI mode

```powershell
python main.py example.com
python main.py 167.99.60.180
```

Install/update managed Tor runtime from CLI:

```powershell
python main.py --install-tor
```

Default CLI output is formatted for readability. Use raw JSON when needed:

```powershell
python main.py example.com --json
```

Force strict privacy behavior:

```powershell
python main.py example.com --block-non-tor
```

Default mode is `public` for quick results. Use stealth mode when needed:

```powershell
python main.py example.com --mode stealth
```

Run without Tor and emit raw JSON:

```powershell
python main.py example.com --mode public --json
```

If Tor is unavailable and you run stealth CLI mode, StealthOps will prompt to install managed Tor when running interactively.

Tor update controls:

```powershell
python main.py example.com --tor-update auto
python main.py example.com --tor-update force
python main.py example.com --tor-update off
```

Prefer system Tor:

```powershell
python main.py example.com --prefer-system-tor
```

### Interactive console mode

Start console mode with persistent route preference:

```powershell
python main.py --console
```

Disable console colors when needed:

```powershell
python main.py --console --no-color
```

Disable colors in CLI output as well:

```powershell
python main.py example.com --no-color
```

Start console in stealth mode:

```powershell
python main.py --console --mode stealth
```

Console commands:

- `query <target>`
- `<target>` (shorthand query)
- `!<target>` (forced shorthand query)
- `mode <stealth|public>`
- `tor install`
- `tor status`
- `web [host] [port]`
- `banner`
- `status`
- `block <on|off>`
- `json <on|off>`
- `clear`
- `exit`

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
- If no manifest is provided, updater discovers the latest Windows Tor Expert Bundle directly from `torproject.org` and resolves SHA256 from `sha256sums-signed-build.txt`.
- `--tor-update-manifest` remains optional for advanced/self-hosted update workflows.

## Standalone EXE (no Python required for users)

Build machine requirements (only for the person creating the EXE):

```powershell
pip install -r requirements.txt
pip install pyinstaller
```

Create a single-file Windows executable and bundle Tor folder contents:

```powershell
pyinstaller --onefile --name StealthOps --collect-data whois --add-data "vendor\tor;tor" main.py
```

Or use the helper script (auto-detects whether `vendor\tor` exists):

```powershell
.\build.ps1
```

Output:

- `dist\StealthOps.exe`

Run examples for end users (no venv required):

```powershell
.\dist\StealthOps.exe
.\dist\StealthOps.exe example.com
.\dist\StealthOps.exe example.com --mode stealth
.\dist\StealthOps.exe --web
```

Packaging notes:

- Bundle the Tor directory, not only `tor.exe`, so companion files remain available.
- On first run, bundled files are copied to managed runtime and launched from there.
- If `vendor\tor` is not present at build time, users can still run in default public mode or use `--install-tor`.

Optional: populate `vendor\tor` from an existing Tor Browser install before building:

```powershell
New-Item -ItemType Directory -Force .\vendor\tor | Out-Null
Copy-Item "C:\Program Files\Tor Browser\Browser\TorBrowser\Tor\*" .\vendor\tor -Recurse -Force
```

## Linux Build

Build Linux artifacts on a Linux machine (or Linux VM/WSL):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install pyinstaller
pyinstaller --onefile --name stealthops --collect-data whois --collect-submodules uvicorn --collect-submodules fastapi --collect-submodules starlette main.py
```

Output:

- `dist/stealthops`

Run:

```bash
./dist/stealthops --web --host 0.0.0.0 --port 5000
```

Note: Tor managed update flow is currently Windows-manifest oriented. On Linux, prefer system Tor (`--prefer-system-tor`) or set `TOR_PATH`.

## Cloud Deployment (Web App)

This repo now includes:

- `Dockerfile`
- `deploy/gcp.sh`
- `deploy/azure.sh`

No separate repo is required.

### Option A: Google Cloud Run (easy + free tier available)

Prereqs:

- `gcloud` CLI installed
- Logged in: `gcloud auth login`
- Billing-enabled GCP project

Deploy:

```bash
bash deploy/gcp.sh <PROJECT_ID> us-central1 stealthops
```

Example:

```bash
bash deploy/gcp.sh my-project-123 us-central1 stealthops
```

The script:

1. Enables required APIs
2. Builds the container with Cloud Build
3. Deploys to Cloud Run
4. Prints your service URL

### Option B: Azure Container Apps (easy managed container)

Prereqs:

- `az` CLI installed
- Logged in: `az login`
- Active subscription selected

Deploy:

```bash
bash deploy/azure.sh <RESOURCE_GROUP> eastus stealthops stealthops-env
```

Example:

```bash
bash deploy/azure.sh rg-stealthops eastus stealthops stealthops-env
```

The script:

1. Installs/updates Container Apps CLI extension
2. Registers required Azure providers
3. Creates/updates the resource group
4. Builds/deploys app from current source
5. Prints your app FQDN

### Updating after code changes

Run the same deploy command again. It rebuilds and rolls out the new version.

### Cost note

Cloud Run and Azure Container Apps both have free allowances, but not guaranteed to be fully free for all workloads. Monitor usage and set budgets/alerts.

## Privacy Notes

- In stealth mode, DNS/MX attempts are Tor-first via DoH when Tor is verified.
- If `Block Non-Tor Traffic` is enabled and Tor is unavailable, queries fail closed.
- WHOIS behavior depends on upstream libraries and registry responses; errors are surfaced in output.

## License

MIT
