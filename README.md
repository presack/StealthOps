# StealthOps

Privacy-hardened OSINT/reconnaissance utility. DNS, WHOIS, MX, HTTP headers, and 13+ threat-intel enrichment providers — routed through Tor when you want it.

## Install

**Windows** (PowerShell — no admin required):

```powershell
irm https://github.com/presack/StealthOps/releases/latest/download/install.ps1 | iex
```

Installs to `%LOCALAPPDATA%\Programs\StealthOps\`, adds to PATH, and sets up the Linux binary in WSL2 automatically. Windows and WSL2 share the same API key store so keys only need to be entered once.

**Linux** (x86_64):

```bash
curl -fsSL https://github.com/presack/StealthOps/releases/latest/download/install.sh | bash
```

Installs to `~/.local/bin/`, adds to PATH in `.bashrc`/`.zshrc`. SHA256-verified.

After installing, open a new terminal and run:

```
stealthops --console
```

To configure enrichment provider API keys:

```
stealthops --configure-keys
```

## Usage

### Console mode (primary)

```powershell
stealthops --console
```

Console commands:

```
example.com             # query
8.8.8.8
mode stealth            # route through Tor
mode public             # direct route
enrich all-enabled      # run all enrichment providers with keys
vt <target>             # VirusTotal shortcut
shodan <target>
providers               # list provider key status
keys                    # show API key status
set-key                 # interactive API key setup wizard
tor install             # install/update managed Tor
tor status
web                     # start web server in background
update                  # check for and apply the latest release
version
```

### CLI mode

```powershell
stealthops example.com
stealthops 8.8.8.8 --enrich all-enabled
stealthops example.com --mode stealth
stealthops --web
stealthops --version
stealthops --update
stealthops --configure-keys
stealthops --providers
```

### Web dashboard

```powershell
stealthops --web
```

Opens at `http://127.0.0.1:5000`. Includes a Settings page (⚙ icon) for managing API keys in the browser.

## Enrichment providers

13 third-party providers, each requiring an API key. Run `stealthops --configure-keys` to enter keys interactively.

| Provider | Targets | Notes |
|---|---|---|
| VirusTotal | IP · Domain · URL | |
| ViewDNS | IP · Domain · URL | |
| MXToolbox | IP · Domain · URL | |
| DNSDB | IP · Domain · URL | |
| URLScan | IP · Domain · URL | |
| Shodan | IP | |
| Censys | IP | |
| Spur | IP | |
| AbuseIPDB | IP | |
| GreyNoise | IP | |
| DNSDumpster | Domain · URL | |
| SecurityTrails | Domain · URL | |
| Spamhaus | ASN | |
| RIPEstat | ASN | |

Keys are stored in `%LOCALAPPDATA%\StealthOps\keys.env` (Windows) or `~/.config/stealthops/keys.env` (Linux). Environment variables take precedence if set.

## Tor / stealth mode

StealthOps can route queries through Tor. In stealth mode, DNS is resolved via DNS-over-HTTPS through the Tor SOCKS5 proxy.

```powershell
stealthops --install-tor          # install managed Tor runtime
stealthops example.com --mode stealth
stealthops --console              # then: mode stealth
```

Tor discovery order:
1. `TOR_PATH` environment variable
2. Managed runtime at `%LOCALAPPDATA%\StealthOps\tor\current`
3. Bundled Tor (if included at build time)
4. System Tor in PATH

## Updates

StealthOps checks for updates in the background on launch (throttled to once per 24 hours) and shows a one-line notice when a newer version is available.

To update immediately:

```powershell
stealthops --update
```

Or in console mode: `update`

## Build from source

Requires Python 3.12 and Windows (for the Windows build):

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py --console
```

Build standalone EXE:

```powershell
.\build.ps1
# Output: dist\windows\stealthops.exe
```

Build Linux binary (run in WSL2 or Linux):

```bash
bash ./build-linux.sh
# Output: dist/linux/stealthops
```

Full release (stamps version, builds both, creates GitHub release):

```powershell
.\release.ps1 v1.2.3
```

## Deployment modes

StealthOps runs in three modes:

| Mode | How to activate | Auth | API keys |
|---|---|---|---|
| **Personal** | default | none | env vars or `--configure-keys` |
| **Server** | `SERVER_MODE=1` | form login (cookie session) | per-user, encrypted in SQLite |
| **Training** | `TRAINING_MODE=1` | HTTP Basic Auth | env vars, shared across all users |

### Server mode (multi-user)

Server mode adds user accounts and per-user encrypted API key storage. Each user logs in with a username and password and manages their own keys via the web Settings page.

```bash
# 1. Generate an encryption key (do once, store securely)
python main.py --generate-fernet-key

# 2. Create users
python main.py --create-user alice
python main.py --list-users

# 3. Run
SERVER_MODE=1 FERNET_KEY=<key> python main.py --web
```

### Training mode (hosted events)

Training mode is for short-lived shared deployments — a class or workshop where multiple participants share one instance. It enables HTTP Basic Auth, a 24-hour result cache, elevated rate limits, and locks enrichment to `all-enabled` (provider selection is hidden from users).

```bash
TRAINING_MODE=1 TRAINING_AUTH_USER=stealthops TRAINING_AUTH_PASS=<passphrase> python main.py --web
```

### Cloud / Docker deployment

The `deploy/` directory contains scripts for GCP-based deployments:

| Script | Purpose |
|---|---|
| `deploy/create-vm.sh` | Provision a GCP e2-small VM, open firewall ports, print IP |
| `deploy/vm-setup.sh` | Run on the VM: install Docker + nginx, issue a Let's Encrypt cert, start the container |
| `deploy/nginx.conf` | nginx config template (TLS termination, proxy to uvicorn) |

The stack is Docker + docker-compose, nginx reverse proxy, Let's Encrypt TLS. The result cache persists in a named Docker volume across container restarts.

```bash
# On GCP Cloud Shell — provision VM
bash deploy/create-vm.sh <name> <gcp-project-id> <zone>

# SSH into VM, clone repo, create .env, then run setup
bash deploy/vm-setup.sh <subdomain.yourdomain.com> <email>

# Redeploy after a code change
git pull && sudo docker compose up -d --build
```

## License

MIT
