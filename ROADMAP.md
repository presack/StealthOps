# StealthOps Roadmap

## Planned

### Feature: `draw` command — link chart export to draw.io

**Files:** `console.py`, new `draw.py`

Generate a `.drawio` XML file visualizing relationships between all indicators queried in the current session (or a provided list). Intended for post-investigation use: analyst completes a pivot chain, types `draw`, gets a shareable link chart.

**Input modes (all three supported, like `bulk`):**
- `draw` — uses session history (current session's queried targets, in order)
- `draw <ind1> <ind2> ...` — inline list of indicators
- `draw [file]` — path to a file with one indicator per line

For the session-history and file/inline modes, data is pulled from the SQLite cache first (no re-fetch if already queried); cache misses trigger a live fetch.

**Output:** `~/Downloads/stealthops-map-<timestamp>.drawio` (draw.io XML). Analyst opens in diagrams.net (free, browser-based) or the VS Code draw.io extension; uses Edit → Select All → Auto Layout to tidy positioning.

**Entities extracted from result dicts:**
- Domains (from query target and WHOIS domain)
- IP addresses (A/AAAA records, network WHOIS IP)
- ASN / org name (from network WHOIS)
- Subdomains (from ViewDNS enrichment)
- Co-hosted domains (from ViewDNS reverse IP)
- Historical IPs (from ViewDNS IP history)

**Edge types (labeled):**
- `A record` — domain → IP
- `PTR` — IP → domain
- `subdomain` — apex domain → subdomain
- `co-hosted` — IP → domain (suppress or show as count label when >10 to avoid hairball)
- `historical IP` — domain → IP (dashed edge)
- `MX` — domain → mail host
- `NS` — domain → nameserver

**Layout:** Assign rough positions by entity type (target at center, IPs as first ring, co-hosted/subdomains as outer ring). draw.io auto-arrange handles cleanup. Node style varies by type (domain = rectangle, IP = ellipse, ASN = hexagon).

**Session history cap increase:** Raise from 10 to 50 entries in `console.py`. The dict is in-memory and 50 full result dicts are not a meaningful memory concern. This makes the no-args `draw` mode useful for full investigation sessions without the analyst having to track which targets fell off the end of the deque.

**Known limitations:**
- Co-hosted relationships generate O(n) edges per IP — default behavior should suppress co-hosted edges when count > 10 and instead label the IP node with "63 co-hosted domains"
- Historical IP edges should be dashed/gray to distinguish from live relationships
- draw.io XML positions are approximate; auto-layout required for clean output on complex graphs

### Feature: Web console — browser-based StealthOps REPL embedded in the web UI

**Files:** `web_ui.py`, `templates/` (xterm.js panel), `console.py` (web-console guard flags)

Add a `>_` terminal icon to the web UI nav bar that opens a resizable console panel anchored to the bottom of the viewport — same pattern as Google Cloud Shell. Each session gets a live StealthOps REPL running inside the browser with no local install required. Particularly valuable in TRAINING_MODE where students may be on locked-down machines.

**Backend — WebSocket endpoint in `web_ui.py`:**

```python
@app.websocket("/ws/console")
async def console_websocket(websocket: WebSocket):
    # authenticate: check session cookie (SERVER_MODE) or Basic Auth header (TRAINING_MODE)
    await websocket.accept()
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "main.py", "--console", "--no-color", "--web-console",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=_console_env(user),   # inject per-user keys in SERVER_MODE
    )
    # bidirectional pipe: WebSocket text → proc.stdin; proc.stdout → WebSocket text
    # on WebSocket disconnect: proc.kill()
```

Subprocess is `python main.py --console`, not a shell. No shell escapes exist in the console REPL, so arbitrary command execution is not possible.

**Frontend — xterm.js panel:**

- xterm.js loaded from CDN (or vendored); `xterm-addon-fit` for responsive resizing
- Panel anchored to bottom of viewport, 40% height default, drag handle to resize
- Toggle button: `>_` icon in nav bar (right side, consistent with Cloud Shell placement)
- "Pop out" button to open in a dedicated browser tab if desired
- ANSI color codes rendered natively by xterm.js — `--no-color` flag NOT needed if xterm.js is handling rendering (remove it; color output will be richer than the web form)

**New CLI flag: `--web-console`**

Passed to `main.py` when spawned by the WebSocket handler. Enables a set of guards in `console.py` and `main.py` that restrict commands inappropriate in a multi-user web context:

| Command | Behavior in `--web-console` mode |
|---|---|
| `bulk [file]` | File-path argument disabled; paste/inline mode only |
| `tor install` | Disabled — prints "not available in web console mode" |
| `update` | Disabled — server is managed by the operator |
| `set-key` | Disabled in TRAINING_MODE (shared keys). In SERVER_MODE: allowed, writes to per-user keystore |
| `web` | No-op — already running |
| `report` | Generates PDF server-side; response includes a download link via `/download/report/<id>` |

**Authentication and key injection:**

- *TRAINING_MODE:* WebSocket upgrade request must include valid Basic Auth credentials (same as all other endpoints). Console subprocess inherits shared env var keys — no extra injection needed.
- *SERVER_MODE:* WebSocket upgrade checks session cookie. On connect, build a subprocess env that includes the authenticated user's decrypted API keys, same as `EnrichmentManager.__init__(key_overrides=...)` does for web queries.

**Mode gating:**

Web console is available in TRAINING_MODE and SERVER_MODE. Not exposed in personal mode (no web UI there). In TRAINING_MODE, Tor-related commands are already suppressed in the UI; the `--web-console` flag adds the same suppression in the console subprocess.

**Process lifecycle:**

One subprocess per WebSocket connection. On client disconnect (tab close, navigation, network drop): `proc.kill()`, then `proc.wait()`. No orphan processes. Idle timeout: kill subprocess after 10 minutes of no stdin activity, send a message to xterm.js before closing.

**Rate limiting:**

Web console connections count against the existing per-IP rate limit. Additionally: max 2 concurrent console sessions per authenticated user (SERVER_MODE) or per IP (TRAINING_MODE) to prevent resource exhaustion.

### Reference: CTF deployment (separate repo)

Training exercises built on StealthOps are maintained in a separate repository and deployed using CTFd (open-source, Docker-based CTF platform). This is a reference note for the relationship between the two projects.

**Architecture:**
- StealthOps TRAINING_MODE instance provides the tool students use to investigate indicators
- CTFd instance hosts challenge descriptions, accepts flag submissions, tracks scores
- Both run as Docker Compose services; can share a VM (e2-medium recommended) or run separately

**CTFd deployment:** Add as a second Docker Compose service alongside StealthOps, or deploy independently. CTFd image: `ctfd/ctfd`. Challenge content is managed in the CTF repo (YAML/JSON import into CTFd).

**Challenge format:** Each question in the training exercise maps to a CTFd challenge. Flag values are discrete, verifiable strings extracted from StealthOps output (e.g., `frogiesarcade.win`, `school-helper101`, `maddox05`). Difficulty tiers map to CTFd point values.

