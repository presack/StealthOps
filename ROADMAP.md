# StealthOps Roadmap

## Planned

### Polish: Drop `uuid` column from urlscan recent_scans table (web UI)

**File:** `web_ui.py` (`provider_specific` dict, `render_dict_list_table`)

The `uuid` column in the urlscan enrichment table is redundant — `result_url` already links directly to the scan (the URL path embeds the UUID). The column consumes space without adding value visible to the analyst.

**Fix:** Remove `"uuid"` from the `("urlscan", "recent_scans")` column list in `provider_specific`:

```python
("urlscan", "recent_scans"): ["time", "domain", "ip", "score", "result_url"],
```

This brings the table to 5 columns, giving the remaining columns more breathing room. The `uuid` field remains in the raw payload (not removed from `urlscan.py`) in case it is useful in the future or accessed programmatically.

---

### Polish: Prompt to restart after self-update

**Files:** `console.py` (update command handler), `updater.py` (`do_update`)

After `do_update()` succeeds in the console, prompt the user before restarting:

```
Update applied — restart now to use v1.1.12? [y/N]
```

If yes: `os.execv(sys.executable, sys.argv)` re-execs the new binary in-place.

**What survives a restart:** SQLite query cache (6h TTL), API keys (`keys.env`). **What resets:** in-memory console state (`enrich` mode, `stealth`/`public` mode, `json on/off`, session history for `last`/`reload`) — all reset to safe defaults, acceptable.

Don't auto-restart without the prompt. The current `update` flow already has one confirmation step (user types `update`); silently re-executing a freshly downloaded binary after that crosses a trust line. The prompt is two characters of friction and keeps the user in control.

### Feature: ASN query support in core pipeline

**Files:** `core_ops.py` (`run_all_staged`, new `asn_rdap_lookup`), `formatter.py` (`format_cli_report`)

**Problem:** Querying an ASN directly (`36963` or `AS36963`) falls into the domain branch of `run_all_staged` because there is no ASN-aware code path in the core engine. The result is a wall of DNS/WHOIS/MX errors. Enrichment providers handle ASNs correctly (they call `classify_target` from `_shared.py`) but the core query never gets that far.

**Fix — core_ops.py:**

1. At the start of `run_all_staged`, call `normalize_asn(lookup_target)` (import from `enrichment.providers._shared`). If it returns a value, take an ASN-specific code path: skip DNS/WHOIS/MX/headers, run `asn_rdap_lookup(asn)`, and return a result dict shaped like `{"asn_query": asn, "asn_rdap": <rdap_data>}`.

2. New method `asn_rdap_lookup(asn: str) -> dict`: query RDAP bootstrap for the ASN:
   - `https://rdap.org/autnum/{asn}` (bootstraps to correct RIR)
   - Parse name, type, handle, country, events (registration/expiry dates), entities (org, abuse contact).
   - Return structured dict with keys: `asn`, `name`, `type`, `handle`, `country`, `org_name`, `abuse_email`, `creation_date`, `updated_date`, `rdap_url`.

**Fix — formatter.py:**

`format_cli_report` checks for `"asn_query"` key. If present, renders a focused ASN report:
- `=== ASN LOOKUP === [source: RDAP autnum]` with the structured RDAP fields
- `=== ENRICHMENT ===` if enrichment ran
- Omits ADDRESS LOOKUP / DNS / WHOIS / MX / NS / TXT / HTTP sections entirely (no misleading errors)

**`_normalize_lookup_target`:** strip leading `AS`/`as` before returning for ASN targets so the display target stays readable but routing is unambiguous.

**Console UX:** both `36963` and `AS36963` should work identically; `classify_target` already normalizes both forms.

### Improvement: Bulk triage — fix blank ASN, N/A for inapplicable columns, domain network data

**Files:** `bulk.py`, `bulk.py:TRIAGE_PRESET_PROVIDERS`

Three related issues discovered while triaging IP indicators:

**1. ASN blank for RIPE/APNIC/LACNIC IPs**

`network_whois` (RDAP) often omits origin ASN for non-ARIN ranges. The ASN column stays blank even though ipinfo (already a free, no-key-required provider) returns `asn` (e.g. `"AS13335"`) for every IP.

Fix:
- Add `"ipinfo"` to `TRIAGE_PRESET_PROVIDERS` so it runs by default on bulk IP queries (no key required, negligible cost).
- In `flatten_result` for IP targets, fall back to `ipinfo.get("asn")` when `nw.get("asn")` is empty. Also pull `org_name` from ipinfo as fallback for Organization when RDAP org is empty.

**2. Domain-specific columns blank vs. "N/A" for IP targets**

When the target is an IP, columns that require a domain registration (Registrar, Created, Expires, Domain Status, Nameservers, MX Hosts) are structurally impossible to populate — they're not just empty, they don't apply. Blank is ambiguous; "N/A" communicates intent and makes it easier to spot genuinely missing data vs. intentionally skipped fields.

Fix: in `flatten_result`, set those six columns to `"N/A"` for IP targets, and set CIDR/ASN to `"N/A"` for domain targets only if `network_whois` also returned nothing (i.e. couldn't resolve an IP).

**3. Domain rows missing ASN/Org/Country/CIDR**

`flatten_result` only pulls `network_whois` fields (ASN, Organization, Country, CIDR) for `target_type == "ip"`. But `run_all` also runs `network_whois_lookup` for domain targets via their resolved A record — the data is already in the result dict. Domain rows should populate those columns the same way IP rows do.

Fix: move the `nw` field extraction (ASN, Organization, Country, CIDR) outside the `if target_type == "ip"` block so it applies to all target types, then let the N/A logic above handle the columns that truly don't apply.

### Polish: Suppress empty WHOIS contact blocks

**File:** `core_ops.py` (`_build_contact_block`)

**Current behavior:** When a WHOIS record has no registrant/admin/tech contact data (common for registries like CentralNic that only return registrar-level fields), the output shows empty section headers:

```
Registrant:


Administrative Contact:


Technical Contact:
```

**Desired behavior:** Omit the section entirely when all fields are empty. If at least one field (name, org, street, city, state, country, phone, email) has a value, render the block as normal.

**Fix:** In `_build_contact_block`, build `rendered` before appending the title line. Only return the block (title + fields) if `rendered` is non-empty. Return an empty list otherwise so the caller's `lines.extend()` adds nothing.

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

