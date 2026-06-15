"""Personal-mode API key storage in a user-writable keys.env file.

Keys are stored as ENV_VAR=value pairs. load_into_environ() is called at startup
to inject file keys into os.environ (existing env vars take precedence).

NOTE: WIZARD_ORDER and the order used in web_ui.py's _SETTINGS_PROVIDER_ORDER must stay in sync.
CONFIG_ENTRIES applies to all interfaces (wizard, console set-key, web UI).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from enrichment import PROVIDER_SPECS

# Broad target types first, then IP-only, then domain/URL-only.
WIZARD_ORDER = [
    "virustotal",
    "viewdns",
    "mxtoolbox",
    "dnsdb",
    "urlscan",
    "shodan",
    "censys",
    "spur",
    "abuseipdb",
    "greynoise",
    "otx",
    "dnsdumpster",
    "securitytrails",
]

# Non-key configuration values shown inline with provider key rows in all UIs.
# Stored in keys.env so users can set them without editing environment variables.
# "before" means the entry appears just above the named provider's key row.
CONFIG_ENTRIES: list[dict] = [
    {
        "name": "dnsdb_root",
        "env_var": "DNSDB_API_ROOT",
        "display_name": "DNSDB API Root",
        "before": "dnsdb",
        "is_url": True,
        "description": (
            "Custom DNSDB API root URL, e.g. https://fsi-NNNN.dnsdb.info/dnsdb/v2. "
            "Leave blank to use the default public endpoint (https://api.dnsdb.info/dnsdb/v2)."
        ),
    },
]

# Lookup tables built once from CONFIG_ENTRIES
_CONFIG_BY_NAME: dict[str, dict] = {e["name"]: e for e in CONFIG_ENTRIES}
# provider → list of config entries that appear before that provider's key row
_CONFIG_BEFORE: dict[str, list[dict]] = {}
for _ce in CONFIG_ENTRIES:
    _CONFIG_BEFORE.setdefault(_ce.get("before", ""), []).append(_ce)

_TARGET_LABELS: dict[tuple[str, ...], str] = {
    ("ip", "domain", "url"): "IP · Domain · URL",
    ("ip", "domain"): "IP · Domain",
    ("ip", "asn"): "IP · ASN",
    ("ip",): "IP",
    ("domain", "url"): "Domain · URL",
    ("asn",): "ASN",
}


def _target_label(provider: str) -> str:
    spec = PROVIDER_SPECS.get(provider)
    if not spec:
        return ""
    return _TARGET_LABELS.get(tuple(spec.target_types), " · ".join(spec.target_types))


def _keys_dir() -> Path:
    # STEALTHOPS_KEYS_DIR lets WSL2 point at the Windows key store so both
    # the Windows and Linux binaries share the same keys.env file.
    # Set automatically by the installer; can also be set manually.
    override = os.environ.get("STEALTHOPS_KEYS_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))
        return Path(base) / "StealthOps"
    return Path.home() / ".config" / "stealthops"


def _keys_file() -> Path:
    return _keys_dir() / "keys.env"


def _read_file() -> dict[str, str]:
    try:
        result: dict[str, str] = {}
        for line in _keys_file().read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if key:
                result[key] = value
        return result
    except Exception:
        return {}


def _write_file(data: dict[str, str]) -> None:
    try:
        _keys_dir().mkdir(parents=True, exist_ok=True)
        lines = [f"{k}={v}" for k, v in sorted(data.items()) if v]
        _keys_file().write_text("\n".join(lines) + ("\n" if lines else ""))
    except Exception:
        pass


def _primary_env_var(provider: str) -> str | None:
    spec = PROVIDER_SPECS.get(provider)
    return spec.env_vars[0] if spec and spec.env_vars else None


def load_into_environ() -> None:
    """Inject file keys into os.environ. Existing env vars are not overwritten."""
    for env_var, value in _read_file().items():
        if env_var not in os.environ and value:
            os.environ[env_var] = value


def sync_into_environ() -> None:
    """Re-read the keys file and overwrite os.environ with current values.

    Unlike load_into_environ, this always applies file values so that keys
    changed externally (web UI in another process, another terminal) are
    picked up immediately. Called on each console REPL iteration.
    """
    for env_var, value in _read_file().items():
        if value:
            os.environ[env_var] = value
        else:
            os.environ.pop(env_var, None)


def set_key(provider: str, key: str) -> bool:
    """Save or clear a key. Returns False if provider is unknown or has no env var."""
    env_var = _primary_env_var(provider)
    if not env_var:
        return False
    data = _read_file()
    if key:
        data[env_var] = key
        os.environ[env_var] = key
    else:
        data.pop(env_var, None)
        os.environ.pop(env_var, None)
    _write_file(data)
    return True


def delete_key(provider: str) -> bool:
    return set_key(provider, "")


def set_config(name: str, value: str) -> bool:
    """Save or clear a CONFIG_ENTRIES value by its name. Returns False if unknown."""
    entry = _CONFIG_BY_NAME.get(name)
    if not entry:
        return False
    env_var = entry["env_var"]
    data = _read_file()
    if value:
        data[env_var] = value
        os.environ[env_var] = value
    else:
        data.pop(env_var, None)
        os.environ.pop(env_var, None)
    _write_file(data)
    return True


def delete_config(name: str) -> bool:
    return set_config(name, "")


def get_config(name: str) -> dict:
    """Return info dict for a single CONFIG_ENTRIES value (includes value and source)."""
    entry = _CONFIG_BY_NAME.get(name)
    if not entry:
        return {}
    env_var = entry["env_var"]
    file_data = _read_file()
    file_value = file_data.get(env_var, "")
    env_value = os.environ.get(env_var, "")
    if file_value:
        source: str | None = "file"
        value = file_value
    elif env_value:
        source = "env"
        value = env_value
    else:
        source = None
        value = ""
    return {**entry, "value": value, "source": source}


def mask(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 4:
        return "••••"
    return "••••••••" + value[-4:]


def get_all() -> dict[str, dict]:
    """Return key info for all key-bearing providers in WIZARD_ORDER.

    Each entry has: value, source ("env"|"file"|None), masked, display_name,
    env_var, target_label.
    source="env" means the key came from an environment variable not in the keys
    file — it is not editable via the UI.
    """
    file_data = _read_file()
    result: dict[str, dict] = {}
    for provider in WIZARD_ORDER:
        spec = PROVIDER_SPECS.get(provider)
        if not spec or not spec.env_vars:
            continue
        env_var = spec.env_vars[0]
        file_value = file_data.get(env_var, "")
        env_value = os.environ.get(env_var, "")

        if file_value:
            source: str | None = "file"
            value = file_value
        elif env_value:
            source = "env"
            value = env_value
        else:
            source = None
            value = ""

        result[provider] = {
            "value": value,
            "source": source,
            "masked": mask(value),
            "display_name": spec.display_name,
            "env_var": env_var,
            "target_label": _target_label(provider),
        }
    return result


def run_setup_wizard() -> None:
    """Walk through all providers interactively. Saves each key immediately;
    Ctrl+C stops early but keeps whatever was already saved."""
    print("")
    print("  StealthOps API Key Setup")
    print("  " + "─" * 38)
    print("  Press Enter to keep an existing value.")
    print("  Type 'done' to finish early, Ctrl+C to stop and keep saved keys.")
    print("")

    all_keys = get_all()
    changes = 0

    for provider in WIZARD_ORDER:
        # Config entries that appear before this provider's key row
        for cfg in _CONFIG_BEFORE.get(provider, []):
            cfg_info = get_config(cfg["name"])
            cfg_source = cfg_info.get("source")
            cfg_current = cfg_info.get("value", "")
            cfg_display = cfg["display_name"]
            if cfg_source == "env":
                print(f"  {cfg_display:<22} {cfg_current!r}  [env — skipping]")
                continue
            suffix = f" [{cfg_current!r}]" if cfg_current else " [not set — blank uses default]"
            prompt = f"  {cfg_display}{suffix}: "
            try:
                new_val = input(prompt).strip()
            except (EOFError, KeyboardInterrupt):
                print("")
                return
            if new_val.lower() == "done":
                return
            if new_val == "":
                continue
            set_config(cfg["name"], new_val)
            changes += 1
            print("  [saved]")

        info = all_keys.get(provider)
        if not info:
            continue

        source = info["source"]
        current = info["value"]
        display = info["display_name"]
        label = info["target_label"]

        if source == "env":
            print(f"  {display:<22} {mask(current)}  [env — skipping]")
            continue

        suffix = f" [{mask(current)}]" if current else " [not set]"
        prompt = f"  {display} ({label}){suffix}: "

        try:
            new_val = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print("")
            break

        if new_val.lower() == "done":
            break
        if new_val == "":
            continue

        set_key(provider, new_val)
        changes += 1
        print("  [saved]")

    print("")
    if changes:
        print(f"  {changes} key(s) saved.")
    else:
        print("  No changes made.")
    print("")
