"""Personal-mode API key storage in a user-writable keys.env file.

Keys are stored as ENV_VAR=value pairs. load_into_environ() is called at startup
to inject file keys into os.environ (existing env vars take precedence).

NOTE: WIZARD_ORDER and the order used in web_ui.py's _SETTINGS_PROVIDER_ORDER must stay in sync.
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
