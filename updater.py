"""Self-update: background version check and binary replacement."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

from _version import __version__

_REPO = "presack/StealthOps"
_API_URL = f"https://api.github.com/repos/{_REPO}/releases/latest"
_CHECK_INTERVAL_CURRENT = 4 * 3600   # 4h when already up-to-date (catches new releases promptly)
_CHECK_INTERVAL_UPDATE  = 86400      # 24h when an update is already cached (user's been notified)


def _state_dir() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))
        return Path(base) / "StealthOps"
    return Path.home() / ".local" / "share" / "stealthops"


def _state_file() -> Path:
    return _state_dir() / "update_check.json"


def _read_state() -> dict:
    try:
        return json.loads(_state_file().read_text())
    except Exception:
        return {}


def _write_state(data: dict) -> None:
    try:
        _state_dir().mkdir(parents=True, exist_ok=True)
        _state_file().write_text(json.dumps(data))
    except Exception:
        pass


def _version_tuple(v: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in v.lstrip("v").split("."))
    except Exception:
        return (0,)


def _fetch_latest() -> dict | None:
    try:
        req = urllib.request.Request(
            _API_URL,
            headers={"User-Agent": f"StealthOps/{__version__}"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def check_for_update_background() -> None:
    """Fire a daemon thread to refresh cached update state if stale (>24h).

    Writes checked_at immediately so the 24h throttle holds even if the
    thread is killed mid-flight (e.g. short-lived CLI runs on Linux).
    Registers an atexit join so short-lived processes wait up to 4s for the
    thread to complete and persist the version info.
    """
    import atexit

    state = _read_state()
    latest_cached = state.get("latest_version", "")
    has_pending = latest_cached and _version_tuple(latest_cached) > _version_tuple(__version__)
    interval = _CHECK_INTERVAL_UPDATE if has_pending else _CHECK_INTERVAL_CURRENT
    if time.time() - state.get("checked_at", 0) < interval:
        return

    # Stamp checked_at now so we don't re-fire on every CLI invocation if the
    # thread gets killed before it can write the state itself.
    _write_state({**state, "checked_at": time.time()})

    def _worker() -> None:
        data = _fetch_latest()
        if not data:
            return
        tag = data.get("tag_name", "")
        _write_state({
            "checked_at": time.time(),
            "latest_version": tag.lstrip("v"),
            "latest_tag": tag,
            "current_version": __version__,
        })

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    # For short-lived CLI runs the process exits before the thread finishes.
    # Wait up to 4s so the state file gets written and the notice shows next run.
    atexit.register(lambda: t.join(timeout=4))


def get_update_notice(use_color: bool = True) -> str | None:
    """Return a formatted one-liner if a newer version is cached, else None."""
    state = _read_state()
    latest = state.get("latest_version")
    if not latest or _version_tuple(latest) <= _version_tuple(__version__):
        return None
    tag = state.get("latest_tag", f"v{latest}")
    hint = "type 'update'" if getattr(sys, "frozen", False) else f"github.com/{_REPO}/releases"
    from formatter import _c
    if use_color:
        return (
            f"  {_c(True, '>', '1;93')} Update Available ............... "
            f"[{_c(True, tag, '1;93')} — {_c(True, hint, '96')}]"
        )
    return f"  > Update Available ............... [{tag} — {hint}]"


def _asset_name() -> str:
    return "stealthops-windows-x64.exe" if sys.platform == "win32" else "stealthops-linux-x64"


def _current_exe() -> Path:
    return Path(sys.executable if getattr(sys, "frozen", False) else sys.argv[0]).resolve()


def cleanup_old_binary() -> None:
    """Remove .old backup left by a previous successful update."""
    try:
        old = Path(str(_current_exe()) + ".old")
        if old.exists():
            old.unlink()
    except Exception:
        pass


def do_update(use_color: bool = True) -> str | None:
    """Interactive update: fetch latest GitHub release and replace the running binary."""
    if not getattr(sys, "frozen", False):
        print("Source install — download the latest release from:")
        print(f"  https://github.com/{_REPO}/releases")
        print("")
        return

    print("[update] checking latest release...")
    data = _fetch_latest()
    if not data:
        print("[update] error: could not reach GitHub — check your connection")
        print("")
        return

    tag = data.get("tag_name", "")
    latest = tag.lstrip("v")
    print(f"[update] current: v{__version__}  latest: {tag}")

    if _version_tuple(latest) <= _version_tuple(__version__):
        print("[update] already up to date")
        print("")
        return

    asset_name = _asset_name()
    assets = {a["name"]: a for a in data.get("assets", [])}
    if asset_name not in assets:
        print(f"[update] error: asset '{asset_name}' not found in release {tag}")
        print("")
        return

    asset_url = assets[asset_name]["browser_download_url"]
    asset_size = assets[asset_name].get("size", 0)

    expected_sha256: str | None = None
    if "checksums.txt" in assets:
        try:
            req = urllib.request.Request(
                assets["checksums.txt"]["browser_download_url"],
                headers={"User-Agent": f"StealthOps/{__version__}"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                for line in resp.read().decode().splitlines():
                    parts = line.split()
                    if len(parts) == 2 and parts[1] == asset_name:
                        expected_sha256 = parts[0]
                        break
        except Exception:
            pass

    size_str = f"{asset_size / 1_048_576:.1f} MB" if asset_size else "unknown size"
    print(f"[update] downloading {tag} ({size_str})...")

    current = _current_exe()
    tmp_path: Path | None = None
    try:
        req = urllib.request.Request(
            asset_url,
            headers={"User-Agent": f"StealthOps/{__version__}"},
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            # Create temp file in the same directory so rename is within-volume
            fd, tmp_name = tempfile.mkstemp(suffix=".new", dir=current.parent)
            tmp_path = Path(tmp_name)
            try:
                with os.fdopen(fd, "wb") as f:
                    while chunk := resp.read(65536):
                        f.write(chunk)
            except Exception:
                tmp_path.unlink(missing_ok=True)
                raise
    except Exception as exc:
        print(f"[update] error downloading: {exc}")
        print("")
        return

    if expected_sha256:
        actual = hashlib.sha256(tmp_path.read_bytes()).hexdigest()
        if actual != expected_sha256:
            tmp_path.unlink(missing_ok=True)
            print("[update] error: SHA256 mismatch — download may be corrupted, try again")
            print("")
            return
        print("[update] SHA256 verified")

    old_path = Path(str(current) + ".old")
    try:
        tmp_path.chmod(0o755)
        if old_path.exists():
            old_path.unlink()
        current.rename(old_path)
        tmp_path.rename(current)
    except Exception as exc:
        # Attempt rollback if we left the binary missing
        if not current.exists() and old_path.exists():
            try:
                old_path.rename(current)
            except Exception:
                pass
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
        print(f"[update] error replacing binary: {exc}")
        print("")
        return

    _write_state({
        "checked_at": time.time(),
        "latest_version": latest,
        "latest_tag": tag,
        "current_version": latest,
    })

    print(f"[update] updated to {tag} — restart StealthOps to use the new version")
    print("")
    return tag
