"""Tor process lifecycle and connectivity helpers for StealthOps."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Optional

import requests
from stem.process import launch_tor_with_config

from tor_updater import TorUpdater


class TorEngine:
    """Manage Tor detection, launch and connectivity verification."""

    def __init__(
        self,
        socks_host: str = "127.0.0.1",
        socks_port: int = 9050,
        control_port: int = 9051,
        data_dir: str | None = None,
        tor_update_mode: str = "auto",
        tor_update_manifest: str | None = None,
        prefer_system_tor: bool = False,
        update_ttl_hours: int = 24,
        status_callback: Callable[[str], None] | None = None,
    ) -> None:
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.control_port = control_port
        self.data_dir = Path(data_dir) if data_dir else self._default_data_dir()
        self.process: Optional[subprocess.Popen] = None
        self.last_error: Optional[str] = None
        self.last_update_message: Optional[str] = None
        self.status_callback = status_callback

        self.tor_update_mode = tor_update_mode
        self.prefer_system_tor = prefer_system_tor
        self.updater = TorUpdater(
            manifest_url=tor_update_manifest,
            ttl_hours=update_ttl_hours,
            status_callback=self._on_status,
        )

    def _on_status(self, message: str) -> None:
        self.last_update_message = message
        if not self.status_callback:
            return
        try:
            self.status_callback(message)
        except Exception:
            pass

    @property
    def proxy_url(self) -> str:
        return f"socks5h://{self.socks_host}:{self.socks_port}"

    @staticmethod
    def _default_data_dir() -> Path:
        if os.name == "nt":
            base = os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))
            return Path(base) / "StealthOps" / "tor_data"
        xdg = os.environ.get("XDG_DATA_HOME")
        base = Path(xdg) if xdg else Path.home() / ".local" / "share"
        return base / "stealthops" / "tor_data"

    @staticmethod
    def _app_base_dir() -> Path:
        if getattr(sys, "frozen", False):
            return Path(sys.executable).resolve().parent
        return Path.cwd()

    def _port_open(self, host: str, port: int, timeout: float = 0.8) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def _discover_active_proxy(self) -> bool:
        preferred_ports = [self.socks_port, 9150, 9050]
        seen: set[int] = set()
        for port in preferred_ports:
            if port in seen:
                continue
            seen.add(port)
            if self._port_open(self.socks_host, port):
                self.socks_port = port
                # Typical Tor Browser / Tor daemon defaults.
                self.control_port = 9151 if port == 9150 else 9051
                self.last_update_message = f"using existing tor socks proxy on {self.socks_host}:{port}"
                return True
        return False

    def is_proxy_running(self) -> bool:
        return self._discover_active_proxy()

    def _system_tor_candidates(self) -> list[Path]:
        candidates: list[Path] = []

        path_hit = shutil.which("tor")
        if path_hit:
            candidates.append(Path(path_hit))

        if os.name == "nt":
            candidates.extend(
                [
                    Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
                    Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Tor" / "tor.exe",
                    Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Tor" / "tor.exe",
                ]
            )

        return [p for p in candidates if p.exists()]

    def _bundled_tor_path(self) -> Path | None:
        base = self._app_base_dir()
        candidates = [
            base / "tor" / "tor.exe",
            base / "tor" / "tor",
            base / "bin" / "tor.exe",
            base / "bin" / "tor",
        ]

        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            root = Path(meipass)
            candidates.extend(
                [
                    root / "tor" / "tor.exe",
                    root / "tor" / "tor",
                    root / "bin" / "tor.exe",
                    root / "bin" / "tor",
                ]
            )

        for candidate in candidates:
            if candidate.exists():
                return candidate
        return None

    def _select_tor_binary(self) -> Optional[str]:
        env_tor = os.environ.get("TOR_PATH")
        if env_tor and Path(env_tor).exists():
            self.last_update_message = "using TOR_PATH override"
            return env_tor

        system_candidates = self._system_tor_candidates()
        system_tor = str(system_candidates[0]) if system_candidates else None

        managed_tor = self.updater.managed_tor_exe
        if not managed_tor.exists():
            bundled = self._bundled_tor_path()
            if bundled:
                bootstrapped = self.updater.bootstrap_from_bundle(bundled.parent)
                if bootstrapped:
                    managed_tor = bootstrapped
                    self.last_update_message = "bootstrapped managed tor from bundled runtime"

        managed_exists = managed_tor.exists()

        selected: str | None
        if self.prefer_system_tor and system_tor:
            selected = system_tor
            self.last_update_message = "using system tor"
        elif managed_exists:
            selected = str(managed_tor)
        elif system_tor:
            selected = system_tor
            self.last_update_message = "using system tor (managed runtime unavailable)"
        else:
            selected = None

        if selected and Path(selected) == managed_tor:
            update_result = self.updater.maybe_update(mode=self.tor_update_mode)
            self.last_update_message = update_result.message
            if update_result.updated and self.updater.managed_tor_exe.exists():
                selected = str(self.updater.managed_tor_exe)

        return selected

    def start_tor(self, timeout: int = 120) -> bool:
        if self._discover_active_proxy():
            self.last_error = None
            return True

        tor_cmd = self._select_tor_binary()
        if not tor_cmd:
            self.last_error = "tor binary not found (set TOR_PATH, install tor, or bundle tor runtime)"
            return False

        self.data_dir.mkdir(parents=True, exist_ok=True)

        if os.name != "nt":
            return self._start_tor_posix(tor_cmd, timeout)

        try:
            self.process = launch_tor_with_config(
                config={
                    "SocksPort": str(self.socks_port),
                    "ControlPort": str(self.control_port),
                    "DataDirectory": str(self.data_dir.resolve()),
                    "CookieAuthentication": "1",
                },
                tor_cmd=tor_cmd,
                take_ownership=True,
            )
        except Exception as exc:  # pragma: no cover - depends on runtime tor env
            self.last_error = f"failed launching tor: {exc}"
            return False

        for _ in range(20):
            if self.is_proxy_running():
                self.last_error = None
                return True
            time.sleep(0.5)

        self.last_error = "tor launched but SOCKS port never became reachable"
        return False

    def _start_tor_posix(self, tor_cmd: str, timeout: int) -> bool:
        """Launch Tor on Linux/macOS without stem's bootstrap watcher.

        Uses a direct subprocess so we can set LD_LIBRARY_PATH (the Tor
        Expert Bundle ships libcrypto/libssl alongside the binary and needs
        $ORIGIN resolution to work; some WSL2 configurations break that),
        capture real stderr on failure, and poll the SOCKS port ourselves.
        """
        tor_dir = Path(tor_cmd).parent
        env = os.environ.copy()
        existing_ldpath = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = (
            f"{tor_dir}:{existing_ldpath}" if existing_ldpath else str(tor_dir)
        )

        try:
            self.process = subprocess.Popen(
                [
                    tor_cmd,
                    "--SocksPort", str(self.socks_port),
                    "--ControlPort", str(self.control_port),
                    "--DataDirectory", str(self.data_dir.resolve()),
                    "--CookieAuthentication", "1",
                    "--quiet",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                env=env,
            )
        except Exception as exc:
            self.last_error = f"failed launching tor: {exc}"
            return False

        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._port_open(self.socks_host, self.socks_port):
                self.last_error = None
                return True
            if self.process.poll() is not None:
                try:
                    raw = self.process.stderr.read().decode("utf-8", errors="replace").strip()
                    detail = raw[-300:] if raw else "no output captured"
                except Exception:
                    detail = "could not read stderr"
                self.last_error = f"tor exited early: {detail}"
                return False
            time.sleep(0.5)

        try:
            self.process.kill()
        except Exception:
            pass
        self.last_error = "tor did not open SOCKS port within timeout"
        return False

    def verify_circuit(self, timeout: int = 12) -> bool:
        if not self._discover_active_proxy():
            self.last_error = "tor proxy unavailable"
            return False

        proxies = {"http": self.proxy_url, "https": self.proxy_url}
        try:
            resp = requests.get(
                "https://check.torproject.org/api/ip",
                proxies=proxies,
                timeout=timeout,
            )
            resp.raise_for_status()
            payload = resp.json()
            is_tor = bool(payload.get("IsTor"))
            if not is_tor:
                self.last_error = "proxy reachable but did not verify as tor"
            else:
                self.last_error = None
            return is_tor
        except Exception as exc:  # pragma: no cover - network dependent
            self.last_error = f"tor circuit verification failed: {exc}"
            return False

    def ensure_tor(self) -> bool:
        if self.is_proxy_running() and self.verify_circuit():
            return True

        started = self.start_tor()
        if not started:
            return False

        return self.verify_circuit()

    def manage_tor_runtime(self, force_update: bool = False) -> str:
        messages: list[str] = []

        managed_tor = self.updater.managed_tor_exe
        no_bundle_available = False
        if not managed_tor.exists():
            bundled = self._bundled_tor_path()
            if bundled:
                installed = self.updater.bootstrap_from_bundle(bundled.parent)
                if installed:
                    messages.append("managed tor bootstrapped from bundled runtime")
            else:
                no_bundle_available = True

        mode = "force" if force_update else self.tor_update_mode
        update_result = self.updater.maybe_update(mode=mode)
        if update_result.message:
            messages.append(update_result.message)

        managed_after_update = self.updater.managed_tor_exe.exists()
        if no_bundle_available and not managed_after_update:
            messages.append("no bundled tor runtime found")
            messages.append("provide bundled tor files, set TOR_PATH, or allow official source download")
            messages.append("updater can also attempt official torproject.org source when no manifest is provided")

        tor_ok = self.ensure_tor()
        messages.append("tor verified" if tor_ok else f"tor unavailable: {self.last_error or 'unknown error'}")

        self.last_update_message = "; ".join(messages)
        return self.last_update_message

    def preview_update_source(self) -> str:
        try:
            candidate = self.updater.preview_update_source()
            return f"Ready to download Tor {candidate['version']} from: {candidate['download_url']}"
        except Exception as exc:
            return f"Unable to resolve update source: {exc}"

    def stop_tor(self) -> None:
        if self.process is None:
            return
        try:
            self.process.terminate()
            self.process.wait(timeout=8)
        except Exception:
            try:
                self.process.kill()
            except Exception:
                pass
        finally:
            self.process = None
