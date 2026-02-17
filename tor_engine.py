"""Tor process lifecycle and connectivity helpers for StealthOps."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Optional

import requests
from stem.process import launch_tor_with_config


class TorEngine:
    """Manage Tor detection, launch and connectivity verification."""

    def __init__(
        self,
        socks_host: str = "127.0.0.1",
        socks_port: int = 9050,
        control_port: int = 9051,
        data_dir: str = ".tor_data",
    ) -> None:
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.control_port = control_port
        self.data_dir = Path(data_dir)
        self.process: Optional[subprocess.Popen] = None
        self.last_error: Optional[str] = None

    @property
    def proxy_url(self) -> str:
        return f"socks5h://{self.socks_host}:{self.socks_port}"

    def _port_open(self, host: str, port: int, timeout: float = 0.8) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def is_proxy_running(self) -> bool:
        return self._port_open(self.socks_host, self.socks_port)

    def _find_tor_binary(self) -> Optional[str]:
        candidates = []

        # 1) PATH
        path_hit = shutil.which("tor")
        if path_hit:
            candidates.append(path_hit)

        # 2) Common local bundle locations
        cwd = Path.cwd()
        candidates.extend(
            [
                str(cwd / "tor" / "tor.exe"),
                str(cwd / "tor" / "tor"),
                str(cwd / "bin" / "tor.exe"),
                str(cwd / "bin" / "tor"),
            ]
        )

        # 3) TOR_PATH override
        env_tor = os.environ.get("TOR_PATH")
        if env_tor:
            candidates.insert(0, env_tor)

        for candidate in candidates:
            if candidate and Path(candidate).exists():
                return candidate
        return None

    def start_tor(self, timeout: int = 45) -> bool:
        if self.is_proxy_running():
            self.last_error = None
            return True

        tor_cmd = self._find_tor_binary()
        if not tor_cmd:
            self.last_error = "tor binary not found (set TOR_PATH or bundle tor executable)"
            return False

        self.data_dir.mkdir(exist_ok=True)

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
                timeout=timeout,
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

    def verify_circuit(self, timeout: int = 12) -> bool:
        if not self.is_proxy_running():
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
