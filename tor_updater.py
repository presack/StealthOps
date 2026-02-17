"""Tor bundle management and update workflow for StealthOps."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import requests


@dataclass
class TorUpdateResult:
    checked: bool
    updated: bool
    message: str
    current_version: Optional[str] = None
    latest_version: Optional[str] = None
    error: Optional[str] = None


class TorUpdater:
    """Manages a writable, app-owned Tor runtime and optional update checks."""

    def __init__(
        self,
        app_name: str = "StealthOps",
        manifest_url: str | None = None,
        ttl_hours: int = 24,
    ) -> None:
        self.manifest_url = manifest_url or os.environ.get("STEALTHOPS_TOR_MANIFEST")
        self.ttl_hours = ttl_hours
        self.managed_root = self._default_managed_root(app_name)
        self.current_dir = self.managed_root / "current"
        self.state_file = self.managed_root / "update_state.json"

    @staticmethod
    def _default_managed_root(app_name: str) -> Path:
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data) / app_name / "tor"
        return Path.home() / f".{app_name.lower()}" / "tor"

    @property
    def managed_tor_exe(self) -> Path:
        discovered = self._find_tor_executable(self.current_dir)
        if discovered:
            return discovered
        return self.current_dir / ("tor.exe" if os.name == "nt" else "tor")

    def _load_state(self) -> dict[str, Any]:
        if not self.state_file.exists():
            return {}
        try:
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_state(self, state: dict[str, Any]) -> None:
        self.managed_root.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")

    def _check_due(self, mode: str) -> bool:
        if mode == "force":
            return True
        if mode == "off":
            return False

        state = self._load_state()
        last_checked = float(state.get("last_checked", 0))
        return (time.time() - last_checked) >= (self.ttl_hours * 3600)

    def _record_checked(self, latest_version: str | None = None) -> None:
        state = self._load_state()
        state["last_checked"] = time.time()
        if latest_version:
            state["last_seen_version"] = latest_version
        self._save_state(state)

    def get_tor_version(self, tor_path: Path) -> str | None:
        if not tor_path.exists():
            return None
        try:
            completed = subprocess.run(
                [str(tor_path), "--version"],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            text = (completed.stdout or "") + " " + (completed.stderr or "")
            match = re.search(r"Tor\s+version\s+([0-9][0-9A-Za-z.\-]+)", text)
            return match.group(1) if match else None
        except Exception:
            return None

    def bootstrap_from_bundle(self, bundle_path: Path | None) -> Path | None:
        """Copies bundled Tor into writable managed location on first run."""
        if self.managed_tor_exe.exists():
            return self.managed_tor_exe

        if not bundle_path or not bundle_path.exists():
            return None

        self.managed_root.mkdir(parents=True, exist_ok=True)
        if self.current_dir.exists():
            shutil.rmtree(self.current_dir, ignore_errors=True)

        source_dir = bundle_path if bundle_path.is_dir() else bundle_path.parent
        shutil.copytree(source_dir, self.current_dir)

        return self._find_tor_executable(self.current_dir)

    @staticmethod
    def _find_tor_executable(root: Path) -> Path | None:
        candidates = [p for p in root.rglob("tor.exe")]
        if not candidates:
            candidates = [p for p in root.rglob("tor") if p.is_file()]
        return candidates[0] if candidates else None

    @staticmethod
    def _version_key(version: str) -> tuple[int, ...]:
        return tuple(int(part) for part in version.split("."))

    def _fetch_official_tor_project_manifest(self) -> dict[str, Any]:
        page_url = "https://www.torproject.org/download/tor/"
        response = requests.get(page_url, timeout=20)
        response.raise_for_status()
        html_text = response.text

        matches = re.findall(
            r'href=["\']([^"\']*tor-expert-bundle-windows-x86_64-([0-9]+(?:\.[0-9]+)+)\.tar\.gz)["\']',
            html_text,
        )
        if not matches:
            raise RuntimeError("unable to discover tor expert bundle from torproject.org download page")

        candidates: list[tuple[str, str]] = []
        for href, version in matches:
            absolute_url = urljoin(page_url, href)
            candidates.append((version, absolute_url))

        latest_version, windows_url = sorted(candidates, key=lambda item: self._version_key(item[0]))[-1]
        filename = Path(urlparse(windows_url).path).name
        sums_url = urljoin(windows_url, "sha256sums-signed-build.txt")

        sums_resp = requests.get(sums_url, timeout=20)
        sums_resp.raise_for_status()
        expected_sha = None
        for line in sums_resp.text.splitlines():
            match = re.match(r"^([A-Fa-f0-9]{64})\s+\*?(.+)$", line.strip())
            if match and match.group(2).strip() == filename:
                expected_sha = match.group(1).lower()
                break

        if not expected_sha:
            raise RuntimeError(f"could not locate sha256 for {filename} in {sums_url}")

        return {"version": latest_version, "windows_url": windows_url, "sha256": expected_sha}

    def _fetch_manifest(self) -> dict[str, Any]:
        manifest_source = self.manifest_url
        source_kind = "explicit" if manifest_source else "auto"
        if not manifest_source:
            candidates = [Path.cwd() / "tor-manifest.json"]
            if getattr(sys, "frozen", False):
                candidates.append(Path(sys.executable).resolve().parent / "tor-manifest.json")

            for candidate in candidates:
                if candidate.exists():
                    manifest_source = str(candidate)
                    source_kind = "local_file"
                    break

        if not manifest_source:
            return self._fetch_official_tor_project_manifest()

        if manifest_source.startswith(("http://", "https://")):
            response = requests.get(manifest_source, timeout=20)
            response.raise_for_status()
            manifest = response.json()
        else:
            manifest = json.loads(Path(manifest_source).read_text(encoding="utf-8"))

        required = ["version", "windows_url", "sha256"]
        missing = [key for key in required if key not in manifest]
        if missing:
            raise RuntimeError(f"manifest missing keys: {', '.join(missing)}")
        if "example.com" in str(manifest.get("windows_url", "")):
            if source_kind == "local_file":
                return self._fetch_official_tor_project_manifest()
            raise RuntimeError("manifest appears to be a template; replace windows_url/sha256 with real values")

        return manifest

    def preview_update_source(self) -> dict[str, Any]:
        """Return the current resolved update candidate without downloading."""
        manifest = self._fetch_manifest()
        return {"version": str(manifest["version"]), "windows_url": str(manifest["windows_url"])}

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest().lower()

    def _download(self, url: str, destination: Path) -> None:
        with requests.get(url, timeout=60, stream=True) as response:
            response.raise_for_status()
            with destination.open("wb") as out:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        out.write(chunk)

    def _extract_bundle(self, archive_path: Path, target_dir: Path) -> None:
        if target_dir.exists():
            shutil.rmtree(target_dir, ignore_errors=True)
        target_dir.mkdir(parents=True, exist_ok=True)

        suffixes = "".join(archive_path.suffixes).lower()
        if archive_path.suffix.lower() == ".zip":
            with zipfile.ZipFile(archive_path, "r") as zf:
                zf.extractall(target_dir)
            return

        if ".tar" in suffixes:
            with tarfile.open(archive_path, "r:*") as tf:
                tf.extractall(target_dir)
            return

        raise RuntimeError(f"unsupported tor bundle format: {archive_path.name}")

    def _activate_staged(self, staged_dir: Path) -> None:
        previous_dir = self.managed_root / "previous"

        if previous_dir.exists():
            shutil.rmtree(previous_dir, ignore_errors=True)

        if self.current_dir.exists():
            self.current_dir.rename(previous_dir)

        staged_dir.rename(self.current_dir)

    def maybe_update(self, mode: str = "auto") -> TorUpdateResult:
        if mode not in {"auto", "force", "off"}:
            return TorUpdateResult(False, False, f"invalid update mode: {mode}", error="invalid_mode")

        if mode == "off":
            return TorUpdateResult(False, False, "update checks disabled")

        if not self._check_due(mode):
            current = self.get_tor_version(self.managed_tor_exe)
            return TorUpdateResult(False, False, "update check skipped (ttl)", current_version=current)

        try:
            manifest = self._fetch_manifest()
        except Exception as exc:
            self._record_checked()
            return TorUpdateResult(True, False, f"update check failed: {exc}", error=str(exc))

        latest = str(manifest["version"])
        current = self.get_tor_version(self.managed_tor_exe)
        self._record_checked(latest)

        if current and current == latest:
            return TorUpdateResult(True, False, "tor already up to date", current_version=current, latest_version=latest)

        try:
            self.managed_root.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix="stealthops-tor-") as tmp_dir:
                temp_dir = Path(tmp_dir)
                archive_name = Path(str(manifest["windows_url"])).name or "tor_bundle.zip"
                archive_path = temp_dir / archive_name

                self._download(str(manifest["windows_url"]), archive_path)

                expected = str(manifest["sha256"]).lower().strip()
                actual = self._sha256_file(archive_path)
                if expected != actual:
                    raise RuntimeError("sha256 verification failed")

                staged = self.managed_root / "staged"
                self._extract_bundle(archive_path, staged)

                staged_exe = self._find_tor_executable(staged)
                if not staged_exe:
                    raise RuntimeError("updated bundle does not contain tor executable")

                self._activate_staged(staged)

            updated_version = self.get_tor_version(self.managed_tor_exe)
            return TorUpdateResult(
                checked=True,
                updated=True,
                message="tor updated successfully",
                current_version=updated_version,
                latest_version=latest,
            )
        except Exception as exc:
            return TorUpdateResult(
                checked=True,
                updated=False,
                message=f"tor update failed: {exc}",
                current_version=current,
                latest_version=latest,
                error=str(exc),
            )
