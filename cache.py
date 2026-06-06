"""SQLite-backed result cache for CLOUD_MODE deployments."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time

_TTL = 86400      # 24 hours — live entries
_SWEEP_AGE = 172800  # 48 hours — sweep threshold


def _db_path() -> str:
    return os.environ.get("CACHE_PATH", os.path.join("cache", "stealthops.db"))


def _open() -> sqlite3.Connection:
    path = _db_path()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS result_cache (
            key        TEXT PRIMARY KEY,
            target     TEXT NOT NULL,
            scope      TEXT NOT NULL,
            payload    TEXT NOT NULL,
            fetched_at INTEGER NOT NULL
        )
    """)
    conn.commit()
    return conn


def _cache_key(target: str, scope: str) -> str:
    return hashlib.sha256(f"{target.lower()}|{scope}".encode()).hexdigest()


def get(target: str, scope: str) -> dict | None:
    """Return cached payload for (target, scope), or None on miss/expiry."""
    key = _cache_key(target, scope)
    try:
        conn = _open()
        try:
            row = conn.execute(
                "SELECT payload, fetched_at FROM result_cache WHERE key = ?", (key,)
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        payload_json, fetched_at = row
        if time.time() - fetched_at > _TTL:
            return None
        return json.loads(payload_json)
    except Exception:
        return None


def put(target: str, scope: str, payload: dict) -> None:
    """Store payload for (target, scope). Silently swallows errors."""
    key = _cache_key(target, scope)
    try:
        conn = _open()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO result_cache "
                "(key, target, scope, payload, fetched_at) VALUES (?, ?, ?, ?, ?)",
                (key, target.lower(), scope, json.dumps(payload), int(time.time())),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass


def sweep() -> None:
    """Delete entries older than 48 hours. Called once at app startup."""
    cutoff = int(time.time()) - _SWEEP_AGE
    try:
        conn = _open()
        try:
            conn.execute("DELETE FROM result_cache WHERE fetched_at < ?", (cutoff,))
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass
