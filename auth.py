"""User authentication and per-user API key storage for SERVER_MODE."""

from __future__ import annotations

import os
import secrets
import sqlite3
import threading
import time
from typing import Any

import bcrypt

_SESSION_TTL = 7 * 86400  # 7 days
_sessions: dict[str, tuple[str, float]] = {}  # token -> (username, created_at)
_sessions_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Encryption helpers
# ---------------------------------------------------------------------------

def _get_fernet():
    from cryptography.fernet import Fernet
    key = os.environ.get("FERNET_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "FERNET_KEY env var is not set. "
            "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    return Fernet(key.encode())


def _encrypt(value: str) -> str:
    return _get_fernet().encrypt(value.encode()).decode()


def _decrypt(token: str) -> str | None:
    from cryptography.fernet import InvalidToken
    try:
        return _get_fernet().decrypt(token.encode()).decode()
    except (InvalidToken, Exception):
        return None


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def _db_path() -> str:
    return os.environ.get("AUTH_DB_PATH", os.path.join("cache", "auth.db"))


def _open_db() -> sqlite3.Connection:
    path = _db_path()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at    INTEGER NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS user_keys (
            user_id       INTEGER NOT NULL,
            provider      TEXT NOT NULL,
            encrypted_key TEXT NOT NULL,
            updated_at    INTEGER NOT NULL,
            PRIMARY KEY (user_id, provider),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    conn.commit()
    return conn


def _user_id(conn: sqlite3.Connection, username: str) -> int | None:
    row = conn.execute(
        "SELECT id FROM users WHERE username = ?", (username.strip().lower(),)
    ).fetchone()
    return row[0] if row else None


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------

def create_user(username: str, password: str) -> bool:
    username = username.strip().lower()
    if not username or not password:
        return False
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    try:
        conn = _open_db()
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, hashed, int(time.time())),
            )
            conn.commit()
        finally:
            conn.close()
        return True
    except sqlite3.IntegrityError:
        return False


def delete_user(username: str) -> bool:
    username = username.strip().lower()
    conn = _open_db()
    try:
        uid = _user_id(conn, username)
        if uid is None:
            return False
        conn.execute("DELETE FROM user_keys WHERE user_id = ?", (uid,))
        conn.execute("DELETE FROM users WHERE id = ?", (uid,))
        conn.commit()
        # Invalidate all sessions for this user
        with _sessions_lock:
            to_remove = [t for t, (u, _) in _sessions.items() if u == username]
            for t in to_remove:
                del _sessions[t]
        return True
    finally:
        conn.close()


def list_users() -> list[str]:
    conn = _open_db()
    try:
        return [r[0] for r in conn.execute(
            "SELECT username FROM users ORDER BY username"
        ).fetchall()]
    finally:
        conn.close()


def verify_user(username: str, password: str) -> bool:
    username = username.strip().lower()
    conn = _open_db()
    try:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        # Constant-time dummy check to resist timing attacks
        bcrypt.checkpw(b"dummy", bcrypt.hashpw(b"dummy", bcrypt.gensalt()))
        return False
    return bcrypt.checkpw(password.encode(), row[0].encode())


def change_password(username: str, old_password: str, new_password: str) -> bool:
    if not verify_user(username, old_password):
        return False
    username = username.strip().lower()
    new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    conn = _open_db()
    try:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?", (new_hash, username)
        )
        conn.commit()
    finally:
        conn.close()
    return True


def admin_reset_password(username: str, new_password: str) -> bool:
    """Reset a user's password without requiring the old one (admin CLI use)."""
    username = username.strip().lower()
    conn = _open_db()
    try:
        if _user_id(conn, username) is None:
            return False
        new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?", (new_hash, username)
        )
        conn.commit()
        return True
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# API key management
# ---------------------------------------------------------------------------

def set_key(username: str, provider: str, key: str) -> bool:
    encrypted = _encrypt(key)
    conn = _open_db()
    try:
        uid = _user_id(conn, username.strip().lower())
        if uid is None:
            return False
        conn.execute(
            "INSERT OR REPLACE INTO user_keys (user_id, provider, encrypted_key, updated_at) "
            "VALUES (?, ?, ?, ?)",
            (uid, provider, encrypted, int(time.time())),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def delete_key(username: str, provider: str) -> bool:
    conn = _open_db()
    try:
        uid = _user_id(conn, username.strip().lower())
        if uid is None:
            return False
        conn.execute(
            "DELETE FROM user_keys WHERE user_id = ? AND provider = ?", (uid, provider)
        )
        conn.commit()
        return True
    finally:
        conn.close()


def get_keys(username: str) -> dict[str, str]:
    conn = _open_db()
    try:
        uid = _user_id(conn, username.strip().lower())
        if uid is None:
            return {}
        rows = conn.execute(
            "SELECT provider, encrypted_key FROM user_keys WHERE user_id = ?", (uid,)
        ).fetchall()
    finally:
        conn.close()
    result: dict[str, str] = {}
    for provider, enc_key in rows:
        decrypted = _decrypt(enc_key)
        if decrypted:
            result[provider] = decrypted
    return result


def set_key_all_users(provider: str, key: str) -> int:
    """Push a key to every existing user. Returns count updated."""
    encrypted = _encrypt(key)
    conn = _open_db()
    try:
        user_ids = [r[0] for r in conn.execute("SELECT id FROM users").fetchall()]
        for uid in user_ids:
            conn.execute(
                "INSERT OR REPLACE INTO user_keys (user_id, provider, encrypted_key, updated_at) "
                "VALUES (?, ?, ?, ?)",
                (uid, provider, encrypted, int(time.time())),
            )
        conn.commit()
        return len(user_ids)
    finally:
        conn.close()


def copy_keys(from_user: str, to_user: str) -> int:
    """Copy all keys from one user to another. Returns number copied."""
    keys = get_keys(from_user)
    count = 0
    for provider, key in keys.items():
        if set_key(to_user, provider, key):
            count += 1
    return count


# ---------------------------------------------------------------------------
# Session management (in-memory, resets on restart)
# ---------------------------------------------------------------------------

def create_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    now = time.time()
    with _sessions_lock:
        expired = [t for t, (_, ts) in _sessions.items() if now - ts > _SESSION_TTL]
        for t in expired:
            del _sessions[t]
        _sessions[token] = (username.strip().lower(), now)
    return token


def get_session_user(token: str) -> str | None:
    with _sessions_lock:
        entry = _sessions.get(token)
        if not entry:
            return None
        username, created = entry
        if time.time() - created > _SESSION_TTL:
            del _sessions[token]
            return None
        return username


def delete_session(token: str) -> None:
    with _sessions_lock:
        _sessions.pop(token, None)
