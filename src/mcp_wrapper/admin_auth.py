from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from fastapi import Request


class AdminAuthRequired(Exception):
    """Raised by require_session when no valid admin session exists."""


def hash_password(password: str) -> str:
    """Return a PBKDF2-HMAC-SHA256 hash string: 'pbkdf2:sha256:600000:<b64salt>:<b64hash>'."""
    salt = secrets.token_bytes(32)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return f"pbkdf2:sha256:600000:{base64.b64encode(salt).decode()}:{base64.b64encode(dk).decode()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time password check. Returns False on any error."""
    try:
        _, algo, iters_str, b64_salt, b64_hash = stored_hash.split(":")
        salt = base64.b64decode(b64_salt)
        expected = base64.b64decode(b64_hash)
        actual = hashlib.pbkdf2_hmac(algo, password.encode(), salt, int(iters_str))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


@dataclass
class _SessionEntry:
    admin_id: str
    csrf_token: str
    expires_at: datetime


class AdminSessionStore:
    def __init__(self, timeout_hours: int = 8) -> None:
        self._sessions: dict[str, _SessionEntry] = {}
        self._timeout = timedelta(hours=timeout_hours)
        self._lock = threading.Lock()

    def create_session(self, admin_id: str) -> tuple[str, str]:
        """Create a session. Returns (session_token, csrf_token)."""
        session_token = secrets.token_hex(32)
        csrf_token = secrets.token_hex(32)
        expires = datetime.now(timezone.utc) + self._timeout
        with self._lock:
            self._sessions[session_token] = _SessionEntry(
                admin_id=admin_id, csrf_token=csrf_token, expires_at=expires
            )
        return session_token, csrf_token

    def validate_session(self, session_token: str) -> _SessionEntry | None:
        """Return entry if valid and not expired, else None."""
        now = datetime.now(timezone.utc)
        with self._lock:
            entry = self._sessions.get(session_token)
            if entry is None or entry.expires_at < now:
                self._sessions.pop(session_token, None)
                return None
            return entry

    def validate_csrf(self, session_token: str, csrf_token: str) -> bool:
        entry = self.validate_session(session_token)
        if entry is None:
            return False
        return hmac.compare_digest(entry.csrf_token, csrf_token)

    def delete_session(self, session_token: str) -> None:
        with self._lock:
            self._sessions.pop(session_token, None)


def make_require_session(store: AdminSessionStore):
    """Factory that returns a FastAPI dependency closed over the session store."""
    def require_session(request: Request) -> tuple[str, str]:
        """Returns (session_token, csrf_token) or raises AdminAuthRequired."""
        session_token = request.cookies.get("admin_session", "")
        entry = store.validate_session(session_token)
        if entry is None:
            raise AdminAuthRequired()
        return session_token, entry.csrf_token
    return require_session
