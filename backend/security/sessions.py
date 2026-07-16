"""Sessões HttpOnly — troca CHAT_API_TOKEN por cookie de sessão (persistidas em disco)."""

from __future__ import annotations

import json
import secrets
import threading
import time

from backend.config import BASE_DIR

SESSION_COOKIE_NAME = "kali_session"
SESSIONS_FILE = BASE_DIR / "backend" / "data" / "sessions.json"


class SessionStore:
    def __init__(self, ttl_seconds: int) -> None:
        self.ttl_seconds = max(60, ttl_seconds)
        self._sessions: dict[str, float] = {}
        self._lock = threading.Lock()
        SESSIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
        self._load()

    def _load(self) -> None:
        if not SESSIONS_FILE.is_file():
            return
        try:
            raw = json.loads(SESSIONS_FILE.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self._sessions = {str(k): float(v) for k, v in raw.items()}
        except (json.JSONDecodeError, OSError, ValueError):
            self._sessions = {}
        self.purge_expired()

    def _save(self) -> None:
        try:
            SESSIONS_FILE.write_text(
                json.dumps(self._sessions, indent=0),
                encoding="utf-8",
            )
        except OSError:
            pass

    def create(self) -> str:
        session_id = secrets.token_urlsafe(32)
        expires = time.time() + self.ttl_seconds
        with self._lock:
            self._sessions[session_id] = expires
            self._save()
        return session_id

    def validate(self, session_id: str | None) -> bool:
        if not session_id:
            return False
        now = time.time()
        with self._lock:
            expires = self._sessions.get(session_id)
            if not expires:
                return False
            if expires <= now:
                del self._sessions[session_id]
                self._save()
                return False
            return True

    def revoke(self, session_id: str | None) -> None:
        if not session_id:
            return
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                self._save()

    def purge_expired(self) -> None:
        now = time.time()
        with self._lock:
            expired = [sid for sid, exp in self._sessions.items() if exp <= now]
            if not expired:
                return
            for sid in expired:
                del self._sessions[sid]
            self._save()


_store: SessionStore | None = None


def get_session_store(ttl_seconds: int) -> SessionStore:
    global _store
    if _store is None:
        _store = SessionStore(ttl_seconds)
    return _store
