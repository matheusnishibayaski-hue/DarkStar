"""Privilégios DarkStar — perfil B (restrito) vs full (master key)."""

from __future__ import annotations

import secrets
import time
from contextvars import ContextVar
from threading import Lock
from typing import Any

from backend.ai.phases import PROFILE_BLOCKED, normalize_risk_profile
from backend.config import MASTER_KEY, SESSION_TTL_HOURS

PRIVILEGE_COOKIE = "darkstar_privilege"
PRIVILEGE_HEADER = "X-DarkStar-Privilege"

# Contexto por request
_privilege_elevated: ContextVar[bool] = ContextVar("privilege_elevated", default=False)

_lock = Lock()
_tokens: dict[str, float] = {}  # token -> expires_at


def is_elevated() -> bool:
    return bool(_privilege_elevated.get())


def set_elevated(value: bool) -> None:
    _privilege_elevated.set(bool(value))


def effective_risk_profile(requested: str | None = None) -> str:
    """Sem master key, teto é safe-active (perfil B). Com key, respeita o pedido/full."""
    profile = normalize_risk_profile(requested)
    if is_elevated():
        return profile
    if profile == "full":
        return "safe-active"
    return profile


def privilege_blocks_tool(binary: str) -> tuple[bool, str]:
    """Retorna (blocked, reason) para o perfil atual."""
    if is_elevated():
        return False, ""
    blocked = PROFILE_BLOCKED.get("safe-active", frozenset())
    name = (binary or "").split("/")[-1].lower()
    if name in blocked:
        return (
            True,
            f"Ferramenta '{name}' bloqueada no perfil B (restrito). "
            "Desbloqueie com a master key DarkStar para permissão total.",
        )
    return False, ""


def master_key_configured() -> bool:
    return bool((MASTER_KEY or "").strip())


def verify_master_key(candidate: str) -> bool:
    expected = (MASTER_KEY or "").strip()
    if not expected or not candidate:
        return False
    return secrets.compare_digest(candidate.strip(), expected)


def create_privilege_token() -> str:
    token = secrets.token_urlsafe(32)
    ttl = max(3600, int(SESSION_TTL_HOURS) * 3600)
    with _lock:
        _tokens[token] = time.time() + ttl
        _purge_locked()
    return token


def validate_privilege_token(token: str | None) -> bool:
    if not token:
        return False
    now = time.time()
    with _lock:
        _purge_locked(now)
        exp = _tokens.get(token)
        if exp is None:
            return False
        if exp < now:
            _tokens.pop(token, None)
            return False
        return True


def revoke_privilege_token(token: str | None) -> None:
    if not token:
        return
    with _lock:
        _tokens.pop(token, None)


def _purge_locked(now: float | None = None) -> None:
    now = now if now is not None else time.time()
    dead = [k for k, exp in _tokens.items() if exp < now]
    for k in dead:
        _tokens.pop(k, None)


def privilege_status() -> dict[str, Any]:
    elevated = is_elevated()
    return {
        "elevated": elevated,
        "profile": "full" if elevated else "B",
        "profile_label": "full (master key)" if elevated else "B (restrito)",
        "master_key_required": master_key_configured(),
    }
