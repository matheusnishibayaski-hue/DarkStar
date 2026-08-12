"""Papéis locais do operador (admin | analyst | viewer) — sem portal do cliente."""

from __future__ import annotations

from backend.config import OPERATOR_ROLE

ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}

# Métodos/paths que viewer não pode usar
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Leitura sempre liberada; writes exigem analyst+
# Algumas POSTs de leitura (activate client, baseline read-like) ainda exigem analyst
_VIEWER_ALLOWED_POST_PREFIXES = (
    "/api/auth/",
    "/api/clients/_active",
)


def current_role() -> str:
    role = (OPERATOR_ROLE or "admin").strip().lower()
    return role if role in ROLE_RANK else "admin"


def role_at_least(minimum: str) -> bool:
    return ROLE_RANK.get(current_role(), 0) >= ROLE_RANK.get(minimum, 99)


def can_write() -> bool:
    return role_at_least("analyst")


def can_admin() -> bool:
    return role_at_least("admin")


def method_allowed(method: str, path: str) -> bool:
    """Viewer: só GET/HEAD/OPTIONS (+ auth). Analyst/admin: tudo autenticado."""
    if role_at_least("analyst"):
        return True
    m = method.upper()
    if m in {"GET", "HEAD", "OPTIONS"}:
        return True
    if m == "POST" and any(path.startswith(p) for p in _VIEWER_ALLOWED_POST_PREFIXES):
        return True
    return False
