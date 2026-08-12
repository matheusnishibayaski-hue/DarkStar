"""Cliente ativo em runtime (similar ao override do provedor LLM)."""

from __future__ import annotations

_active_client_id: str = "default"


def get_active_client_id() -> str:
    return _active_client_id or "default"


def set_active_client_id(client_id: str) -> str:
    from backend.clients.store import normalize_client_id

    global _active_client_id
    cid = normalize_client_id(client_id) or "default"
    _active_client_id = cid
    return _active_client_id
