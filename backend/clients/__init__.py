"""Workspaces multi-cliente locais (MSSP)."""

from backend.clients.runtime import get_active_client_id, set_active_client_id
from backend.clients.store import (
    create_client,
    delete_client,
    get_client,
    list_clients,
    normalize_client_id,
    update_client,
)

__all__ = [
    "create_client",
    "delete_client",
    "get_active_client_id",
    "get_client",
    "list_clients",
    "normalize_client_id",
    "set_active_client_id",
    "update_client",
]
