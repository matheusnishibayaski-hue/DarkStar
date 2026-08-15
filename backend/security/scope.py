"""Restrição de escopo: lista do cliente ativo, senão ALLOWED_TARGETS no .env."""

from __future__ import annotations

from backend.config import ALLOWED_TARGETS, HOST_WIFI_TOOLS
from backend.executor.recon_db import extract_targets, normalize_target


def _client_allowed_targets(client_id: str | None = None) -> frozenset[str]:
    try:
        from backend.clients.runtime import get_active_client_id
        from backend.clients.store import get_client

        cid = client_id or get_active_client_id()
        meta = get_client(cid) or {}
        raw = meta.get("allowed_targets") or []
        if not raw:
            return frozenset()
        return frozenset(str(t).strip() for t in raw if str(t).strip())
    except Exception:  # noqa: BLE001
        return frozenset()


def effective_allowed_targets(client_id: str | None = None) -> frozenset[str]:
    """Lista efetiva: ROE do cliente se preenchido, senão ALLOWED_TARGETS do .env."""
    client_list = _client_allowed_targets(client_id)
    if client_list:
        return client_list
    return ALLOWED_TARGETS


def scope_source(client_id: str | None = None) -> str:
    if _client_allowed_targets(client_id):
        return "cliente"
    if ALLOWED_TARGETS:
        return "ALLOWED_TARGETS"
    return ""


def scope_lock_enabled() -> bool:
    return bool(effective_allowed_targets())


def is_target_allowed(target: str) -> bool:
    allowed = effective_allowed_targets()
    if not allowed:
        return True
    normalized = normalize_target(target)
    for item in allowed:
        if normalized == item:
            return True
        if "." in item and not _looks_like_ip(item):
            if normalized.endswith("." + item):
                return True
    return False


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def validate_command_scope(args: list[str]) -> tuple[bool, str]:
    allowed = effective_allowed_targets()
    if not allowed or not args:
        return True, ""

    binary = args[0].split("/")[-1]
    if binary in HOST_WIFI_TOOLS:
        return True, ""

    targets = extract_targets(" ".join(args))
    if not targets:
        return True, ""

    for target in targets:
        if not is_target_allowed(target):
            return False, _scope_error_message(target)
    return True, ""


def validate_autonomous_target(target: str) -> tuple[bool, str]:
    allowed = effective_allowed_targets()
    if not allowed:
        return True, ""
    if not (target or "").strip():
        return False, "Alvo obrigatório."
    normalized = normalize_target(target)
    if not is_target_allowed(normalized):
        return False, _scope_error_message(normalized)
    return True, ""


def _scope_error_message(target: str) -> str:
    allowed = effective_allowed_targets()
    source = scope_source()
    listed = ", ".join(sorted(allowed)[:10])
    extra = "…" if len(allowed) > 10 else ""
    origin = "cliente ativo" if source == "cliente" else "ALLOWED_TARGETS"
    return f"Alvo '{target}' fora do escopo autorizado ({origin}). Permitidos: {listed}{extra}"
