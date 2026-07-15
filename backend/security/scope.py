"""Restrição de escopo via ALLOWED_TARGETS no .env."""

from __future__ import annotations

from backend.config import ALLOWED_TARGETS, HOST_WIFI_TOOLS
from backend.executor.recon_db import extract_targets, normalize_target


def scope_lock_enabled() -> bool:
    return bool(ALLOWED_TARGETS)


def is_target_allowed(target: str) -> bool:
    if not ALLOWED_TARGETS:
        return True
    normalized = normalize_target(target)
    for allowed in ALLOWED_TARGETS:
        if normalized == allowed:
            return True
        if "." in allowed and not _looks_like_ip(allowed):
            if normalized.endswith("." + allowed):
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
    if not ALLOWED_TARGETS or not args:
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
    if not ALLOWED_TARGETS:
        return True, ""
    if not (target or "").strip():
        return False, "Alvo obrigatório."
    normalized = normalize_target(target)
    if not is_target_allowed(normalized):
        return False, _scope_error_message(normalized)
    return True, ""


def _scope_error_message(target: str) -> str:
    allowed = ", ".join(sorted(ALLOWED_TARGETS)[:10])
    extra = "…" if len(ALLOWED_TARGETS) > 10 else ""
    return (
        f"Alvo '{target}' fora do escopo autorizado (ALLOWED_TARGETS). "
        f"Permitidos: {allowed}{extra}"
    )
