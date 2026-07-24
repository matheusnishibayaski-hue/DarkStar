"""Override em runtime do provedor LLM (switch Offline na UI)."""

from __future__ import annotations

import threading

from backend.config import AI_PROVIDER

_lock = threading.Lock()
_override: str | None = None

_VALID = {"openrouter", "ollama"}


def normalize_provider_name(name: str | None) -> str:
    raw = (name or "").strip().lower()
    if raw in {"local", "offline", "airgap", "air-gapped"}:
        return "ollama"
    if raw in {"cloud", "or", "online"}:
        return "openrouter"
    if raw in _VALID:
        return raw
    return "openrouter"


def get_active_provider_name() -> str:
    with _lock:
        if _override:
            return _override
    return normalize_provider_name(AI_PROVIDER)


def set_active_provider(name: str) -> str:
    """Define o provedor ativo (sessão do processo). Retorna o nome normalizado."""
    global _override
    normalized = normalize_provider_name(name)
    with _lock:
        _override = normalized
    from backend.ai.providers.factory import reset_llm_provider_cache

    reset_llm_provider_cache()
    return normalized


def clear_provider_override() -> None:
    """Volta ao AI_PROVIDER do .env (útil em testes)."""
    global _override
    with _lock:
        _override = None
    from backend.ai.providers.factory import reset_llm_provider_cache

    reset_llm_provider_cache()


def provider_status() -> dict:
    from backend.ai.providers.factory import get_llm_provider

    active = get_active_provider_name()
    provider = get_llm_provider(active)
    health = provider.health()
    return {
        "provider": active,
        "offline": active == "ollama",
        "default_provider": normalize_provider_name(AI_PROVIDER),
        "override": _override is not None,
        "llm": health,
    }
