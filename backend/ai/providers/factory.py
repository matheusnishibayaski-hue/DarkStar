"""Factory do provedor LLM ativo (`AI_PROVIDER` + override da UI)."""

from __future__ import annotations

from functools import lru_cache

from backend.ai.providers.base import BaseLLMProvider
from backend.ai.providers.ollama import OllamaAdapter
from backend.ai.providers.openrouter import OpenRouterAdapter
from backend.ai.providers.runtime import get_active_provider_name, normalize_provider_name


@lru_cache(maxsize=8)
def _provider_for(name: str) -> BaseLLMProvider:
    provider = normalize_provider_name(name)
    if provider == "ollama":
        return OllamaAdapter()
    return OpenRouterAdapter()


def get_llm_provider(name: str | None = None) -> BaseLLMProvider:
    resolved = normalize_provider_name(name) if name else get_active_provider_name()
    return _provider_for(resolved)


def reset_llm_provider_cache() -> None:
    """Usado em testes / ao trocar provedor na UI."""
    _provider_for.cache_clear()
