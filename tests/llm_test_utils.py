"""Helpers para mockar o LLM provider nos testes de cobertura."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from backend.ai.openrouter_common import is_retryable_error, openrouter_error_message
from backend.ai.providers.openrouter import OpenRouterAdapter


def make_openrouter_provider(client=None, *, api_key: str = "sk", models=("m1", "m2")):
    provider = OpenRouterAdapter(api_key=api_key)
    if client is not None:
        provider._client = client
    # resolve_models costuma ser fixado nos testes
    provider.resolve_models = MagicMock(return_value=models)  # type: ignore[method-assign]
    return provider


def patch_agent_provider(client=None, *, api_key: str = "sk", models=("m1", "m2")):
    provider = make_openrouter_provider(client, api_key=api_key, models=models)
    return patch("backend.ai.agent.get_llm_provider", return_value=provider), provider


def patch_autopilot_provider(client=None, *, api_key: str = "sk", models=("m1", "m2")):
    provider = make_openrouter_provider(client, api_key=api_key, models=models)
    return patch("backend.ai.autopilot.get_llm_provider", return_value=provider), provider


def provider_mock_simple(*, configured: bool = True, models=("m1", "m2")):
    p = MagicMock()
    p.name = "openrouter"
    p.is_configured.return_value = configured
    p.configuration_error.return_value = (
        "Configure OPENROUTER_API_KEY no arquivo .env.\n\n"
        "Obtenha uma chave em: https://openrouter.ai/keys"
    )
    p.resolve_models.return_value = models
    p.is_retryable_error.side_effect = is_retryable_error
    p.format_error.side_effect = openrouter_error_message
    return p
