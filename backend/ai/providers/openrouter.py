"""Adapter OpenRouter (nuvem) — comportamento legado do DarkStar."""

from __future__ import annotations

from typing import Any

from backend.ai.providers.openai_compatible import OpenAICompatibleProvider
from backend.config import FALLBACK_MODEL, OPENROUTER_API_KEY, PRIMARY_MODEL

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

OPENROUTER_HEADERS = {
    "HTTP-Referer": "https://github.com/matheusnishibayaski-hue/Chat-IA-Kali",
    "X-Title": "DarkStar",
}


class OpenRouterAdapter(OpenAICompatibleProvider):
    def __init__(
        self,
        *,
        api_key: str | None = None,
        default_model: str | None = None,
        default_fallback: str | None = None,
    ) -> None:
        super().__init__(
            name="openrouter",
            base_url=OPENROUTER_BASE_URL,
            api_key=(api_key if api_key is not None else OPENROUTER_API_KEY) or "",
            default_model=default_model or PRIMARY_MODEL,
            default_fallback=default_fallback or FALLBACK_MODEL,
            extra_headers=dict(OPENROUTER_HEADERS),
        )

    def is_configured(self) -> bool:
        return bool(self.api_key.strip())

    def configuration_error(self) -> str:
        return (
            "Configure OPENROUTER_API_KEY no arquivo .env.\n\n"
            "Obtenha uma chave em: https://openrouter.ai/keys\n\n"
            "Ou defina AI_PROVIDER=ollama para uso 100% local."
        )

    def format_error(self, error: str) -> str:
        lowered = error.lower()
        if "401" in error or ("invalid" in lowered and "key" in lowered):
            return (
                "Chave OpenRouter inválida. Configure OPENROUTER_API_KEY no arquivo .env.\n\n"
                "Obtenha uma chave em: https://openrouter.ai/keys"
            )
        if self.is_retryable_error(error):
            return (
                "Cota ou limite de requisições atingido no OpenRouter.\n\n"
                "O que fazer:\n"
                "• Aguarde alguns minutos se enviou muitas mensagens seguidas\n"
                "• Verifique saldo/cota em https://openrouter.ai/\n"
                "• O fallback tentará o modelo secundário automaticamente\n"
                "• Cada comando no chat gera 2–6 chamadas à API (ferramentas + resposta)"
            )
        return f"Erro ao chamar OpenRouter: {error}"

    def resolve_models(
        self, model: str | None = None, fallback: str | None = None
    ) -> tuple[str, str]:
        from backend.models_catalog import resolve_model as catalog_resolve

        return catalog_resolve(model, fallback)

    def models_catalog(self) -> dict[str, Any]:
        from backend.models_catalog import get_models_catalog

        catalog = get_models_catalog()
        catalog["provider"] = self.name
        return catalog

    def health(self) -> dict[str, Any]:
        ok = self.is_configured()
        return {
            "provider": self.name,
            "configured": ok,
            "ok": ok,
            "detail": "" if ok else "OPENROUTER_API_KEY ausente",
            "base_url": self.base_url,
        }
