"""Adapter Ollama — ambiente local / air-gapped (API OpenAI-compatible)."""

from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any

from backend.ai.providers.openai_compatible import OpenAICompatibleProvider
from backend.config import (
    OLLAMA_API_KEY,
    OLLAMA_BASE_URL,
    OLLAMA_FALLBACK_MODEL,
    OLLAMA_MODEL,
)


class OllamaAdapter(OpenAICompatibleProvider):
    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        default_model: str | None = None,
        default_fallback: str | None = None,
    ) -> None:
        url = (base_url or OLLAMA_BASE_URL).rstrip("/")
        super().__init__(
            name="ollama",
            base_url=url,
            api_key=(api_key if api_key is not None else OLLAMA_API_KEY) or "ollama",
            default_model=default_model or OLLAMA_MODEL,
            default_fallback=default_fallback or OLLAMA_FALLBACK_MODEL or OLLAMA_MODEL,
            extra_headers=None,
        )

    def is_configured(self) -> bool:
        # Não exige API key; falhas de daemon aparecem no complete()/health().
        return True

    def configuration_error(self) -> str:
        return (
            "Ollama não está acessível.\n\n"
            "1. Instale: https://ollama.com\n"
            f"2. Suba o daemon e puxe um modelo: ollama pull {self.default_model}\n"
            f"3. Confirme OLLAMA_BASE_URL={self.base_url} no .env\n"
            "4. Ou use AI_PROVIDER=openrouter com OPENROUTER_API_KEY"
        )

    def format_error(self, error: str) -> str:
        lowered = error.lower()
        if "connection" in lowered or "refused" in lowered or "10061" in error:
            return self.configuration_error()
        if "not found" in lowered or "404" in error:
            return (
                f"Modelo Ollama não encontrado.\n\n"
                f"Execute: ollama pull {self.default_model}\n"
                f"Ou ajuste OLLAMA_MODEL no .env."
            )
        if self.is_retryable_error(error):
            return (
                "Ollama sobrecarregado ou indisponível temporariamente. "
                "Aguarde e tente novamente; modelos locais grandes podem demorar."
            )
        return f"Erro ao chamar Ollama: {error}"

    def _tags_url(self) -> str:
        # /v1 → raiz do Ollama para /api/tags
        root = self.base_url
        if root.endswith("/v1"):
            root = root[:-3]
        return f"{root.rstrip('/')}/api/tags"

    def _list_local_models(self) -> list[str]:
        try:
            req = urllib.request.Request(self._tags_url(), method="GET")
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                import json

                payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception:
            return []
        models = []
        for item in payload.get("models") or []:
            name = (item.get("name") or item.get("model") or "").strip()
            if name:
                models.append(name)
        return models

    def health(self) -> dict[str, Any]:
        models = self._list_local_models()
        ok = True
        detail = ""
        try:
            req = urllib.request.Request(self._tags_url(), method="GET")
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                if getattr(resp, "status", 200) >= 400:
                    ok = False
                    detail = f"HTTP {resp.status}"
        except urllib.error.URLError as e:
            ok = False
            detail = str(e.reason if hasattr(e, "reason") else e)
        except Exception as e:
            ok = False
            detail = str(e)

        return {
            "provider": self.name,
            "configured": ok,
            "ok": ok,
            "detail": detail,
            "base_url": self.base_url,
            "models": models[:20],
            "default_model": self.default_model,
        }

    def models_catalog(self) -> dict[str, Any]:
        local = self._list_local_models()
        primary, fallback = self.resolve_models(None, None)
        ids = local or [primary]
        if primary not in ids:
            ids = [primary, *ids]
        models = []
        for mid in ids[:12]:
            models.append(
                {
                    "id": mid,
                    "name": mid,
                    "description": "Modelo local Ollama · air-gapped",
                    "provider": "ollama",
                    "fallback": fallback if mid != fallback else primary,
                }
            )
        return {
            "provider": self.name,
            "default_model": primary,
            "default_fallback": fallback,
            "tiers": [
                {
                    "id": "local",
                    "label": "Local (Ollama)",
                    "description": "100% na sua máquina · sem OpenRouter",
                    "models": models,
                }
            ],
        }
