"""Contrato Provider/Adapter para LLMs (OpenRouter, Ollama, …)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: str  # JSON string (pode estar malformado — heal corrige)


@dataclass
class LLMMessage:
    content: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)

    @property
    def has_tool_calls(self) -> bool:
        return bool(self.tool_calls)


@dataclass
class LLMCompletion:
    message: LLMMessage
    model: str = ""
    raw: Any = None


class BaseLLMProvider(ABC):
    """Interface mínima usada por chat e Auto-Pilot."""

    name: str = "base"

    @abstractmethod
    def is_configured(self) -> bool: ...

    @abstractmethod
    def configuration_error(self) -> str:
        """Mensagem amigável quando o provedor não está configurado."""

    @abstractmethod
    def resolve_models(
        self, model: str | None = None, fallback: str | None = None
    ) -> tuple[str, str]: ...

    @abstractmethod
    def complete(
        self,
        *,
        model: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        tool_choice: str | dict | None = "auto",
    ) -> LLMCompletion: ...

    @abstractmethod
    def format_error(self, error: str) -> str: ...

    def is_retryable_error(self, error: str) -> bool:
        lowered = error.lower()
        return (
            "429" in error
            or "rate" in lowered
            or "quota" in lowered
            or "overloaded" in lowered
            or "unavailable" in lowered
        )

    def health(self) -> dict[str, Any]:
        return {
            "provider": self.name,
            "configured": self.is_configured(),
            "ok": self.is_configured(),
            "detail": "",
        }

    def models_catalog(self) -> dict[str, Any]:
        primary, fallback = self.resolve_models(None, None)
        return {
            "provider": self.name,
            "default_model": primary,
            "default_fallback": fallback,
            "tiers": [
                {
                    "id": "local" if self.name == "ollama" else "default",
                    "label": "Local" if self.name == "ollama" else "Padrão",
                    "description": f"Provedor {self.name}",
                    "models": [
                        {
                            "id": primary,
                            "name": primary,
                            "description": f"Modelo principal ({self.name})",
                            "provider": self.name,
                            "fallback": fallback,
                        }
                    ],
                }
            ],
        }
