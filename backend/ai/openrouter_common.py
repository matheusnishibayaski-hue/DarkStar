"""Helpers compartilhados — reexports + mensagens de erro (compat)."""

from __future__ import annotations

from typing import Any

from backend.ai.providers.base import LLMMessage, ToolCall
from backend.ai.providers.openrouter import OPENROUTER_BASE_URL, OPENROUTER_HEADERS
from backend.ai.providers.tool_heal import assistant_dict_from_message
from backend.ai.providers.tool_parse import sdk_message_to_tool_calls


def assistant_message_dict(message: Any) -> dict:
    """Aceita LLMMessage ou mensagem SDK OpenAI (compat com testes/legado)."""
    if isinstance(message, LLMMessage):
        return assistant_dict_from_message(message)
    content = getattr(message, "content", None)
    tool_calls = sdk_message_to_tool_calls(message)
    return assistant_dict_from_message(LLMMessage(content=content, tool_calls=tool_calls))


def is_retryable_error(error: str) -> bool:
    lowered = error.lower()
    return "429" in error or "rate" in lowered or "quota" in lowered or "overloaded" in lowered


def openrouter_error_message(error: str) -> str:
    from backend.ai.providers.openrouter import OpenRouterAdapter

    return OpenRouterAdapter().format_error(error)


__all__ = [
    "OPENROUTER_BASE_URL",
    "OPENROUTER_HEADERS",
    "ToolCall",
    "assistant_message_dict",
    "is_retryable_error",
    "openrouter_error_message",
]
