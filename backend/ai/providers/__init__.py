"""Provedores LLM (OpenRouter / Ollama) — padrão Provider/Adapter."""

from backend.ai.providers.base import BaseLLMProvider, LLMCompletion, LLMMessage, ToolCall
from backend.ai.providers.factory import get_llm_provider, reset_llm_provider_cache
from backend.ai.providers.ollama import OllamaAdapter
from backend.ai.providers.openrouter import (
    OPENROUTER_BASE_URL,
    OPENROUTER_HEADERS,
    OpenRouterAdapter,
)
from backend.ai.providers.runtime import (
    clear_provider_override,
    get_active_provider_name,
    provider_status,
    set_active_provider,
)
from backend.ai.providers.tool_heal import (
    assistant_dict_from_message,
    heal_tool_arguments,
    resolve_tool_arguments,
)
from backend.ai.providers.tool_parse import (
    extract_tool_calls_from_content,
    parse_tool_arguments,
    try_parse_json,
)

__all__ = [
    "BaseLLMProvider",
    "LLMCompletion",
    "LLMMessage",
    "ToolCall",
    "OpenRouterAdapter",
    "OllamaAdapter",
    "OPENROUTER_BASE_URL",
    "OPENROUTER_HEADERS",
    "get_llm_provider",
    "reset_llm_provider_cache",
    "get_active_provider_name",
    "set_active_provider",
    "clear_provider_override",
    "provider_status",
    "assistant_dict_from_message",
    "heal_tool_arguments",
    "resolve_tool_arguments",
    "extract_tool_calls_from_content",
    "parse_tool_arguments",
    "try_parse_json",
]
