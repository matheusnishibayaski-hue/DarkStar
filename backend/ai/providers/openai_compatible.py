"""Provider base para APIs compatíveis com OpenAI Chat Completions."""

from __future__ import annotations

from typing import Any

from openai import OpenAI

from backend.ai.providers.base import BaseLLMProvider, LLMCompletion, LLMMessage
from backend.ai.providers.tool_parse import extract_tool_calls_from_content, sdk_message_to_tool_calls


class OpenAICompatibleProvider(BaseLLMProvider):
    def __init__(
        self,
        *,
        name: str,
        base_url: str,
        api_key: str,
        default_model: str,
        default_fallback: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.default_model = default_model
        self.default_fallback = default_fallback or default_model
        self.extra_headers = extra_headers or {}
        self._client: OpenAI | None = None

    def _get_client(self) -> OpenAI:
        if self._client is None:
            self._client = OpenAI(base_url=self.base_url, api_key=self.api_key or "unused")
        return self._client

    def resolve_models(
        self, model: str | None = None, fallback: str | None = None
    ) -> tuple[str, str]:
        primary = (model or "").strip() or self.default_model
        fb = (fallback or "").strip() or self.default_fallback
        if primary == fb:
            fb = self.default_fallback if self.default_fallback != primary else primary
        return primary, fb

    def complete(
        self,
        *,
        model: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        tool_choice: str | dict | None = "auto",
    ) -> LLMCompletion:
        kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
        }
        if tools:
            kwargs["tools"] = tools
            if tool_choice is not None:
                kwargs["tool_choice"] = tool_choice
        if self.extra_headers:
            kwargs["extra_headers"] = self.extra_headers

        response = self._get_client().chat.completions.create(**kwargs)
        raw_msg = response.choices[0].message
        tool_calls = sdk_message_to_tool_calls(raw_msg)
        content = raw_msg.content

        # Modelos locais: às vezes a tool vem só no texto
        if not tool_calls and tools:
            extracted = extract_tool_calls_from_content(content)
            if extracted:
                tool_calls = extracted
                # Evita eco do JSON bruto no chat quando já viramos tool_calls
                content = None

        return LLMCompletion(
            message=LLMMessage(content=content, tool_calls=tool_calls),
            model=model,
            raw=response,
        )
