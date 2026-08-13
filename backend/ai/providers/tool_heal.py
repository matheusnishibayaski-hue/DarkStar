"""Autocorreção de function calling (JSON malformado / schema inválido)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from backend.ai.providers.base import LLMMessage, ToolCall
from backend.ai.providers.tool_parse import parse_tool_arguments

if TYPE_CHECKING:
    from backend.ai.providers.base import BaseLLMProvider

MAX_TOOL_HEAL_ATTEMPTS = 2

_SCHEMA_HINTS = {
    "run_kali_tool": (
        '{"command":"nmap -sV scanme.nmap.org","reason":"enumerar serviços no alvo autorizado"}'
    ),
    "finish_mission": ('{"summary":"Resumo final da missão em português.","objective_met":true}'),
}


def _heal_prompt(tool_name: str, broken: str, error: str) -> str:
    example = _SCHEMA_HINTS.get(tool_name, '{"key":"value"}')
    return (
        "A chamada de ferramenta anterior está inválida.\n"
        f"Tool: {tool_name}\n"
        f"Erro: {error}\n"
        f"Argumentos recebidos:\n{broken[:2000]}\n\n"
        "Responda APENAS com um JSON válido (sem markdown, sem texto extra) "
        f"seguindo exatamente este formato de exemplo:\n{example}"
    )


def validate_tool_payload(tool_name: str, data: dict[str, Any]) -> str | None:
    """Retorna mensagem de erro ou None se ok."""
    if tool_name == "run_kali_tool":
        cmd = data.get("command")
        if not isinstance(cmd, str) or not cmd.strip():
            return "campo 'command' ausente ou vazio"
        if "reason" not in data:
            data["reason"] = "execução solicitada pela IA"
        return None
    if tool_name == "finish_mission":
        if not isinstance(data.get("summary"), str) or not str(data.get("summary")).strip():
            return "campo 'summary' ausente ou vazio"
        if "objective_met" not in data:
            data["objective_met"] = False
        return None
    return f"tool desconhecida: {tool_name}"


def heal_tool_arguments(
    provider: BaseLLMProvider,
    *,
    model: str,
    tool_name: str,
    broken_arguments: str,
    messages: list[dict] | None = None,
    max_attempts: int = MAX_TOOL_HEAL_ATTEMPTS,
) -> dict[str, Any] | None:
    """
    Tenta parse local e, se falhar, pede ao LLM para reformatar (até max_attempts).
    Retorna dict válido ou None.
    """
    data = parse_tool_arguments(broken_arguments)
    if data is not None:
        err = validate_tool_payload(tool_name, data)
        if err is None:
            return data

    last_error = "JSON inválido"
    current = broken_arguments
    if data is not None:
        last_error = validate_tool_payload(tool_name, data) or last_error
        current = json.dumps(data, ensure_ascii=False)

    heal_messages = list(messages or [])
    for _ in range(max(0, max_attempts)):
        heal_messages = [
            *heal_messages,
            {"role": "user", "content": _heal_prompt(tool_name, current, last_error)},
        ]
        try:
            completion = provider.complete(
                model=model,
                messages=heal_messages,
                tools=None,
                tool_choice=None,
            )
        except Exception as e:
            last_error = str(e)
            continue

        content = (completion.message.content or "").strip()
        # Também aceita se o modelo devolver tool_calls na correção
        if completion.message.tool_calls:
            for tc in completion.message.tool_calls:
                if tc.name == tool_name or tool_name in (tc.name or ""):
                    content = tc.arguments
                    break

        parsed = parse_tool_arguments(content)
        if parsed is None:
            last_error = "resposta de correção não é JSON"
            current = content
            heal_messages.append({"role": "assistant", "content": content or "(vazio)"})
            continue

        err = validate_tool_payload(tool_name, parsed)
        if err is None:
            return parsed
        last_error = err
        current = json.dumps(parsed, ensure_ascii=False)
        heal_messages.append({"role": "assistant", "content": current})

    return None


def resolve_tool_arguments(
    provider: BaseLLMProvider,
    *,
    model: str,
    tool_call: ToolCall,
    messages: list[dict] | None = None,
) -> tuple[dict[str, Any] | None, str]:
    """
    Resolve argumentos de uma tool call.
    Retorna (payload|None, motivo_erro).
    """
    data = parse_tool_arguments(tool_call.arguments)
    if data is not None and validate_tool_payload(tool_call.name, data) is None:
        return data, ""

    healed = heal_tool_arguments(
        provider,
        model=model,
        tool_name=tool_call.name,
        broken_arguments=tool_call.arguments,
        messages=messages,
    )
    if healed is not None:
        return healed, ""
    return None, (
        f"Não foi possível corrigir os argumentos de {tool_call.name} "
        f"após {MAX_TOOL_HEAL_ATTEMPTS} tentativas de autocorreção."
    )


def assistant_dict_from_message(message: LLMMessage) -> dict:
    data: dict = {"role": "assistant", "content": message.content}
    if message.tool_calls:
        data["tool_calls"] = [
            {
                "id": tc.id,
                "type": "function",
                "function": {"name": tc.name, "arguments": tc.arguments},
            }
            for tc in message.tool_calls
        ]
    return data
