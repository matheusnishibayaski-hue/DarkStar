"""Extrai e normaliza tool calls a partir de respostas de LLM (API ou texto)."""

from __future__ import annotations

import json
import re
import uuid
from typing import Any

from backend.ai.providers.base import ToolCall

# JSON em code fence ou solto no content
_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.IGNORECASE)
_RUN_KALI_HINT = re.compile(
    r"run_kali_tool|finish_mission|\"command\"\s*:|\"objective_met\"\s*:",
    re.IGNORECASE,
)


def try_parse_json(raw: str) -> Any | None:
    text = (raw or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Trailing commas comuns em modelos locais
    fixed = re.sub(r",\s*([}\]])", r"\1", text)
    try:
        return json.loads(fixed)
    except json.JSONDecodeError:
        pass

    # Aspas simples → duplas (heurística leve)
    if "'" in text and '"' not in text:
        try:
            return json.loads(text.replace("'", '"'))
        except json.JSONDecodeError:
            pass

    # Extrai primeiro objeto {...}
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        chunk = text[start : end + 1]
        chunk = re.sub(r",\s*([}\]])", r"\1", chunk)
        try:
            return json.loads(chunk)
        except json.JSONDecodeError:
            return None
    return None


def parse_tool_arguments(raw: str) -> dict[str, Any] | None:
    data = try_parse_json(raw)
    return data if isinstance(data, dict) else None


def _dict_to_tool_call(
    data: dict[str, Any], default_name: str = "run_kali_tool"
) -> ToolCall | None:
    fn = data.get("function") if isinstance(data.get("function"), dict) else None
    name = str(
        data.get("name") or data.get("tool") or (fn.get("name") if fn else None) or ""
    ).strip()

    args: Any
    if fn and fn.get("name") in {"run_kali_tool", "finish_mission"}:
        name = str(fn["name"])
        args = fn.get("arguments", fn.get("parameters", {}))
    elif name in {"run_kali_tool", "finish_mission"}:
        args = data.get("arguments") or data.get("parameters")
        if args is None:
            if name == "run_kali_tool" and "command" in data:
                args = {"command": data.get("command", ""), "reason": data.get("reason", "")}
            elif name == "finish_mission" and "summary" in data:
                args = {
                    "summary": data.get("summary", ""),
                    "objective_met": bool(data.get("objective_met", False)),
                }
            else:
                args = data
    elif "command" in data:
        name = "run_kali_tool"
        args = {"command": data.get("command", ""), "reason": data.get("reason", "")}
    elif "summary" in data and "objective_met" in data:
        name = "finish_mission"
        args = {
            "summary": data.get("summary", ""),
            "objective_met": bool(data.get("objective_met", False)),
        }
    else:
        return None

    if not name:
        name = default_name

    if isinstance(args, str):
        args_str = args
    else:
        args_str = json.dumps(args or {}, ensure_ascii=False)

    return ToolCall(id=f"local-{uuid.uuid4().hex[:12]}", name=str(name), arguments=args_str)


def extract_tool_calls_from_content(content: str | None) -> list[ToolCall]:
    """Quando o modelo coloca a tool no texto em vez de tool_calls nativo."""
    text = (content or "").strip()
    if not text or not _RUN_KALI_HINT.search(text):
        return []

    candidates: list[str] = []
    for match in _FENCE_RE.finditer(text):
        candidates.append(match.group(1).strip())
    candidates.append(text)

    found: list[ToolCall] = []
    for cand in candidates:
        data = try_parse_json(cand)
        if data is None:
            continue
        items = data if isinstance(data, list) else [data]
        for item in items:
            if not isinstance(item, dict):
                continue
            # Formato {"tool_calls":[...]}
            if "tool_calls" in item and isinstance(item["tool_calls"], list):
                for tc in item["tool_calls"]:
                    if isinstance(tc, dict):
                        parsed = _dict_to_tool_call(tc)
                        if parsed:
                            found.append(parsed)
                continue
            parsed = _dict_to_tool_call(item)
            if parsed:
                found.append(parsed)
        if found:
            break
    return found


def sdk_message_to_tool_calls(message: Any) -> list[ToolCall]:
    raw_calls = getattr(message, "tool_calls", None) or []
    out: list[ToolCall] = []
    for tc in raw_calls:
        fn = getattr(tc, "function", None)
        name = getattr(fn, "name", "") if fn is not None else ""
        args = getattr(fn, "arguments", "") if fn is not None else ""
        out.append(
            ToolCall(
                id=str(getattr(tc, "id", "") or f"sdk-{uuid.uuid4().hex[:12]}"),
                name=str(name or ""),
                arguments=args if isinstance(args, str) else json.dumps(args or {}),
            )
        )
    return out
