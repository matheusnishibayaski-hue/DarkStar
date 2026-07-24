"""Servidor MCP (Model Context Protocol) — núcleo compartilhado.

Expõe o motor de pentest do Chat IA Kali (Attack Surface Graph, whitelist de
ferramentas e execução no container Kali) como **Tools** e **Resources** MCP,
para consumo por clientes como Cursor, Claude Desktop e outros agentes.

Este módulo é *transporte-agnóstico*: tanto a camada HTTP
(`backend/routes/mcp.py`, montada em `/api/mcp/*`) quanto o servidor stdio
(`backend/mcp_server.py`, usado por `python -m backend.mcp_server`) delegam
para as funções aqui definidas — mesma lógica, mesmas travas de segurança.

Segurança: `run_kali_tool` passa pela mesma validação de whitelist
(`ALLOWED_TOOLS`) e trava de escopo (`ALLOWED_TARGETS`) usada pelo chat e pelo
Auto-Pilot — nenhuma execução bypassa `validate_command_scope`.

Referência do protocolo: https://modelcontextprotocol.io
"""

from __future__ import annotations

from typing import Any, Callable

from backend.config import ALLOWED_TARGETS, ALLOWED_TOOLS, MCP_ENABLED, TOOL_CATEGORIES
from backend.deps import APP_VERSION

MCP_PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "chat-ia-kali-mcp"

ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]


def server_info() -> dict[str, Any]:
    """Metadados do servidor MCP, expostos em GET /api/mcp/info e no `initialize`."""
    return {
        "name": SERVER_NAME,
        "version": APP_VERSION,
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "enabled": MCP_ENABLED,
        "scope_lock_enabled": bool(ALLOWED_TARGETS),
        "capabilities": {"tools": {}, "resources": {}},
    }


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


def _tool_list_surface_targets(_args: dict[str, Any]) -> dict[str, Any]:
    from backend.executor.surface import list_surface_summaries

    return {"targets": list_surface_summaries()}


def _tool_get_surface_graph(args: dict[str, Any]) -> dict[str, Any]:
    from backend.executor.surface import load_surface

    target = str(args.get("target") or "").strip()
    if not target:
        raise ValueError("Parâmetro 'target' é obrigatório.")
    data = load_surface(target)
    if not data:
        raise ValueError(f"Nenhum Attack Surface encontrado para '{target}'.")
    return data


def _tool_get_surface_triage(args: dict[str, Any]) -> dict[str, Any]:
    from backend.ai.chains import infer_attack_chains
    from backend.ai.risk_score import risk_score_for_target
    from backend.ai.verify import confidence_gate_buckets
    from backend.executor.recon_db import normalize_target
    from backend.executor.surface import load_surface, surface_summary

    target = str(args.get("target") or "").strip()
    if not target:
        raise ValueError("Parâmetro 'target' é obrigatório.")
    data = load_surface(target)
    if not data:
        raise ValueError(f"Nenhum engajamento encontrado para '{target}'.")
    gate = confidence_gate_buckets(target)
    return {
        "target": normalize_target(target),
        "summary": surface_summary(data),
        "risk": risk_score_for_target(target),
        "chains": infer_attack_chains(data),
        "executive": gate["executive"],
        "human_queue": gate["human_queue"],
        "archive": gate["archive"],
    }


def _tool_get_risk_score(args: dict[str, Any]) -> dict[str, Any]:
    from backend.ai.risk_score import risk_score_for_target

    target = str(args.get("target") or "").strip()
    if not target:
        raise ValueError("Parâmetro 'target' é obrigatório.")
    return risk_score_for_target(target)


def _tool_list_allowed_tools(_args: dict[str, Any]) -> dict[str, Any]:
    return {"tools": sorted(ALLOWED_TOOLS), "categories": TOOL_CATEGORIES}


def _tool_run_kali_tool(args: dict[str, Any]) -> dict[str, Any]:
    from backend.executor.kali import execute_kali_command, parse_command_string
    from backend.security.scope import validate_command_scope

    command = str(args.get("command") or "").strip()
    reason = str(args.get("reason") or "Execução via MCP").strip()[:300]
    if not command:
        raise ValueError("Parâmetro 'command' é obrigatório.")

    argv = parse_command_string(command)
    scope_ok, scope_error = validate_command_scope(argv)
    if not scope_ok:
        return {"blocked": True, "success": False, "block_reason": scope_error}

    result = execute_kali_command(argv, reason)
    return {
        "command": result.command,
        "tool": result.tool,
        "success": result.success,
        "blocked": result.blocked,
        "block_reason": result.block_reason,
        "exit_code": result.exit_code,
        "stdout": result.stdout[:8000],
        "stderr": result.stderr[:4000],
    }


def _tool_enrich_target_threat_intel(args: dict[str, Any]) -> dict[str, Any]:
    from backend.ai.threat_intel import enrich_surface_with_threat_intel

    target = str(args.get("target") or "").strip()
    if not target:
        raise ValueError("Parâmetro 'target' é obrigatório.")
    processed = enrich_surface_with_threat_intel(target)
    return {"target": target, "findings_enriched": processed}


def _tool_suggest_next_checks(args: dict[str, Any]) -> dict[str, Any]:
    from backend.intelligence.hub import suggest

    target = str(args.get("target") or "").strip()
    if not target:
        raise ValueError("Parâmetro 'target' é obrigatório.")
    industry = str(args.get("industry") or "").strip() or None
    limit = int(args.get("limit") or 10)
    return suggest(target, industry=industry, limit=limit)


_TOOL_DEFS: list[dict[str, Any]] = [
    {
        "name": "list_surface_targets",
        "description": "Lista os alvos com Attack Surface Graph registrado (resumo por alvo).",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": _tool_list_surface_targets,
    },
    {
        "name": "get_surface_graph",
        "description": (
            "Retorna o Attack Surface Graph completo (hosts, portas, urls, serviços e "
            "findings) de um alvo já testado."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Host/IP/domínio alvo."}},
            "required": ["target"],
            "additionalProperties": False,
        },
        "handler": _tool_get_surface_graph,
    },
    {
        "name": "get_surface_triage",
        "description": (
            "Painel de triagem do alvo: findings executivos (confirmados), fila humana, "
            "arquivo (FP/descartados), hipóteses de cadeia de ataque e risk score."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
            "additionalProperties": False,
        },
        "handler": _tool_get_surface_triage,
    },
    {
        "name": "get_risk_score",
        "description": (
            "Score de risco 0-100 (+ faixa crítico/alto/médio/baixo/info) calculado a partir "
            "dos findings confirmados do alvo, com boost automático para CVEs em CISA KEV/EPSS."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
            "additionalProperties": False,
        },
        "handler": _tool_get_risk_score,
    },
    {
        "name": "list_allowed_tools",
        "description": "Lista a whitelist de binários permitidos no executor Kali e suas categorias na UI.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": _tool_list_allowed_tools,
    },
    {
        "name": "run_kali_tool",
        "description": (
            "Executa um comando de pentest no container Kali isolado (whitelist de ~180 "
            "binários). Respeita a trava de escopo ALLOWED_TARGETS: comandos fora do escopo "
            "autorizado são bloqueados antes da execução."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Comando completo, ex.: 'nmap -sV -Pn alvo.com'.",
                },
                "reason": {
                    "type": "string",
                    "description": "Motivo/objetivo da execução (auditoria).",
                },
            },
            "required": ["command"],
            "additionalProperties": False,
        },
        "handler": _tool_run_kali_tool,
    },
    {
        "name": "enrich_target_threat_intel",
        "description": (
            "Enriquece os findings com CVE do alvo usando CISA KEV (exploração ativa) e "
            "FIRST EPSS (probabilidade de exploração em 30 dias)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
            "additionalProperties": False,
        },
        "handler": _tool_enrich_target_threat_intel,
    },
    {
        "name": "suggest_next_checks",
        "description": (
            "Sugere próximos checks de pentest com base no Attack Surface e padrões "
            "do Intelligence Hub (heurístico; inclui rationale)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "industry": {"type": "string"},
                "limit": {"type": "integer"},
            },
            "required": ["target"],
            "additionalProperties": False,
        },
        "handler": _tool_suggest_next_checks,
    },
]

_TOOLS_BY_NAME: dict[str, dict[str, Any]] = {t["name"]: t for t in _TOOL_DEFS}


def list_tools() -> list[dict[str, Any]]:
    """Metadados MCP das tools (sem o handler interno)."""
    return [{k: v for k, v in t.items() if k != "handler"} for t in _TOOL_DEFS]


def get_tool(name: str) -> dict[str, Any] | None:
    tool = _TOOLS_BY_NAME.get(name)
    if not tool:
        return None
    return {k: v for k, v in tool.items() if k != "handler"}


def call_tool(name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Executa uma tool MCP e retorna o formato de conteúdo padrão (content/isError)."""
    tool = _TOOLS_BY_NAME.get(name)
    if not tool:
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Tool '{name}' não encontrada."}],
        }
    try:
        result = tool["handler"](arguments or {})
        return {"isError": False, "content": [{"type": "json", "json": result}]}
    except ValueError as exc:
        return {"isError": True, "content": [{"type": "text", "text": str(exc)}]}
    except Exception as exc:  # pragma: no cover - defensivo, não deve vazar stack trace
        return {"isError": True, "content": [{"type": "text", "text": f"Erro interno: {exc}"}]}


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------


def list_resources() -> list[dict[str, Any]]:
    """Lista recursos MCP: alvos, whitelist e um `surface://{alvo}` por engajamento."""
    from backend.executor.surface import list_surface_summaries

    resources: list[dict[str, Any]] = [
        {
            "uri": "targets://list",
            "name": "Alvos com Attack Surface",
            "description": "Lista de alvos com engajamento (Attack Surface Graph) registrado.",
            "mimeType": "application/json",
        },
        {
            "uri": "tools://whitelist",
            "name": "Whitelist de ferramentas",
            "description": "Binários permitidos para execução no container Kali.",
            "mimeType": "application/json",
        },
    ]
    for summary in list_surface_summaries():
        target = summary.get("target")
        if target:
            resources.append(
                {
                    "uri": f"surface://{target}",
                    "name": f"Attack Surface — {target}",
                    "description": f"Grafo completo de superfície de ataque de '{target}'.",
                    "mimeType": "application/json",
                }
            )
    return resources


def read_resource(uri: str) -> dict[str, Any]:
    """Lê o conteúdo de um recurso MCP pela URI (`targets://`, `tools://`, `surface://`)."""
    from backend.executor.surface import list_surface_summaries, load_surface

    if uri == "targets://list":
        return {
            "uri": uri,
            "mimeType": "application/json",
            "json": {"targets": list_surface_summaries()},
        }
    if uri == "tools://whitelist":
        return {
            "uri": uri,
            "mimeType": "application/json",
            "json": {"tools": sorted(ALLOWED_TOOLS), "categories": TOOL_CATEGORIES},
        }
    if uri.startswith("surface://"):
        target = uri[len("surface://") :]
        data = load_surface(target)
        if not data:
            raise ValueError(f"Recurso '{uri}' não encontrado.")
        return {"uri": uri, "mimeType": "application/json", "json": data}
    raise ValueError(f"Recurso '{uri}' desconhecido.")


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 — usado por POST /api/mcp/rpc e pelo transporte stdio
# ---------------------------------------------------------------------------


def handle_rpc(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Processa uma mensagem JSON-RPC 2.0 MCP. Retorna None para notificações."""
    msg_id = payload.get("id")
    method = payload.get("method")
    params = payload.get("params") or {}
    is_notification = "id" not in payload

    def _ok(result: Any) -> dict[str, Any] | None:
        return None if is_notification else {"jsonrpc": "2.0", "id": msg_id, "result": result}

    def _err(code: int, message: str) -> dict[str, Any] | None:
        if is_notification:
            return None
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}

    try:
        if method == "initialize":
            return _ok(
                {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "serverInfo": {"name": SERVER_NAME, "version": APP_VERSION},
                    "capabilities": {"tools": {}, "resources": {}},
                }
            )
        if method == "ping":
            return _ok({})
        if method == "tools/list":
            return _ok({"tools": list_tools()})
        if method == "tools/call":
            name = str(params.get("name") or "")
            arguments = params.get("arguments") or {}
            return _ok(call_tool(name, arguments))
        if method == "resources/list":
            return _ok({"resources": list_resources()})
        if method == "resources/read":
            uri = str(params.get("uri") or "")
            return _ok({"contents": [read_resource(uri)]})
        if method in {"notifications/initialized", "notifications/cancelled"}:
            return None
        return _err(-32601, f"Método não suportado: {method}")
    except ValueError as exc:
        return _err(-32602, str(exc))
    except Exception as exc:  # pragma: no cover - defensivo
        return _err(-32603, f"Erro interno: {exc}")
