"""Rotas HTTP do servidor MCP (Model Context Protocol) — `/api/mcp/*`.

Expõe a mesma lógica de `backend/mcp_service.py` via REST simples, para
clientes que preferem HTTP ao transporte stdio (ou para debug/curl manual).
Herda a autenticação já aplicada a todo `/api/*` por `api_token_guard`
(`backend/middleware.py`) — nenhuma trava adicional é necessária aqui.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend import mcp_service
from backend.config import MCP_ENABLED

router = APIRouter(prefix="/api/mcp", tags=["mcp"])


class McpToolCallRequest(BaseModel):
    arguments: dict[str, Any] = Field(default_factory=dict)


def _ensure_enabled() -> None:
    if not MCP_ENABLED:
        raise HTTPException(
            status_code=404, detail="Servidor MCP desabilitado (MCP_ENABLED=false)."
        )


@router.get("/info")
def mcp_info():
    _ensure_enabled()
    return mcp_service.server_info()


@router.get("/tools")
def mcp_list_tools():
    _ensure_enabled()
    return {"tools": mcp_service.list_tools()}


@router.get("/tools/{name}")
def mcp_get_tool(name: str):
    _ensure_enabled()
    tool = mcp_service.get_tool(name)
    if not tool:
        raise HTTPException(status_code=404, detail=f"Tool '{name}' não encontrada.")
    return tool


@router.post("/tools/{name}")
def mcp_call_tool(name: str, body: McpToolCallRequest):
    _ensure_enabled()
    if not mcp_service.get_tool(name):
        raise HTTPException(status_code=404, detail=f"Tool '{name}' não encontrada.")
    return mcp_service.call_tool(name, body.arguments)


@router.get("/resources")
def mcp_list_resources():
    _ensure_enabled()
    return {"resources": mcp_service.list_resources()}


@router.get("/resources/{uri:path}")
def mcp_read_resource(uri: str):
    _ensure_enabled()
    try:
        return mcp_service.read_resource(uri)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/rpc")
def mcp_rpc(body: dict[str, Any]):
    """Endpoint JSON-RPC 2.0 genérico — mesmo dispatcher usado pelo transporte stdio."""
    _ensure_enabled()
    response = mcp_service.handle_rpc(body)
    return response or {}
