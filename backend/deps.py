"""Dependências e helpers compartilhados da API."""

from __future__ import annotations

from fastapi import Request

from backend.config import CHAT_API_TOKEN, SESSION_TTL_HOURS, TRUST_PROXY
from backend.schemas import ToolExecutionResponse
from backend.security.sessions import SESSION_COOKIE_NAME, get_session_store

APP_VERSION = "2.0.0"

PUBLIC_API_PATHS = frozenset(
    {
        "/api/health",
        "/api/client-config",
        "/api/auth/login",
        "/api/auth/session",
        "/api/auth/privilege",
        "/api/auth/master-key",
        "/api/auth/master-key/lock",
    }
)

RATE_LIMITED_PATHS = frozenset(
    {
        "/api/chat",
        "/api/chat/stream",
        "/api/autonomous",
        "/api/autonomous/stream",
    }
)


def client_ip(request: Request) -> str:
    """IP do cliente. X-Forwarded-For só é lido com TRUST_PROXY=true."""
    if TRUST_PROXY:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip() or "unknown"
    if request.client:
        return request.client.host
    return "unknown"


def is_authenticated(request: Request) -> bool:
    if not CHAT_API_TOKEN:
        return True

    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if get_session_store(SESSION_TTL_HOURS * 3600).validate(session_id):
        return True

    token = request.headers.get("X-Chat-Token") or request.query_params.get("token")
    return token == CHAT_API_TOKEN


def tool_execution_response(e) -> ToolExecutionResponse:
    return ToolExecutionResponse(
        command=e.command,
        reason=e.reason,
        stdout=e.stdout,
        stderr=e.stderr,
        exit_code=e.exit_code,
        success=e.success,
        blocked=e.blocked,
        log_file_id=getattr(e, "log_file_id", "") or "",
        tool=getattr(e, "tool", "") or "",
    )


def valid_mission_id(mission_id: str) -> bool:
    return (
        bool(mission_id)
        and len(mission_id) <= 64
        and all(c.isalnum() or c in "-_" for c in mission_id)
    )
