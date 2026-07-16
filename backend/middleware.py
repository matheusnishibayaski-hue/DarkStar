"""Middlewares HTTP da aplicação."""

from __future__ import annotations

import time

from fastapi import Request
from fastapi.responses import JSONResponse

from backend.config import CHAT_API_TOKEN, RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SEC
from backend.deps import PUBLIC_API_PATHS, RATE_LIMITED_PATHS, client_ip, is_authenticated
from backend.observability import (
    incr,
    log_event,
    new_request_id,
    set_client_ip,
    set_correlation_id,
    set_request_id,
)
from backend.security.rate_limit import get_rate_limiter


async def request_context_guard(request: Request, call_next):
    """Propaga X-Request-ID, correlation ID e mede duração do endpoint."""
    incoming = (request.headers.get("X-Request-ID") or "").strip()
    request_id = incoming[:64] if incoming else new_request_id()
    set_request_id(request_id)
    set_correlation_id(request.query_params.get("mission_id") or request_id)
    set_client_ip(client_ip(request))
    request.state.request_id = request_id
    request.state.correlation_id = get_correlation_id_safe()
    request.state.client_ip = client_ip(request)

    incr("requests_total")
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        incr("errors_total")
        log_event(
            "ERROR",
            "request_failed",
            method=request.method,
            path=request.url.path,
        )
        raise

    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    status = getattr(response, "status_code", 500)
    if status >= 500:
        incr("errors_total")
    log_event(
        "INFO",
        "request_completed",
        method=request.method,
        path=request.url.path,
        status_code=status,
        duration_ms=duration_ms,
    )
    response.headers["X-Request-ID"] = request_id
    return response


def get_correlation_id_safe() -> str:
    from backend.observability import get_correlation_id

    return get_correlation_id()


async def rate_limit_guard(request: Request, call_next):
    if request.method == "POST" and request.url.path in RATE_LIMITED_PATHS:
        limiter = get_rate_limiter(RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SEC)
        allowed, retry_after = limiter.allow(client_ip(request))
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": "Muitas requisições. Aguarde e tente novamente."},
                headers={"Retry-After": str(retry_after)},
            )
    return await call_next(request)


async def api_token_guard(request: Request, call_next):
    if not CHAT_API_TOKEN:
        return await call_next(request)

    path = request.url.path
    if not path.startswith("/api/") or path in PUBLIC_API_PATHS:
        return await call_next(request)

    if is_authenticated(request):
        return await call_next(request)

    return JSONResponse(status_code=401, content={"detail": "Token de API inválido ou ausente."})
