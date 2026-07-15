"""Middlewares HTTP da aplicação."""

from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse

from backend.config import CHAT_API_TOKEN, RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SEC
from backend.deps import PUBLIC_API_PATHS, RATE_LIMITED_PATHS, client_ip, is_authenticated
from backend.security.rate_limit import get_rate_limiter


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
