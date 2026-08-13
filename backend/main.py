"""Entry point FastAPI — monta app, middlewares e rotas."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from backend.config import CORS_ORIGINS
from backend.deps import APP_VERSION
from backend.middleware import (
    api_token_guard,
    privilege_guard,
    rate_limit_guard,
    request_context_guard,
    role_guard,
)
from backend.observability import configure_logging
from backend.routes import (
    audit,
    auth,
    autonomous,
    chat,
    chat_sessions,
    clients,
    compliance,
    dashboard,
    data,
    engagements,
    files,
    github,
    intel_sessions,
    intelligence,
    mcp,
    notifications,
    playbooks,
    portfolio,
    remediation,
    reports,
    schedule_api,
    system,
)

configure_logging()

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"


def _resolve_cors_origins(raw: list[str]) -> list[str]:
    origins = [origin for origin in raw if origin != "*"]
    if not origins:
        origins = ["http://127.0.0.1:8000", "http://localhost:8000"]
    return origins


@asynccontextmanager
async def lifespan(_app: FastAPI):
    try:
        from backend.database.db import ensure_dashboard_db

        ensure_dashboard_db()
    except Exception as exc:  # noqa: BLE001
        import logging

        logging.getLogger(__name__).warning("dashboard_db_init_skipped: %s", exc)
    try:
        from backend.config import DATABASE_URL
        from backend.intelligence.store import use_postgres

        if use_postgres() and DATABASE_URL:
            from backend.database.db import init_db

            init_db()
    except Exception as exc:  # noqa: BLE001 — boot não deve falhar se DB offline
        import logging

        logging.getLogger(__name__).warning("intelligence_db_init_skipped: %s", exc)
    try:
        from backend.schedule.runner import start_scheduler

        start_scheduler()
    except Exception as exc:  # noqa: BLE001
        import logging

        logging.getLogger(__name__).warning("scheduler_start_skipped: %s", exc)
    try:
        yield
    finally:
        try:
            from backend.schedule.runner import stop_scheduler

            stop_scheduler()
        except Exception:  # noqa: BLE001
            pass


app = FastAPI(title="DarkStar", version=APP_VERSION, lifespan=lifespan)

_cors_origins = _resolve_cors_origins(CORS_ORIGINS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-Chat-Token",
        "X-Request-ID",
        "X-DarkStar-Privilege",
    ],
)
app.middleware("http")(request_context_guard)
app.middleware("http")(privilege_guard)
app.middleware("http")(role_guard)
app.middleware("http")(rate_limit_guard)
app.middleware("http")(api_token_guard)


@app.middleware("http")
async def static_no_cache(request, call_next):
    """Evita JS/CSS stale no browser (módulos ES sem ?v= na cadeia de imports)."""
    response = await call_next(request)
    path = request.url.path
    if path == "/" or path.startswith("/static/"):
        if path == "/" or path.endswith((".js", ".css", ".html", ".mjs")):
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
    return response


app.include_router(system.router)
app.include_router(files.router)
app.include_router(data.router)
app.include_router(audit.router)
app.include_router(playbooks.router)
app.include_router(engagements.router)
app.include_router(clients.router)
app.include_router(portfolio.router)
app.include_router(dashboard.router)
app.include_router(schedule_api.router)
app.include_router(intel_sessions.router)
app.include_router(intelligence.router)
app.include_router(compliance.router)
app.include_router(auth.router)
app.include_router(chat.router)
app.include_router(chat_sessions.router)
app.include_router(reports.router)
app.include_router(autonomous.router)
app.include_router(github.router)
app.include_router(notifications.router)
app.include_router(remediation.router)
app.include_router(mcp.router)


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
        '<rect width="32" height="32" rx="4" fill="#0d1117"/>'
        '<text x="16" y="22" text-anchor="middle" font-family="monospace" '
        'font-size="14" fill="#3fb950">$</text></svg>'
    )
    return Response(content=svg, media_type="image/svg+xml")


@app.get("/")
def index():
    return FileResponse(
        FRONTEND_DIR / "index.html",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
        },
    )


app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
