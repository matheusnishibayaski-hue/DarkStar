"""Entry point FastAPI — monta app, middlewares e rotas."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from backend.config import CORS_ORIGINS
from backend.deps import APP_VERSION
from backend.middleware import api_token_guard, rate_limit_guard
from backend.routes import auth, autonomous, chat, system

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"

app = FastAPI(title="Chat IA Kali", version=APP_VERSION)

_cors_allow_all = "*" in CORS_ORIGINS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if _cors_allow_all else CORS_ORIGINS,
    allow_credentials=not _cors_allow_all,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.middleware("http")(rate_limit_guard)
app.middleware("http")(api_token_guard)

app.include_router(system.router)
app.include_router(auth.router)
app.include_router(chat.router)
app.include_router(autonomous.router)


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
    return FileResponse(FRONTEND_DIR / "index.html")


app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
