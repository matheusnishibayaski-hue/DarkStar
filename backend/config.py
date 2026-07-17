import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

# OpenRouter — chave em https://openrouter.ai/keys
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")

# Aliases novos (preferidos) com retrocompatibilidade GEMINI_*
PRIMARY_MODEL = (
    os.getenv("OPENROUTER_PRIMARY_MODEL") or os.getenv("GEMINI_MODEL") or "google/gemini-2.5-flash"
)
FALLBACK_MODEL = (
    os.getenv("OPENROUTER_FALLBACK_MODEL")
    or os.getenv("GEMINI_FALLBACK_MODEL")
    or "deepseek/deepseek-v3.2"
)
GEMINI_MODEL = PRIMARY_MODEL
GEMINI_FALLBACK_MODEL = FALLBACK_MODEL

# Servidor / segurança local
UVICORN_HOST = os.getenv("UVICORN_HOST", "127.0.0.1")
UVICORN_PORT = int(os.getenv("UVICORN_PORT", "8000"))
CHAT_API_TOKEN = os.getenv("CHAT_API_TOKEN", "").strip()
# Só confie em X-Forwarded-For atrás de reverse proxy que limpa o header do cliente.
TRUST_PROXY = os.getenv("TRUST_PROXY", "").strip().lower() in {"1", "true", "yes", "on"}
SESSION_TTL_HOURS = int(os.getenv("SESSION_TTL_HOURS", "24"))
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "30"))
RATE_LIMIT_WINDOW_SEC = int(os.getenv("RATE_LIMIT_WINDOW_SEC", "60"))
_cors_raw = os.getenv(
    "CORS_ORIGINS",
    "http://127.0.0.1:8000,http://localhost:8000",
)
CORS_ORIGINS = [o.strip() for o in _cors_raw.split(",") if o.strip()]

KALI_CONTAINER = os.getenv("KALI_CONTAINER", "kali-tools")
COMMAND_TIMEOUT = int(os.getenv("COMMAND_TIMEOUT", "180"))
WIFI_COMMAND_TIMEOUT = int(os.getenv("WIFI_COMMAND_TIMEOUT", "600"))
MAX_TOOL_ITERATIONS = int(os.getenv("MAX_TOOL_ITERATIONS", "5"))
MAX_HEALING_ATTEMPTS = int(os.getenv("MAX_HEALING_ATTEMPTS", "2"))
MAX_HISTORY_MESSAGES = int(os.getenv("MAX_HISTORY_MESSAGES", "10"))
MAX_AUTONOMOUS_ROUNDS = int(os.getenv("MAX_AUTONOMOUS_ROUNDS", "10"))
MAX_AUTONOMOUS_TOOLS = int(os.getenv("MAX_AUTONOMOUS_TOOLS", "25"))
OUTPUT_TOKEN_LIMIT = int(os.getenv("OUTPUT_TOKEN_LIMIT", "3000"))
SUMMARY_HEAD_LINES = int(os.getenv("SUMMARY_HEAD_LINES", "30"))
SUMMARY_TAIL_LINES = int(os.getenv("SUMMARY_TAIL_LINES", "15"))
LOG_DIR = BASE_DIR / "backend" / "logs"
RECON_DIR = BASE_DIR / "backend" / "recon"
_outputs_dir_raw = os.getenv("OUTPUTS_DIR", "").strip()
OUTPUTS_DIR = (
    Path(_outputs_dir_raw).expanduser().resolve()
    if _outputs_dir_raw
    else BASE_DIR / "backend" / "outputs"
)
RECON_TTL_DAYS = int(os.getenv("RECON_TTL_DAYS", "30"))
AUDIT_DIR = BASE_DIR / "backend" / "audit"
SURFACE_DIR = BASE_DIR / "backend" / "surface"
# Perfil Auto-Pilot: passive | safe-active | full
RISK_PROFILE = (os.getenv("RISK_PROFILE", "safe-active") or "safe-active").strip().lower()
if RISK_PROFILE not in {"passive", "safe-active", "full"}:
    RISK_PROFILE = "safe-active"
# Teto do pipeline PoC (high/critical sempre entram; hard-cap 80 no verify)
VERIFY_MAX_FINDINGS = int(os.getenv("VERIFY_MAX_FINDINGS", "40"))
VERIFY_MAX_FINDINGS = max(12, min(VERIFY_MAX_FINDINGS, 80))
REPORT_BRAND_NAME = os.getenv("REPORT_BRAND_NAME", "Chat IA Kali").strip() or "Chat IA Kali"
_max_dl_mb = int(os.getenv("MAX_FILE_DOWNLOAD_MB", "50"))
MAX_FILE_DOWNLOAD_BYTES = _max_dl_mb * 1024 * 1024

# Escopo de alvos (vazio = sem restrição). Ex: scanme.nmap.org,10.0.0.5,lab.local
_allowed_targets_raw = os.getenv("ALLOWED_TARGETS", "").strip()


def _normalize_scope_target(value: str) -> str:
    import re

    v = value.strip().lower()
    v = re.sub(r"^https?://", "", v)
    v = v.split("/")[0].split(":")[0].strip(".")
    v = re.sub(r"[^\w.\-]", "_", v)
    return v[:128] or "unknown"


ALLOWED_TARGETS: frozenset[str] = (
    frozenset(_normalize_scope_target(t) for t in _allowed_targets_raw.split(",") if t.strip())
    if _allowed_targets_raw
    else frozenset()
)

from backend.config_prompts import AUTONOMOUS_SYSTEM_PROMPT, SYSTEM_PROMPT
from backend.config_tools import (
    ALLOWED_TOOLS,
    HOST_WIFI_TOOLS,
    TOOL_CATEGORIES,
    WIFI_CONTAINER_TOOLS,
    WIFI_TOOLS,
)

__all__ = [
    "BASE_DIR",
    "OPENROUTER_API_KEY",
    "PRIMARY_MODEL",
    "FALLBACK_MODEL",
    "GEMINI_MODEL",
    "GEMINI_FALLBACK_MODEL",
    "UVICORN_HOST",
    "UVICORN_PORT",
    "CHAT_API_TOKEN",
    "TRUST_PROXY",
    "SESSION_TTL_HOURS",
    "RATE_LIMIT_REQUESTS",
    "RATE_LIMIT_WINDOW_SEC",
    "CORS_ORIGINS",
    "KALI_CONTAINER",
    "COMMAND_TIMEOUT",
    "WIFI_COMMAND_TIMEOUT",
    "MAX_TOOL_ITERATIONS",
    "MAX_HEALING_ATTEMPTS",
    "MAX_HISTORY_MESSAGES",
    "MAX_AUTONOMOUS_ROUNDS",
    "MAX_AUTONOMOUS_TOOLS",
    "OUTPUT_TOKEN_LIMIT",
    "SUMMARY_HEAD_LINES",
    "SUMMARY_TAIL_LINES",
    "LOG_DIR",
    "RECON_DIR",
    "OUTPUTS_DIR",
    "RECON_TTL_DAYS",
    "AUDIT_DIR",
    "SURFACE_DIR",
    "RISK_PROFILE",
    "MAX_FILE_DOWNLOAD_BYTES",
    "ALLOWED_TARGETS",
    "HOST_WIFI_TOOLS",
    "WIFI_CONTAINER_TOOLS",
    "WIFI_TOOLS",
    "ALLOWED_TOOLS",
    "SYSTEM_PROMPT",
    "AUTONOMOUS_SYSTEM_PROMPT",
    "TOOL_CATEGORIES",
]
