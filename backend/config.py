import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

# OpenRouter — chave em https://openrouter.ai/keys
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")

# Provedor de IA: openrouter (nuvem) | ollama (local / air-gapped)
AI_PROVIDER = (os.getenv("AI_PROVIDER", "openrouter") or "openrouter").strip().lower()
if AI_PROVIDER in {"local"}:
    AI_PROVIDER = "ollama"
if AI_PROVIDER not in {"openrouter", "ollama"}:
    AI_PROVIDER = "openrouter"

# Ollama — API OpenAI-compatible (https://ollama.com)
OLLAMA_BASE_URL = (os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1") or "").strip().rstrip(
    "/"
) or "http://localhost:11434/v1"
OLLAMA_MODEL = (os.getenv("OLLAMA_MODEL", "llama3.1:8b") or "llama3.1:8b").strip()
OLLAMA_FALLBACK_MODEL = (
    os.getenv("OLLAMA_FALLBACK_MODEL", "") or OLLAMA_MODEL
).strip() or OLLAMA_MODEL
OLLAMA_API_KEY = (os.getenv("OLLAMA_API_KEY", "ollama") or "ollama").strip()

# Aliases novos (preferidos) com retrocompatibilidade GEMINI_*
PRIMARY_MODEL = (
    os.getenv("OPENROUTER_PRIMARY_MODEL") or os.getenv("GEMINI_MODEL") or "google/gemini-2.5-flash"
)
FALLBACK_MODEL = (
    os.getenv("OPENROUTER_FALLBACK_MODEL")
    or os.getenv("GEMINI_FALLBACK_MODEL")
    or "deepseek/deepseek-v3.2"
)
# Quando AI_PROVIDER=ollama, os defaults efetivos vêm de OLLAMA_* via factory
if AI_PROVIDER == "ollama":
    GEMINI_MODEL = OLLAMA_MODEL
    GEMINI_FALLBACK_MODEL = OLLAMA_FALLBACK_MODEL
else:
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
REPORT_BRAND_NAME = os.getenv("REPORT_BRAND_NAME", "DarkStar").strip() or "DarkStar"
# White-label da consultoria (PDF / portal). Prioridade: engagement brand → estes → DarkStar
CONSULTING_NAME = (
    os.getenv("CONSULTING_NAME", "") or REPORT_BRAND_NAME
).strip() or "DarkStar"
_default_logo = BASE_DIR / "assets" / "darkstar-logo.png"
CONSULTING_LOGO_PATH = (
    os.getenv("CONSULTING_LOGO_PATH", "") or ""
).strip() or (
    "assets/darkstar-logo.png" if _default_logo.is_file() else ""
)
CONSULTING_PRIMARY_COLOR = (
    os.getenv("CONSULTING_PRIMARY_COLOR", "#1E90FF") or "#1E90FF"
).strip()
CONSULTING_FOOTER = (
    os.getenv("CONSULTING_FOOTER", "")
    or "Documento confidencial — uso autorizado apenas."
).strip()
# Workspaces multi-cliente locais
CLIENTS_DIR = BASE_DIR / "backend" / "clients"
CLIENTS_DIR.mkdir(parents=True, exist_ok=True)
# Timeout do sumário executivo via LLM (segundos)
EXECUTIVE_SUMMARY_TIMEOUT = int(os.getenv("EXECUTIVE_SUMMARY_TIMEOUT", "15"))
EXECUTIVE_SUMMARY_TIMEOUT = max(5, min(EXECUTIVE_SUMMARY_TIMEOUT, 60))
# MSSP local — recorrência, alertas, retenção, papel do operador
SCHEDULE_ENABLED = os.getenv("SCHEDULE_ENABLED", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
SCHEDULE_TICK_SEC = int(os.getenv("SCHEDULE_TICK_SEC", "60"))
SCHEDULE_TICK_SEC = max(15, min(SCHEDULE_TICK_SEC, 3600))
SCHEDULE_DIR = BASE_DIR / "backend" / "schedules"
SCHEDULE_DIR.mkdir(parents=True, exist_ok=True)
ALERT_WEBHOOK_URL = (os.getenv("ALERT_WEBHOOK_URL", "") or "").strip()
# Token GitHub (PAT ou Actions GITHUB_TOKEN) — comentários/issues/status
GITHUB_TOKEN = (os.getenv("GITHUB_TOKEN", "") or "").strip()
# Notificações multicanal
SLACK_WEBHOOK_URL = (os.getenv("SLACK_WEBHOOK_URL", "") or "").strip()
SLACK_CHANNEL = (os.getenv("SLACK_CHANNEL", "#security") or "#security").strip()
DISCORD_WEBHOOK_URL = (os.getenv("DISCORD_WEBHOOK_URL", "") or "").strip()
TELEGRAM_BOT_TOKEN = (os.getenv("TELEGRAM_BOT_TOKEN", "") or "").strip()
TELEGRAM_CHAT_ID = (os.getenv("TELEGRAM_CHAT_ID", "") or "").strip()
SMTP_SERVER = (os.getenv("SMTP_SERVER", "") or "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587") or 587)
SMTP_USER = (os.getenv("SMTP_USER", "") or "").strip()
SMTP_PASSWORD = (os.getenv("SMTP_PASSWORD", "") or "").strip()
EMAIL_FROM = (os.getenv("EMAIL_FROM", "") or "").strip()
EMAIL_TO = (os.getenv("EMAIL_TO", "") or "").strip()
JIRA_URL = (os.getenv("JIRA_URL", "") or "").strip()
JIRA_USER = (os.getenv("JIRA_USER", "") or "").strip()
JIRA_TOKEN = (os.getenv("JIRA_TOKEN", "") or "").strip()
JIRA_PROJECT = (os.getenv("JIRA_PROJECT", "SEC") or "SEC").strip()
ALERT_ON_CRITICAL = os.getenv("ALERT_ON_CRITICAL", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
ALERT_RISK_JUMP = float(os.getenv("ALERT_RISK_JUMP", "15") or 15)
AUTO_BASELINE_AFTER_VERIFY = os.getenv(
    "AUTO_BASELINE_AFTER_VERIFY", "true"
).strip().lower() in {"1", "true", "yes", "on"}
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "0") or 0)  # 0 = desligado
RISK_HISTORY_DIR = BASE_DIR / "backend" / "risk_history"
RISK_HISTORY_DIR.mkdir(parents=True, exist_ok=True)
FP_SUPPRESS_PATH = BASE_DIR / "backend" / "fp_suppress.json"
# Papel local do operador: admin | analyst | viewer (sem portal do cliente)
OPERATOR_ROLE = (os.getenv("OPERATOR_ROLE", "admin") or "admin").strip().lower()
if OPERATOR_ROLE not in {"admin", "analyst", "viewer"}:
    OPERATOR_ROLE = "admin"
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

# Threat Intelligence — CISA KEV (Known Exploited Vulnerabilities) + FIRST EPSS
THREAT_INTEL_ENABLED = os.getenv("THREAT_INTEL_ENABLED", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
# TTL do cache em memória (segundos) para catálogo KEV e scores EPSS
THREAT_INTEL_CACHE_TTL = int(os.getenv("THREAT_INTEL_CACHE_TTL", "21600"))

# Servidor MCP (Model Context Protocol) — expõe o motor via /api/mcp/* e stdio
MCP_ENABLED = os.getenv("MCP_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}

# Intelligence Hub — histórico/padrões/sugestões (JSON local ou PostgreSQL)
INTELLIGENCE_ENABLED = os.getenv("INTELLIGENCE_ENABLED", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
INTELLIGENCE_TTL_DAYS = int(os.getenv("INTELLIGENCE_TTL_DAYS", "90"))
_intel_dir_raw = os.getenv("INTELLIGENCE_DIR", "").strip()
INTELLIGENCE_DIR = (
    Path(_intel_dir_raw).expanduser().resolve()
    if _intel_dir_raw
    else BASE_DIR / "backend" / "intelligence_data"
)
# postgres | json — postgres exige DATABASE_URL
INTELLIGENCE_STORAGE = (os.getenv("INTELLIGENCE_STORAGE", "json") or "json").strip().lower()
if INTELLIGENCE_STORAGE not in {"json", "postgres"}:
    INTELLIGENCE_STORAGE = "json"
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
COMPLIANCE_ENABLED = os.getenv("COMPLIANCE_ENABLED", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

# Master key DarkStar — sem ela o operador fica no perfil B (restrito).
# Gere com: python -c "import secrets; print(secrets.token_urlsafe(64))"
MASTER_KEY = os.getenv("MASTER_KEY", "").strip()

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
    "AI_PROVIDER",
    "OLLAMA_BASE_URL",
    "OLLAMA_MODEL",
    "OLLAMA_FALLBACK_MODEL",
    "OLLAMA_API_KEY",
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
    "CONSULTING_NAME",
    "CONSULTING_LOGO_PATH",
    "CONSULTING_PRIMARY_COLOR",
    "CONSULTING_FOOTER",
    "CLIENTS_DIR",
    "EXECUTIVE_SUMMARY_TIMEOUT",
    "SCHEDULE_ENABLED",
    "SCHEDULE_TICK_SEC",
    "SCHEDULE_DIR",
    "ALERT_WEBHOOK_URL",
    "GITHUB_TOKEN",
    "SLACK_WEBHOOK_URL",
    "SLACK_CHANNEL",
    "DISCORD_WEBHOOK_URL",
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID",
    "SMTP_SERVER",
    "SMTP_PORT",
    "SMTP_USER",
    "SMTP_PASSWORD",
    "EMAIL_FROM",
    "EMAIL_TO",
    "JIRA_URL",
    "JIRA_USER",
    "JIRA_TOKEN",
    "JIRA_PROJECT",
    "ALERT_ON_CRITICAL",
    "ALERT_RISK_JUMP",
    "AUTO_BASELINE_AFTER_VERIFY",
    "RETENTION_DAYS",
    "RISK_HISTORY_DIR",
    "FP_SUPPRESS_PATH",
    "OPERATOR_ROLE",
    "REPORT_BRAND_NAME",
    "RISK_PROFILE",
    "MAX_FILE_DOWNLOAD_BYTES",
    "VERIFY_MAX_FINDINGS",
    "ALLOWED_TARGETS",
    "THREAT_INTEL_ENABLED",
    "THREAT_INTEL_CACHE_TTL",
    "MCP_ENABLED",
    "INTELLIGENCE_ENABLED",
    "INTELLIGENCE_TTL_DAYS",
    "INTELLIGENCE_DIR",
    "INTELLIGENCE_STORAGE",
    "DATABASE_URL",
    "COMPLIANCE_ENABLED",
    "MASTER_KEY",
    "HOST_WIFI_TOOLS",
    "WIFI_CONTAINER_TOOLS",
    "WIFI_TOOLS",
    "ALLOWED_TOOLS",
    "SYSTEM_PROMPT",
    "AUTONOMOUS_SYSTEM_PROMPT",
    "TOOL_CATEGORIES",
]
