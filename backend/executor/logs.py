import uuid
from datetime import datetime, timezone
from pathlib import Path

from backend.config import LOG_DIR

LOG_DIR.mkdir(parents=True, exist_ok=True)


def save_execution_log(command: str, reason: str, stdout: str, stderr: str) -> str:
    log_id = uuid.uuid4().hex[:12]
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    content = (
        f"=== Chat IA Kali — Log de Execução ===\n"
        f"ID: {log_id}\n"
        f"Timestamp: {timestamp}\n"
        f"Comando: {command}\n"
        f"Motivo: {reason}\n\n"
        f"=== STDOUT ===\n{stdout}\n\n"
        f"=== STDERR ===\n{stderr}\n"
    )
    (LOG_DIR / f"{log_id}.log").write_text(content, encoding="utf-8")
    return log_id


def read_execution_log(log_id: str) -> str | None:
    if not log_id or not log_id.isalnum():
        return None
    path = LOG_DIR / f"{log_id}.log"
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")
