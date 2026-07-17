import uuid
from datetime import datetime, timezone

from backend.config import LOG_DIR

LOG_DIR.mkdir(parents=True, exist_ok=True)


def new_log_id() -> str:
    return uuid.uuid4().hex[:12]


def save_execution_log(
    command: str,
    reason: str,
    stdout: str,
    stderr: str,
    log_id: str | None = None,
) -> str:
    log_id = log_id or new_log_id()
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


def list_execution_logs(limit: int = 100) -> list[dict]:
    """Lista logs em disco + referências órfãs só na auditoria."""
    limit = max(1, min(limit, 500))
    items: list[dict] = []
    seen: set[str] = set()

    paths = sorted(
        LOG_DIR.glob("*.log"),
        key=lambda p: p.stat().st_mtime if p.is_file() else 0,
        reverse=True,
    )
    for path in paths:
        if not path.is_file():
            continue
        log_id = path.stem
        if not log_id.isalnum():
            continue
        try:
            st = path.stat()
        except OSError:
            continue
        seen.add(log_id)
        items.append(
            {
                "id": log_id,
                "size": st.st_size,
                "modified_at": datetime.fromtimestamp(
                    st.st_mtime, tz=timezone.utc
                ).isoformat(),
                "has_file": True,
            }
        )

    from backend.security.audit import list_events

    for ev in list_events(limit=500):
        log_id = str(ev.get("log_file_id") or "")
        if not log_id or not log_id.isalnum() or log_id in seen:
            continue
        seen.add(log_id)
        items.append(
            {
                "id": log_id,
                "size": 0,
                "modified_at": str(ev.get("ts") or ""),
                "has_file": False,
                "tool": str(ev.get("tool") or ""),
                "command": str(ev.get("command") or ""),
            }
        )

    items.sort(key=lambda x: str(x.get("modified_at") or ""), reverse=True)
    return items[:limit]
