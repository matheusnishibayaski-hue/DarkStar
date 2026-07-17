import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from backend.config import LOG_DIR

LOG_DIR.mkdir(parents=True, exist_ok=True)
_SESSION_INDEX_DIR = LOG_DIR / "by_session"
_SESSION_ID_RE = re.compile(r"^[\w-]{1,128}$")


def new_log_id() -> str:
    return uuid.uuid4().hex[:12]


def _session_index_path(session_id: str) -> Path | None:
    if not session_id or not _SESSION_ID_RE.match(session_id):
        return None
    _SESSION_INDEX_DIR.mkdir(parents=True, exist_ok=True)
    return _SESSION_INDEX_DIR / f"{session_id}.json"


def _register_session_log(session_id: str, log_id: str) -> None:
    path = _session_index_path(session_id)
    if not path:
        return
    data: dict = {"log_ids": []}
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = {"log_ids": []}
    ids = list(data.get("log_ids") or [])
    if log_id not in ids:
        ids.append(log_id)
    path.write_text(json.dumps({"log_ids": ids}, ensure_ascii=False), encoding="utf-8")


def save_execution_log(
    command: str,
    reason: str,
    stdout: str,
    stderr: str,
    log_id: str | None = None,
    chat_session_id: str | None = None,
) -> str:
    log_id = log_id or new_log_id()
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    session_line = f"Chat-Session: {chat_session_id}\n" if chat_session_id else ""
    content = (
        f"=== Chat IA Kali — Log de Execução ===\n"
        f"ID: {log_id}\n"
        f"Timestamp: {timestamp}\n"
        f"{session_line}"
        f"Comando: {command}\n"
        f"Motivo: {reason}\n\n"
        f"=== STDOUT ===\n{stdout}\n\n"
        f"=== STDERR ===\n{stderr}\n"
    )
    (LOG_DIR / f"{log_id}.log").write_text(content, encoding="utf-8")
    if chat_session_id:
        meta = {"chat_session_id": chat_session_id, "log_id": log_id}
        (LOG_DIR / f"{log_id}.meta.json").write_text(
            json.dumps(meta, ensure_ascii=False), encoding="utf-8"
        )
        _register_session_log(chat_session_id, log_id)
    return log_id


def read_execution_log(log_id: str) -> str | None:
    if not log_id or not log_id.isalnum():
        return None
    path = LOG_DIR / f"{log_id}.log"
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def list_log_ids_for_session(session_id: str) -> list[str]:
    path = _session_index_path(session_id)
    if not path or not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    return [str(x) for x in (data.get("log_ids") or []) if str(x).isalnum()]


def list_execution_logs(limit: int = 100, session_id: str | None = None) -> list[dict]:
    """Lista logs em disco (+ órfãos na auditoria). Filtra por chat_session_id se informado."""
    limit = max(1, min(limit, 500))
    session_logs: set[str] | None = None
    if session_id:
        session_logs = set(list_log_ids_for_session(session_id))

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
        if session_logs is not None and log_id not in session_logs:
            continue
        try:
            st = path.stat()
        except OSError:
            continue
        seen.add(log_id)
        chat_sid = ""
        meta_path = LOG_DIR / f"{log_id}.meta.json"
        if meta_path.is_file():
            try:
                chat_sid = str(json.loads(meta_path.read_text(encoding="utf-8")).get("chat_session_id") or "")
            except (json.JSONDecodeError, OSError):
                pass
        items.append(
            {
                "id": log_id,
                "size": st.st_size,
                "modified_at": datetime.fromtimestamp(
                    st.st_mtime, tz=timezone.utc
                ).isoformat(),
                "has_file": True,
                "chat_session_id": chat_sid,
            }
        )

    if session_id:
        return items[:limit]

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
                "chat_session_id": "",
            }
        )

    items.sort(key=lambda x: str(x.get("modified_at") or ""), reverse=True)
    return items[:limit]
