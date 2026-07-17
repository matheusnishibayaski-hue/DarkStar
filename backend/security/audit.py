"""Auditoria imutável — append-only JSONL por dia."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.config import AUDIT_DIR

_SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|token|password|secret|authorization)\s*[:=]\s*\S+"),
    re.compile(r"(?i)bearer\s+\S+"),
    re.compile(r"(?i)sk-[a-z0-9]{20,}"),
)

AUDIT_DIR.mkdir(parents=True, exist_ok=True)


def _redact(value: Any) -> Any:
    if isinstance(value, str):
        redacted = value
        redacted = _SECRET_PATTERNS[0].sub(r"\1=***", redacted)
        redacted = _SECRET_PATTERNS[1].sub("Bearer ***", redacted)
        redacted = _SECRET_PATTERNS[2].sub("sk-***", redacted)
        for secret_key in ("OPENROUTER_API_KEY", "CHAT_API_TOKEN", "SESSION_COOKIE"):
            if secret_key in redacted:
                redacted = redacted.replace(secret_key, "***")
        return redacted
    if isinstance(value, dict):
        return {k: _redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


def _audit_path(date: datetime | None = None) -> Path:
    dt = date or datetime.now(timezone.utc)
    return AUDIT_DIR / f"events-{dt.strftime('%Y-%m-%d')}.jsonl"


def record_event(event_type: str, payload: dict[str, Any]) -> None:
    entry = _redact(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            **payload,
        }
    )
    path = _audit_path()
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def record_tool_execution(
    *,
    command: str,
    tool: str,
    targets: list[str] | None = None,
    success: bool,
    blocked: bool = False,
    exit_code: int = 0,
    log_file_id: str = "",
    mission_id: str | None = None,
    reason: str = "",
    client_ip: str | None = None,
) -> None:
    record_event(
        "tool_execution",
        {
            "mission_id": mission_id or "",
            "tool": tool,
            "command": command,
            "targets": targets or [],
            "success": success,
            "blocked": blocked,
            "exit_code": exit_code,
            "log_file_id": log_file_id,
            "reason": reason[:200] if reason else "",
            "client_ip": client_ip or "",
        },
    )


def list_events(
    *,
    date: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 500))
    if date:
        try:
            dt = datetime.strptime(date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            return []
        paths = [_audit_path(dt)]
    else:
        paths = sorted(AUDIT_DIR.glob("events-*.jsonl"), reverse=True)

    events: list[dict[str, Any]] = []
    for path in paths:
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        if len(events) >= limit:
            break

    events.sort(key=lambda e: e.get("ts", ""), reverse=True)
    return events[:limit]


def remove_entries_by_log_id(log_id: str) -> int:
    """Remove linhas de auditoria que referenciam o log_file_id."""
    if not log_id or not log_id.isalnum():
        return 0
    removed = 0
    for path in sorted(AUDIT_DIR.glob("events-*.jsonl")):
        if not path.is_file():
            continue
        kept: list[str] = []
        file_removed = 0
        for line in path.read_text(encoding="utf-8").splitlines():
            raw = line.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                kept.append(raw)
                continue
            if str(obj.get("log_file_id") or "") == log_id:
                file_removed += 1
            else:
                kept.append(raw)
        if file_removed:
            path.write_text(
                ("\n".join(kept) + "\n") if kept else "",
                encoding="utf-8",
            )
            removed += file_removed
    return removed
