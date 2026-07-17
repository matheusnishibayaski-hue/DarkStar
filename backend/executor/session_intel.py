"""Intel e relatório agrupados por conversa (chat_session_id)."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.config import BASE_DIR
from backend.executor.recon_db import normalize_target
from backend.executor.surface import load_surface, mark_finding_status, save_surface

INTEL_SESSIONS_DIR = BASE_DIR / "backend" / "intel_sessions"
_SESSION_ID_RE = re.compile(r"^[\w-]{8,128}$")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _session_path(session_id: str) -> Path | None:
    if not session_id or not _SESSION_ID_RE.match(session_id):
        return None
    INTEL_SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    return INTEL_SESSIONS_DIR / f"{session_id}.json"


def load_session(session_id: str) -> dict[str, Any]:
    path = _session_path(session_id)
    if not path or not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def save_session(session_id: str, data: dict[str, Any]) -> dict[str, Any]:
    path = _session_path(session_id)
    if not path:
        return {}
    payload = dict(data)
    payload["session_id"] = session_id
    payload["updated_at"] = _now()
    if not payload.get("created_at"):
        payload["created_at"] = payload["updated_at"]
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return payload


def touch_session(session_id: str, target: str) -> dict[str, Any]:
    """Registra alvo testado nesta conversa."""
    if not session_id or not target:
        return {}
    host = normalize_target(target)
    if not host:
        return {}
    data = load_session(session_id) or {
        "session_id": session_id,
        "label": "",
        "targets": [],
        "created_at": _now(),
    }
    targets = list(data.get("targets") or [])
    if host not in targets:
        targets.append(host)
    data["targets"] = targets[:50]
    return save_session(session_id, data)


def set_session_label(session_id: str, label: str) -> dict[str, Any]:
    data = load_session(session_id) or {
        "session_id": session_id,
        "label": "",
        "targets": [],
        "created_at": _now(),
    }
    data["label"] = (label or "").strip()[:120]
    return save_session(session_id, data)


def _finding_belongs_to_session(finding: dict[str, Any], session_id: str) -> bool:
    return str(finding.get("chat_session_id") or "") == session_id


def aggregate_session_findings(session_id: str) -> list[dict[str, Any]]:
    """Achados de todos os alvos desta conversa."""
    meta = load_session(session_id)
    targets = list(meta.get("targets") or [])
    if not targets:
        return []

    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for target in targets:
        surface = load_surface(target)
        if not surface:
            continue
        for f in surface.get("findings") or []:
            if not isinstance(f, dict):
                continue
            if not _finding_belongs_to_session(f, session_id):
                continue
            fid = str(f.get("id") or "")
            key = f"{target}:{fid}"
            if key in seen:
                continue
            seen.add(key)
            row = dict(f)
            row["surface_target"] = target
            out.append(row)
    return out


def session_summary(session_id: str) -> dict[str, Any]:
    meta = load_session(session_id)
    findings = aggregate_session_findings(session_id)
    confirmed = sum(1 for f in findings if f.get("status") == "confirmed")
    return {
        "session_id": session_id,
        "label": meta.get("label") or "",
        "targets": meta.get("targets") or [],
        "findings_total": len(findings),
        "findings_confirmed": confirmed,
        "updated_at": meta.get("updated_at"),
        "created_at": meta.get("created_at"),
    }


def list_session_summaries() -> list[dict[str, Any]]:
    if not INTEL_SESSIONS_DIR.is_dir():
        return []
    items: list[dict[str, Any]] = []
    for path in INTEL_SESSIONS_DIR.glob("*.json"):
        sid = path.stem
        if not _SESSION_ID_RE.match(sid):
            continue
        items.append(session_summary(sid))
    items.sort(key=lambda x: str(x.get("updated_at") or ""), reverse=True)
    return items


def patch_session_finding(
    session_id: str,
    surface_target: str,
    finding_id: str,
    status: str,
    *,
    evidence: str = "",
) -> dict[str, Any] | None:
    finding = mark_finding_status(surface_target, finding_id, status, evidence=evidence)
    if not finding:
        return None
    touch_session(session_id, surface_target)
    return {**finding, "surface_target": surface_target}


def delete_session_intel(session_id: str) -> bool:
    """Remove índice da conversa e achados vinculados a ela."""
    meta = load_session(session_id)
    path = _session_path(session_id)
    if path and path.is_file():
        path.unlink()

    removed_any = bool(meta)
    for target in meta.get("targets") or []:
        surface = load_surface(target)
        if not surface:
            continue
        before = len(surface.get("findings") or [])
        kept = [
            f
            for f in (surface.get("findings") or [])
            if str(f.get("chat_session_id") or "") != session_id
        ]
        if len(kept) != before:
            surface["findings"] = kept
            save_surface(target, surface)
            removed_any = True
    return removed_any or (path is None or not path.exists())


def collect_session_tool_executions(session_id: str, limit: int = 80) -> list[dict[str, Any]]:
    """Logs de execução desta conversa (para anexo no PDF)."""
    from backend.executor.logs import list_log_ids_for_session, read_execution_log

    rows: list[dict[str, Any]] = []
    for log_id in list_log_ids_for_session(session_id)[:limit]:
        raw = read_execution_log(log_id)
        if not raw:
            continue
        cmd = ""
        for line in raw.splitlines():
            if line.startswith("Comando:"):
                cmd = line.split(":", 1)[-1].strip()
                break
        rows.append({"log_id": log_id, "command": cmd})
    return rows
