"""Jobs de recorrência — persistidos no banco (com migração de JSON legado)."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from backend.config import SCHEDULE_DIR
from backend.executor.recon_db import normalize_target

logger = logging.getLogger(__name__)

JOB_TYPES = frozenset({"monitor", "full", "remind", "repeat"})
INTERVALS = {
    "daily": 1,
    "weekly": 7,
    "monthly": 30,
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _path(job_id: str) -> Path:
    return SCHEDULE_DIR / f"{job_id}.json"


def _read_file(job_id: str) -> dict[str, Any] | None:
    path = _path(job_id)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


def save_job(data: dict[str, Any]) -> dict[str, Any]:
    from backend.database.db import ensure_dashboard_db, session_scope
    from backend.database.models_store import ScheduleJobRow

    job_id = str(data.get("id") or "").strip()
    if not job_id:
        raise ValueError("job id required")
    data = dict(data)
    data["id"] = job_id
    data["client_id"] = str(data.get("client_id") or "default")
    data["target"] = normalize_target(str(data.get("target") or ""))
    data["next_run_at"] = str(data.get("next_run_at") or "")
    data["updated_at"] = data.get("updated_at") or _iso(_now())

    ensure_dashboard_db()
    with session_scope() as db:
        row = db.query(ScheduleJobRow).filter(ScheduleJobRow.id == job_id).first()
        payload = json.dumps(data, ensure_ascii=False)
        if row:
            row.client_id = data["client_id"][:64]
            row.target = data["target"][:256]
            row.next_run_at = data["next_run_at"][:64]
            row.payload_json = payload
        else:
            db.add(
                ScheduleJobRow(
                    id=job_id[:32],
                    client_id=data["client_id"][:64],
                    target=data["target"][:256],
                    next_run_at=data["next_run_at"][:64],
                    payload_json=payload,
                )
            )
        db.flush()

    # Espelho legado
    try:
        SCHEDULE_DIR.mkdir(parents=True, exist_ok=True)
        _path(job_id).write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError:
        pass
    return data


def get_job(job_id: str) -> dict[str, Any] | None:
    from backend.database.db import ensure_dashboard_db, session_scope
    from backend.database.models_store import ScheduleJobRow

    jid = (job_id or "").strip()
    if not jid:
        return None
    try:
        ensure_dashboard_db()
        with session_scope() as db:
            row = db.query(ScheduleJobRow).filter(ScheduleJobRow.id == jid).first()
            if row:
                try:
                    data = json.loads(row.payload_json or "{}")
                except json.JSONDecodeError:
                    data = {}
                if isinstance(data, dict) and data:
                    return data
    except Exception as exc:  # noqa: BLE001
        logger.debug("schedule_db_get_failed: %s", exc)

    file_data = _read_file(jid)
    if file_data:
        try:
            return save_job(file_data)
        except Exception as exc:  # noqa: BLE001
            logger.warning("schedule_migrate_failed: %s", exc)
            return file_data
    return None


def _migrate_all_files() -> None:
    if not SCHEDULE_DIR.is_dir():
        return
    for path in SCHEDULE_DIR.glob("*.json"):
        get_job(path.stem)


def list_jobs(*, client_id: str | None = None, target: str | None = None) -> list[dict[str, Any]]:
    from backend.database.db import ensure_dashboard_db, session_scope
    from backend.database.models_store import ScheduleJobRow

    _migrate_all_files()
    items: list[dict[str, Any]] = []
    try:
        ensure_dashboard_db()
        with session_scope() as db:
            q = db.query(ScheduleJobRow)
            if client_id:
                q = q.filter(ScheduleJobRow.client_id == client_id)
            rows = q.all()
            for row in rows:
                try:
                    data = json.loads(row.payload_json or "{}")
                except json.JSONDecodeError:
                    continue
                if not isinstance(data, dict):
                    continue
                if target and normalize_target(str(data.get("target") or "")) != normalize_target(
                    target
                ):
                    continue
                items.append(data)
    except Exception as exc:  # noqa: BLE001
        logger.warning("schedule_list_db_failed: %s", exc)
        SCHEDULE_DIR.mkdir(parents=True, exist_ok=True)
        for path in sorted(SCHEDULE_DIR.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            if not isinstance(data, dict):
                continue
            if client_id and data.get("client_id") != client_id:
                continue
            if target and normalize_target(str(data.get("target") or "")) != normalize_target(
                target
            ):
                continue
            items.append(data)

    items.sort(key=lambda x: str(x.get("next_run_at") or ""))
    return items


def create_job(
    *,
    target: str,
    client_id: str = "default",
    job_type: str = "monitor",
    interval: str = "monthly",
    enabled: bool = True,
    scan_profile: str = "basic",
    risk_profile: str = "passive",
    interval_days: int | None = None,
    custom_tools: list[str] | None = None,
    chat_session_id: str = "",
) -> dict[str, Any]:
    jt = job_type if job_type in JOB_TYPES else "monitor"
    if interval_days is not None:
        try:
            days = max(1, min(365, int(interval_days)))
        except (TypeError, ValueError):
            days = 30
        interval_label = "custom"
    else:
        days = INTERVALS.get(interval, 30)
        interval_label = interval if interval in INTERVALS else "monthly"
    now = _now()
    tools = [str(t).strip() for t in (custom_tools or []) if str(t).strip()]
    job = {
        "id": uuid.uuid4().hex[:12],
        "target": normalize_target(target),
        "client_id": client_id or "default",
        "job_type": jt,
        "interval": interval_label,
        "interval_days": days,
        "enabled": bool(enabled),
        "scan_profile": scan_profile or "basic",
        "risk_profile": risk_profile or "passive",
        "custom_tools": tools[:80],
        "chat_session_id": str(chat_session_id or "")[:128],
        "created_at": _iso(now),
        "updated_at": _iso(now),
        "last_run_at": None,
        "next_run_at": _iso(now + timedelta(days=days)),
        "last_status": "idle",
        "last_error": "",
    }
    return save_job(job)


def delete_job(job_id: str) -> bool:
    from backend.database.db import ensure_dashboard_db, session_scope
    from backend.database.models_store import ScheduleJobRow

    jid = (job_id or "").strip()
    if not jid:
        return False
    deleted = False
    try:
        ensure_dashboard_db()
        with session_scope() as db:
            n = (
                db.query(ScheduleJobRow)
                .filter(ScheduleJobRow.id == jid)
                .delete(synchronize_session=False)
            )
            deleted = bool(n)
    except Exception as exc:  # noqa: BLE001
        logger.warning("schedule_db_delete_failed: %s", exc)

    path = _path(jid)
    if path.is_file():
        try:
            path.unlink()
            deleted = True
        except OSError:
            pass
    return deleted


def due_jobs(now: datetime | None = None) -> list[dict[str, Any]]:
    now = now or _now()
    out: list[dict[str, Any]] = []
    for job in list_jobs():
        if not job.get("enabled"):
            continue
        if str(job.get("last_status") or "") == "running":
            continue
        nxt = _parse_iso(job.get("next_run_at"))
        if nxt and nxt <= now:
            out.append(job)
    return out


def advance_job(job: dict[str, Any], *, status: str, error: str = "") -> dict[str, Any]:
    now = _now()
    days = int(job.get("interval_days") or INTERVALS.get(str(job.get("interval")), 30))
    job["last_run_at"] = _iso(now)
    job["next_run_at"] = _iso(now + timedelta(days=days))
    job["last_status"] = status
    job["last_error"] = (error or "")[:500]
    job["updated_at"] = _iso(now)
    return save_job(job)


def run_job_now(job_id: str) -> dict[str, Any]:
    """Força execução imediata (via runner)."""
    from backend.schedule.runner import execute_job

    job = get_job(job_id)
    if not job:
        raise FileNotFoundError(f"Job '{job_id}' não encontrado.")
    return execute_job(job)
