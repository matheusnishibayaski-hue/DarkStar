"""Jobs de recorrência em backend/schedules/*.json."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from backend.config import SCHEDULE_DIR
from backend.executor.recon_db import normalize_target

JOB_TYPES = frozenset({"monitor", "full", "remind"})
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


def list_jobs(*, client_id: str | None = None, target: str | None = None) -> list[dict[str, Any]]:
    SCHEDULE_DIR.mkdir(parents=True, exist_ok=True)
    items: list[dict[str, Any]] = []
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


def get_job(job_id: str) -> dict[str, Any] | None:
    path = _path(job_id)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


def save_job(data: dict[str, Any]) -> dict[str, Any]:
    SCHEDULE_DIR.mkdir(parents=True, exist_ok=True)
    job_id = str(data.get("id") or "")
    path = _path(job_id)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return data


def create_job(
    *,
    target: str,
    client_id: str = "default",
    job_type: str = "monitor",
    interval: str = "monthly",
    enabled: bool = True,
    scan_profile: str = "basic",
    risk_profile: str = "passive",
) -> dict[str, Any]:
    jt = job_type if job_type in JOB_TYPES else "monitor"
    days = INTERVALS.get(interval, 30)
    now = _now()
    job = {
        "id": uuid.uuid4().hex[:12],
        "target": normalize_target(target),
        "client_id": client_id or "default",
        "job_type": jt,
        "interval": interval if interval in INTERVALS else "monthly",
        "interval_days": days,
        "enabled": bool(enabled),
        "scan_profile": scan_profile or "basic",
        "risk_profile": risk_profile or "passive",
        "created_at": _iso(now),
        "updated_at": _iso(now),
        "last_run_at": None,
        "next_run_at": _iso(now + timedelta(days=days)),
        "last_status": "idle",
        "last_error": "",
    }
    return save_job(job)


def delete_job(job_id: str) -> bool:
    path = _path(job_id)
    if path.is_file():
        path.unlink()
        return True
    return False


def due_jobs(now: datetime | None = None) -> list[dict[str, Any]]:
    now = now or _now()
    out: list[dict[str, Any]] = []
    for job in list_jobs():
        if not job.get("enabled"):
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
        raise FileNotFoundError("Job não encontrado")
    return execute_job(job, force=True)
