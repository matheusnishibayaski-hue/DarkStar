"""API de agendamento de scans recorrentes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from backend.schedule.store import (
    create_job,
    delete_job,
    get_job,
    list_jobs,
    run_job_now,
    save_job,
)
from backend.security.scope import validate_autonomous_target

router = APIRouter(prefix="/api", tags=["schedule"])


class ScheduleCreateRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=253)
    client_id: str = Field(default="default", max_length=64)
    job_type: str = Field(default="monitor", max_length=32)
    interval: str = Field(default="monthly", max_length=32)
    enabled: bool = True
    scan_profile: str = Field(default="basic", max_length=32)
    risk_profile: str = Field(default="passive", max_length=32)


class SchedulePatchRequest(BaseModel):
    enabled: bool | None = None
    interval: str | None = Field(default=None, max_length=32)
    job_type: str | None = Field(default=None, max_length=32)
    scan_profile: str | None = Field(default=None, max_length=32)
    risk_profile: str | None = Field(default=None, max_length=32)


@router.get("/schedules")
def api_schedules_list(
    client_id: str | None = Query(default=None, max_length=64),
    target: str | None = Query(default=None, max_length=253),
):
    return {"jobs": list_jobs(client_id=client_id, target=target)}


@router.post("/schedules")
def api_schedules_create(req: ScheduleCreateRequest):
    ok, err = validate_autonomous_target(req.target)
    if not ok:
        raise HTTPException(status_code=403, detail=err)
    job = create_job(
        target=req.target,
        client_id=req.client_id,
        job_type=req.job_type,
        interval=req.interval,
        enabled=req.enabled,
        scan_profile=req.scan_profile,
        risk_profile=req.risk_profile,
    )
    return job


@router.get("/schedules/{job_id}")
def api_schedules_get(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job não encontrado")
    return job


@router.patch("/schedules/{job_id}")
def api_schedules_patch(job_id: str, req: SchedulePatchRequest):
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job não encontrado")
    if req.enabled is not None:
        job["enabled"] = req.enabled
    if req.interval is not None:
        from backend.schedule.store import INTERVALS

        job["interval"] = req.interval if req.interval in INTERVALS else job["interval"]
        job["interval_days"] = INTERVALS.get(job["interval"], 30)
    if req.job_type is not None:
        job["job_type"] = req.job_type
    if req.scan_profile is not None:
        job["scan_profile"] = req.scan_profile
    if req.risk_profile is not None:
        job["risk_profile"] = req.risk_profile
    return save_job(job)


@router.delete("/schedules/{job_id}")
def api_schedules_delete(job_id: str):
    if not delete_job(job_id):
        raise HTTPException(status_code=404, detail="Job não encontrado")
    return {"deleted": True, "id": job_id}


@router.post("/schedules/{job_id}/run")
def api_schedules_run(job_id: str):
    try:
        return run_job_now(job_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
