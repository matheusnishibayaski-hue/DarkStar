"""API de remediação inteligente (planos IA + tracking)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.ai.remediation_ai import (
    remediation_advisor,
    remediation_tracker,
    remediation_verifier,
)

router = APIRouter(prefix="/api/remediation", tags=["remediation"])


class GenerateRequest(BaseModel):
    finding: dict[str, Any]
    code_context: str = ""
    project_info: dict[str, Any] | None = None


class VerifyRequest(BaseModel):
    original_code: str = ""
    fixed_code: str = ""
    test_command: str = ""
    language: str = "python"


class TrackRequest(BaseModel):
    finding_id: str = Field(..., min_length=1, max_length=128)
    remediation_plan: dict[str, Any] = Field(default_factory=dict)
    status: str = Field(default="in_progress", max_length=32)


class TrackUpdateRequest(BaseModel):
    status: str | None = Field(default=None, max_length=32)
    steps_completed: int | None = Field(default=None, ge=0, le=100)
    notes: str | None = Field(default=None, max_length=2000)


@router.post("/generate")
def generate_remediation(req: GenerateRequest):
    if not isinstance(req.finding, dict) or not req.finding:
        raise HTTPException(status_code=400, detail="finding required")
    plan = remediation_advisor.generate_remediation(
        finding=req.finding,
        code_context=req.code_context or "",
        project_info=req.project_info or {},
    )
    return {"status": "generated", "plan": plan.to_dict()}


@router.post("/verify")
def verify_remediation(req: VerifyRequest):
    results = remediation_verifier.verify_fix(
        original_code=req.original_code,
        fixed_code=req.fixed_code,
        test_command=req.test_command,
        language=req.language,
    )
    return {
        "status": "verified" if results.get("syntax_valid") else "failed",
        "results": results,
    }


@router.post("/track")
def track_remediation(req: TrackRequest):
    entry = remediation_tracker.track(
        finding_id=req.finding_id,
        remediation_plan=req.remediation_plan,
        status=req.status or "in_progress",
    )
    return {
        "status": "tracked",
        "finding_id": req.finding_id,
        "remediation_status": entry.get("status"),
    }


@router.patch("/track/{finding_id}")
def update_remediation_status(finding_id: str, req: TrackUpdateRequest):
    entry = remediation_tracker.update(
        finding_id,
        status=req.status,
        steps_completed=req.steps_completed,
        notes=req.notes,
    )
    if not entry:
        raise HTTPException(status_code=404, detail="finding not tracked")
    return {
        "status": "updated",
        "finding_id": finding_id,
        "current_status": entry.get("status"),
        "steps_completed": entry.get("steps_completed"),
    }


@router.get("/stats")
def remediation_statistics():
    return {"status": "ok", "statistics": remediation_tracker.stats()}


@router.get("/alternatives/{finding_id}")
def get_alternative_approaches(finding_id: str):
    raise HTTPException(
        status_code=501,
        detail="Multiple approaches not implemented in MVP",
    )
