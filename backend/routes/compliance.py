"""Rotas de compliance indicativo — `/api/compliance/*`."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from backend.compliance.frameworks import get_framework, list_frameworks
from backend.compliance.reporter import generate_compliance_report
from backend.config import COMPLIANCE_ENABLED

router = APIRouter(prefix="/api/compliance", tags=["compliance"])


class ComplianceReportRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=256)
    frameworks: list[str] = Field(default_factory=lambda: ["LGPD"])
    source: str = Field(default="surface")


def _ensure_enabled() -> None:
    if not COMPLIANCE_ENABLED:
        raise HTTPException(
            status_code=404,
            detail="Compliance desabilitado (COMPLIANCE_ENABLED=false).",
        )


@router.get("/frameworks")
def api_frameworks():
    _ensure_enabled()
    return {"frameworks": list_frameworks()}


@router.post("/report")
def api_report(body: ComplianceReportRequest):
    _ensure_enabled()
    if body.source != "surface":
        raise HTTPException(status_code=400, detail="source suportado: surface")
    fws: list[str] = []
    for fw in body.frameworks or ["LGPD"]:
        if not get_framework(fw):
            raise HTTPException(status_code=400, detail=f"Framework desconhecido: {fw}")
        fws.append(fw)
    try:
        return generate_compliance_report(body.target.strip(), fws)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/report/{target}")
def api_report_get(target: str, format: str = "json", frameworks: str = "LGPD"):
    _ensure_enabled()
    fws = [f.strip() for f in frameworks.split(",") if f.strip()]
    for fw in fws:
        if not get_framework(fw):
            raise HTTPException(status_code=400, detail=f"Framework desconhecido: {fw}")
    try:
        report = generate_compliance_report(target, fws or ["LGPD"])
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    fmt = (format or "json").lower()
    if fmt == "md":
        return PlainTextResponse(report.get("report_md") or "", media_type="text/markdown")
    if fmt == "json":
        payload = report
        return payload
    raise HTTPException(status_code=400, detail="format: json|md")
