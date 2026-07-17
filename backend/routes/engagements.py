"""API do Attack Surface Graph, engajamentos, triagem e export de relatório."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

from backend.ai.phases import PHASES, PHASE_LABELS, normalize_risk_profile
from backend.config import REPORT_BRAND_NAME, RISK_PROFILE, VERIFY_MAX_FINDINGS
from backend.executor.recon_db import normalize_target
from backend.executor.surface import (
    get_or_create_surface,
    list_surface_summaries,
    load_surface,
    mark_finding_status,
    save_surface,
    surface_summary,
)
from backend.security.scope import validate_autonomous_target

router = APIRouter(prefix="/api", tags=["engagements"])


class EngagementCreateRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=253)
    objective: str = Field(default="", max_length=2000)
    risk_profile: str = Field(default="", max_length=32)
    mission_id: str = Field(default="", max_length=64)
    client: str = Field(default="", max_length=200)
    scope_notes: str = Field(default="", max_length=4000)
    brand_name: str = Field(default="", max_length=120)


class EngagementPatchRequest(BaseModel):
    objective: str | None = Field(default=None, max_length=2000)
    risk_profile: str | None = Field(default=None, max_length=32)
    client: str | None = Field(default=None, max_length=200)
    scope_notes: str | None = Field(default=None, max_length=4000)
    brand_name: str | None = Field(default=None, max_length=120)
    label: str | None = Field(default=None, max_length=120)


class PhasePatchRequest(BaseModel):
    phase: str = Field(..., min_length=1, max_length=32)


class FindingStatusRequest(BaseModel):
    status: str = Field(..., min_length=1, max_length=32)
    evidence: str = Field(default="", max_length=2000)


def _ensure_scope(target: str) -> None:
    ok, err = validate_autonomous_target(target)
    if not ok:
        raise HTTPException(status_code=403, detail=err)


@router.get("/surface")
def api_surface_list():
    return {"targets": list_surface_summaries()}


@router.get("/surface/{target}")
def api_surface_detail(target: str):
    if not target or len(target) > 128 or ".." in target:
        raise HTTPException(status_code=400, detail="Alvo inválido.")
    data = load_surface(target)
    if not data:
        raise HTTPException(status_code=404, detail="Nenhum Attack Surface para este alvo.")
    return data


@router.post("/engagements")
def api_engagement_create(req: EngagementCreateRequest):
    _ensure_scope(req.target)
    profile = normalize_risk_profile(req.risk_profile or RISK_PROFILE)
    data = get_or_create_surface(
        req.target,
        objective=req.objective,
        risk_profile=profile,
        mission_id=req.mission_id,
        client=req.client,
        scope_notes=req.scope_notes,
        brand_name=req.brand_name or REPORT_BRAND_NAME,
    )
    return {
        "target": data.get("target"),
        "phase": data.get("phase"),
        "risk_profile": data.get("risk_profile"),
        "client": data.get("client"),
        "scope_notes": data.get("scope_notes"),
        "brand_name": data.get("brand_name"),
        "summary": surface_summary(data),
        "phases": [{"id": p, "label": PHASE_LABELS[p]} for p in PHASES],
    }


@router.patch("/engagements/{target}")
def api_engagement_patch(target: str, req: EngagementPatchRequest):
    data = load_surface(target)
    if not data:
        raise HTTPException(status_code=404, detail="Engajamento não encontrado.")
    if req.objective is not None:
        data["objective"] = req.objective
    if req.risk_profile is not None:
        data["risk_profile"] = normalize_risk_profile(req.risk_profile)
    if req.client is not None:
        data["client"] = req.client
    if req.scope_notes is not None:
        data["scope_notes"] = req.scope_notes
    if req.brand_name is not None:
        data["brand_name"] = req.brand_name or REPORT_BRAND_NAME
    if req.label is not None:
        data["label"] = req.label.strip()[:120]
    save_surface(target, data)
    return {
        "target": normalize_target(target),
        "label": data.get("label"),
        "client": data.get("client"),
        "scope_notes": data.get("scope_notes"),
        "brand_name": data.get("brand_name"),
        "risk_profile": data.get("risk_profile"),
        "objective": data.get("objective"),
    }


@router.delete("/engagements/{target}")
def api_engagement_delete(target: str):
    from backend.executor.data_cleanup import delete_recon, delete_surface

    removed_surface = delete_surface(target)
    delete_recon(target)
    if not removed_surface:
        raise HTTPException(status_code=404, detail="Engajamento não encontrado.")
    return {"deleted": True, "target": target}


@router.get("/engagements/{target}")
def api_engagement_get(target: str):
    if not target or len(target) > 128 or ".." in target:
        raise HTTPException(status_code=400, detail="Alvo inválido.")
    data = load_surface(target)
    if not data:
        raise HTTPException(status_code=404, detail="Engajamento não encontrado.")
    from backend.ai.delta import compute_delta
    from backend.ai.verify import confidence_gate_buckets

    return {
        "target": data.get("target"),
        "objective": data.get("objective"),
        "phase": data.get("phase"),
        "phases_completed": data.get("phases_completed"),
        "risk_profile": data.get("risk_profile"),
        "mission_id": data.get("mission_id"),
        "client": data.get("client"),
        "scope_notes": data.get("scope_notes"),
        "brand_name": data.get("brand_name"),
        "summary": surface_summary(data),
        "gate": {
            k: [
                {
                    "id": f.get("id"),
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "status": f.get("status"),
                    "confidence": f.get("confidence"),
                }
                for f in v
            ]
            for k, v in confidence_gate_buckets(target).items()
        },
        "delta": compute_delta(target),
        "surface": data,
    }


@router.get("/engagements/{target}/triage")
def api_engagement_triage(target: str):
    """Painel de triagem: executive / human_queue / archive + risk score."""
    if not load_surface(target):
        raise HTTPException(status_code=404, detail="Engajamento não encontrado.")
    from backend.ai.chains import infer_attack_chains
    from backend.ai.risk_score import risk_score_for_target
    from backend.ai.verify import confidence_gate_buckets

    gate = confidence_gate_buckets(target)
    data = load_surface(target) or {}
    return {
        "target": normalize_target(target),
        "summary": surface_summary(data),
        "risk": risk_score_for_target(target),
        "chains": infer_attack_chains(data),
        "executive": gate["executive"],
        "human_queue": gate["human_queue"],
        "archive": gate["archive"],
    }


@router.get("/engagements/{target}/delta")
def api_engagement_delta(target: str):
    if not load_surface(target):
        raise HTTPException(status_code=404, detail="Engajamento não encontrado.")
    from backend.ai.delta import compute_delta

    return compute_delta(target)


@router.post("/engagements/{target}/baseline")
def api_engagement_baseline(target: str):
    """Congela confirmados atuais como baseline do próximo reteste."""
    if not load_surface(target):
        raise HTTPException(status_code=404, detail="Engajamento não encontrado.")
    from backend.ai.delta import snapshot_confirmed

    baseline = snapshot_confirmed(target)
    return {
        "target": normalize_target(target),
        "baseline_count": len(baseline),
        "baseline": baseline,
    }


@router.get("/engagements/{target}/report")
def api_engagement_report(
    target: str,
    format: str = Query(default="pdf", pattern="^(pdf|md|html|zip)$"),
):
    """Export do relatório — padrão PDF."""
    from fastapi.responses import Response

    data = load_surface(target)
    if not data:
        raise HTTPException(status_code=404, detail="Engajamento não encontrado.")

    display = str(data.get("label") or data.get("client") or target).strip()
    title = f"Relatório — {display}"
    history = [
        {
            "role": "user",
            "content": (
                f"[Engajamento] Alvo: {target}\n"
                f"Cliente: {data.get('client') or '—'}\n"
                f"Objetivo: {data.get('objective') or '—'}\n"
                f"Escopo: {data.get('scope_notes') or '—'}"
            ),
        },
        {
            "role": "assistant",
            "content": (
                f"Fase {data.get('phase')}. "
                f"{surface_summary(data).get('findings_confirmed', 0)} confirmado(s)."
            ),
        },
    ]

    if format == "pdf":
        from backend.ai.pdf_report import generate_report_pdf
        from backend.executor.recon_db import normalize_target as _nt

        raw = generate_report_pdf(surface_target=target, title=title)
        fname = f"{_nt(target)}-relatorio.pdf"
        return Response(
            content=raw,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )

    from backend.ai.report import generate_report, generate_report_html

    if format == "zip":
        from backend.ai.delivery import build_delivery_bundle
        from backend.executor.recon_db import normalize_target as _nt

        raw = build_delivery_bundle(target)
        fname = f"{_nt(target)}-delivery.zip"
        return Response(
            content=raw,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )
    if format == "html":
        body = generate_report_html(
            history, [], title=title, surface_target=target, snapshot_baseline=False
        )
        return HTMLResponse(content=body)
    md = generate_report(
        history, [], title=title, surface_target=target, snapshot_baseline=False
    )
    return PlainTextResponse(content=md, media_type="text/markdown; charset=utf-8")


@router.get("/engagements/{target}/risk")
def api_engagement_risk(target: str):
    if not load_surface(target):
        raise HTTPException(status_code=404, detail="Engajamento não encontrado.")
    from backend.ai.risk_score import risk_score_for_target

    return risk_score_for_target(target)


@router.patch("/engagements/{target}/phase")
def api_engagement_phase(target: str, req: PhasePatchRequest):
    if req.phase not in PHASES:
        raise HTTPException(status_code=400, detail=f"Fase inválida. Use: {', '.join(PHASES)}")
    data = load_surface(target)
    if not data:
        raise HTTPException(status_code=404, detail="Engajamento não encontrado.")
    data["phase"] = req.phase
    save_surface(target, data)
    return {"target": normalize_target(target), "phase": req.phase}


@router.post("/engagements/{target}/findings/{finding_id}")
def api_finding_status(target: str, finding_id: str, req: FindingStatusRequest):
    if req.status not in {
        "candidate",
        "inconclusive",
        "confirmed",
        "false_positive",
        "discarded",
    }:
        raise HTTPException(status_code=400, detail="status inválido")
    finding = mark_finding_status(
        target, finding_id, req.status, evidence=req.evidence
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding ou alvo não encontrado.")
    return finding


@router.post("/engagements/{target}/verify")
def api_engagement_verify(
    target: str,
    max_findings: int = Query(default=None, ge=1, le=80),
):
    """Roda o pipeline de PoC + re-verificação e fecha findings para relatório."""
    from backend.ai.verify import run_verification_pipeline

    _ensure_scope(target)
    if not load_surface(target):
        raise HTTPException(status_code=404, detail="Engajamento não encontrado.")
    result = run_verification_pipeline(
        target, max_findings=max_findings or VERIFY_MAX_FINDINGS
    )
    data = load_surface(target)
    return {
        "target": normalize_target(target),
        "confirmed": result.confirmed,
        "false_positive": result.false_positive,
        "discarded": result.discarded,
        "verify_commands_run": result.verify_commands_run,
        "summary": surface_summary(data) if data else {},
        "outcomes": [
            {
                "finding_id": o.finding_id,
                "title": o.title,
                "status": o.status,
                "confidence": o.confidence,
                "reason": o.reason,
                "pass": o.pass_number,
            }
            for o in result.outcomes
        ],
    }
