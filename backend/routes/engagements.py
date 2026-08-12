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
    client_id: str = Field(default="", max_length=64)
    scope_notes: str = Field(default="", max_length=4000)
    brand_name: str = Field(default="", max_length=120)


class EngagementPatchRequest(BaseModel):
    objective: str | None = Field(default=None, max_length=2000)
    risk_profile: str | None = Field(default=None, max_length=32)
    client: str | None = Field(default=None, max_length=200)
    client_id: str | None = Field(default=None, max_length=64)
    scope_notes: str | None = Field(default=None, max_length=4000)
    brand_name: str | None = Field(default=None, max_length=120)
    label: str | None = Field(default=None, max_length=120)
    lifecycle: str | None = Field(default=None, max_length=32)


class ScannerImportRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=5_000_000)
    format: str = Field(default="auto", max_length=32)


_LIFECYCLES = frozenset({"prospect", "active", "paused", "closed"})


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
def api_surface_list(
    client_id: str | None = Query(default=None, max_length=64),
):
    from backend.clients.runtime import get_active_client_id

    cid = (client_id or "").strip() or None
    # Sem filtro explícito: não força active (evita esconder legado)
    return {
        "targets": list_surface_summaries(client_id=cid),
        "active_client_id": get_active_client_id(),
        "filter_client_id": cid,
    }


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
    from backend.clients.runtime import get_active_client_id
    from backend.clients.store import ensure_default_client, normalize_client_id

    _ensure_scope(req.target)
    ensure_default_client()
    profile = normalize_risk_profile(req.risk_profile or RISK_PROFILE)
    cid = normalize_client_id(req.client_id or get_active_client_id() or "default")
    data = get_or_create_surface(
        req.target,
        objective=req.objective,
        risk_profile=profile,
        mission_id=req.mission_id,
        client=req.client,
        client_id=cid,
        scope_notes=req.scope_notes,
        brand_name=req.brand_name or REPORT_BRAND_NAME,
    )
    return {
        "target": data.get("target"),
        "phase": data.get("phase"),
        "risk_profile": data.get("risk_profile"),
        "client": data.get("client"),
        "client_id": data.get("client_id"),
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
    if req.client_id is not None:
        from backend.clients.store import normalize_client_id

        data["client_id"] = normalize_client_id(req.client_id)
    if req.scope_notes is not None:
        data["scope_notes"] = req.scope_notes
    if req.brand_name is not None:
        data["brand_name"] = req.brand_name or REPORT_BRAND_NAME
    if req.label is not None:
        data["label"] = req.label.strip()[:120]
    if req.lifecycle is not None:
        life = req.lifecycle.strip().lower()
        if life not in _LIFECYCLES:
            raise HTTPException(
                status_code=400,
                detail=f"lifecycle inválido. Use: {', '.join(sorted(_LIFECYCLES))}",
            )
        data["lifecycle"] = life
    save_surface(target, data)
    return {
        "target": normalize_target(target),
        "label": data.get("label"),
        "client": data.get("client"),
        "client_id": data.get("client_id"),
        "lifecycle": data.get("lifecycle"),
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
        "client_id": data.get("client_id"),
        "lifecycle": data.get("lifecycle") or "active",
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
    """Congela findings confirmados + superfície como baseline do próximo reteste."""
    if not load_surface(target):
        raise HTTPException(status_code=404, detail="Engajamento não encontrado.")
    from backend.ai.delta import snapshot_surface_baseline

    snap = snapshot_surface_baseline(target)
    return {
        "target": normalize_target(target),
        "baseline_count": snap.get("baseline_count", 0),
        "baseline": snap.get("findings") or [],
        "baseline_surface": snap.get("surface") or {},
        "baseline_at": snap.get("baseline_at"),
    }


@router.get("/engagements/{target}/report")
def api_engagement_report(
    target: str,
    format: str = Query(default="pdf", pattern="^(pdf|md|html|zip)$"),
    regenerate: bool = Query(default=False),
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

        raw = generate_report_pdf(
            surface_target=target,
            title=title,
            regenerate_executive=regenerate,
        )
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
    from backend.ai.risk_history import load_risk_history, record_risk_snapshot
    from backend.ai.risk_score import risk_score_for_target

    risk = risk_score_for_target(target)
    record_risk_snapshot(target, risk, source="api")
    return {**risk, "history": load_risk_history(target, limit=60)}


@router.post("/engagements/{target}/import")
def api_engagement_import(target: str, req: ScannerImportRequest):
    """Import Nuclei JSONL ou Nessus CSV para o Attack Surface."""
    _ensure_scope(target)
    if not load_surface(target):
        get_or_create_surface(target)
    from backend.ai.scanner_import import import_scanner_payload

    try:
        return import_scanner_payload(target, req.content, format=req.format)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


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
    auto_baseline: bool | None = Query(default=None),
):
    """Roda o pipeline de PoC + re-verificação e fecha findings para relatório."""
    from backend.ai.risk_history import previous_score, record_risk_snapshot
    from backend.ai.risk_score import risk_score_for_target
    from backend.ai.verify import run_verification_pipeline
    from backend.alerts.webhook import maybe_alert_delta
    from backend.ai.delta import compute_delta
    from backend.config import AUTO_BASELINE_AFTER_VERIFY

    _ensure_scope(target)
    if not load_surface(target):
        raise HTTPException(status_code=404, detail="Engajamento não encontrado.")
    result = run_verification_pipeline(
        target, max_findings=max_findings or VERIFY_MAX_FINDINGS
    )
    data = load_surface(target)
    risk = risk_score_for_target(target)
    prev = previous_score(target)
    record_risk_snapshot(target, risk, source="verify")
    # Delta/alertas ANTES do baseline automático (senão o diff zera)
    delta = compute_delta(target)
    alerts = maybe_alert_delta(target, delta=delta, risk=risk, previous_score=prev)

    do_baseline = (
        AUTO_BASELINE_AFTER_VERIFY if auto_baseline is None else auto_baseline
    )
    baseline_info = None
    if do_baseline:
        from backend.ai.delta import snapshot_surface_baseline

        baseline_info = snapshot_surface_baseline(target)

    return {
        "target": normalize_target(target),
        "confirmed": result.confirmed,
        "false_positive": result.false_positive,
        "discarded": result.discarded,
        "verify_commands_run": result.verify_commands_run,
        "summary": surface_summary(data) if data else {},
        "auto_baseline": baseline_info,
        "risk": risk,
        "alerts": alerts,
        "delta": {
            "has_baseline": delta.get("has_baseline"),
            "fixed": len(delta.get("fixed") or []),
            "new": len(delta.get("new") or []),
            "still_open": len(delta.get("still_open") or []),
        },
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
