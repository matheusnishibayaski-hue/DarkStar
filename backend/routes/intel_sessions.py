"""Intel e relatório agrupados por conversa (chat_session_id)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field

from backend.executor.session_intel import (
    aggregate_session_findings,
    backfill_session_findings_from_client,
    collect_session_tool_executions,
    delete_session_intel,
    ingest_extracted_findings,
    list_session_summaries,
    load_session,
    patch_session_finding,
    session_summary,
    set_session_label,
    sync_session_intel_from_logs,
)

router = APIRouter(prefix="/api/intel", tags=["intel"])


class SessionLabelPatch(BaseModel):
    label: str = Field(default="", max_length=120)


class SessionFindingPatch(BaseModel):
    surface_target: str = Field(..., min_length=1, max_length=253)
    status: str = Field(..., min_length=1, max_length=32)
    evidence: str = Field(default="", max_length=2000)


class SessionExecutionsSync(BaseModel):
    executions: list[dict] = Field(default_factory=list, max_length=40)


def _triage_response(session_id: str, executions: list[dict] | None = None) -> dict:
    """Fila de triagem sem reindexar logs nem gerar compliance (isso atrasava o modal)."""
    from backend.ai.fp_explain import (
        build_triage_queue,
        residual_risk_score,
        severity_counts,
    )

    if executions:
        backfill_session_findings_from_client(session_id, executions)
        try:
            ingest_extracted_findings(
                session_id, extra_executions=executions, skip_disk_logs=True
            )
        except Exception:  # noqa: BLE001
            pass
        findings = aggregate_session_findings(session_id, sync=False)
    else:
        findings = aggregate_session_findings(session_id, sync=False)
        try:
            ingest_extracted_findings(session_id)
            findings = aggregate_session_findings(session_id, sync=False)
        except Exception:  # noqa: BLE001
            pass
    queue = build_triage_queue(findings)
    return {
        "session_id": session_id,
        "queue": queue,
        "queue_count": len(queue),
        "findings_total": len(findings),
        "risk": residual_risk_score(findings),
        "severity": severity_counts(findings),
        "compliance": None,
    }


def _validate_session_id(session_id: str) -> str:
    if not session_id or len(session_id) > 128 or ".." in session_id:
        raise HTTPException(status_code=400, detail="ID de conversa inválido.")
    return session_id


@router.get("/sessions")
def api_intel_sessions_list():
    return {"sessions": list_session_summaries()}


@router.get("/sessions/{session_id}")
def api_intel_session_detail(session_id: str):
    session_id = _validate_session_id(session_id)
    meta = load_session(session_id)
    findings = aggregate_session_findings(session_id)
    return {
        **session_summary(session_id),
        "findings": findings,
        "has_intel": bool(meta or findings),
    }


@router.patch("/sessions/{session_id}")
def api_intel_session_patch(session_id: str, req: SessionLabelPatch):
    session_id = _validate_session_id(session_id)
    data = set_session_label(session_id, req.label)
    return {
        "session_id": session_id,
        "label": data.get("label") or "",
        "targets": data.get("targets") or [],
    }


@router.delete("/sessions/{session_id}")
def api_intel_session_delete(session_id: str):
    session_id = _validate_session_id(session_id)
    deleted = delete_session_intel(session_id)
    return {"deleted": deleted, "session_id": session_id}


@router.post("/sessions/{session_id}/sync-executions")
def api_intel_sync_executions(session_id: str, body: SessionExecutionsSync):
    session_id = _validate_session_id(session_id)
    sync_session_intel_from_logs(session_id)
    stats = backfill_session_findings_from_client(session_id, body.executions)
    extracted = 0
    try:
        extracted = ingest_extracted_findings(session_id, extra_executions=body.executions)
    except Exception:  # noqa: BLE001
        extracted = 0
    findings = aggregate_session_findings(session_id, sync=False)
    return {
        "session_id": session_id,
        **stats,
        "extracted": extracted,
        "findings_count": len(findings),
    }


@router.post("/sessions/{session_id}/findings/{finding_id}")
def api_intel_session_finding_patch(
    session_id: str,
    finding_id: str,
    req: SessionFindingPatch,
):
    session_id = _validate_session_id(session_id)
    if req.status not in {
        "candidate",
        "inconclusive",
        "confirmed",
        "false_positive",
        "discarded",
    }:
        raise HTTPException(status_code=400, detail="status inválido")
    finding = patch_session_finding(
        session_id,
        req.surface_target,
        finding_id,
        req.status,
        evidence=req.evidence,
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Achado não encontrado.")
    return finding


@router.get("/sessions/{session_id}/triage-queue")
def api_intel_triage_queue(session_id: str):
    """Fila de validação humana: pendentes + possíveis FPs, com explicação simples."""
    session_id = _validate_session_id(session_id)
    return _triage_response(session_id)


@router.post("/sessions/{session_id}/triage-queue")
def api_intel_triage_queue_post(session_id: str, body: SessionExecutionsSync):
    """Mesma fila, já ingestando as execuções do chat (uma ida só)."""
    session_id = _validate_session_id(session_id)
    return _triage_response(session_id, body.executions)


@router.get("/sessions/{session_id}/report")
def api_intel_session_report(
    session_id: str,
    format: str = Query(default="pdf", pattern="^pdf$"),
):
    session_id = _validate_session_id(session_id)
    meta = load_session(session_id)
    findings = aggregate_session_findings(session_id)
    execs = collect_session_tool_executions(session_id)
    if not meta and not findings and not execs:
        raise HTTPException(
            status_code=404,
            detail="Nenhum dado de pentest para esta conversa.",
        )

    from backend.ai.pdf_report import generate_report_pdf

    display = str(meta.get("label") or "").strip() or "Conversa"
    title = f"Relatório — {display}"
    raw = generate_report_pdf(
        session_id=session_id,
        title=title,
        tool_executions=execs or None,
    )
    fname = f"relatorio-{session_id[:8]}.pdf"
    return Response(
        content=raw,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )
