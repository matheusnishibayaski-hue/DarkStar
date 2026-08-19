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
    ingest_assistant_findings,
    ingest_extracted_findings,
    list_session_summaries,
    load_session,
    merge_session_finding_fields,
    patch_session_finding,
    patch_session_findings_batch,
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
        build_triage_buckets,
        residual_risk_score,
        severity_counts,
    )

    if executions:
        backfill_session_findings_from_client(session_id, executions)
        try:
            ingest_extracted_findings(session_id, extra_executions=executions, skip_disk_logs=True)
        except Exception:  # noqa: BLE001
            pass
    else:
        try:
            ingest_extracted_findings(session_id)
        except Exception:  # noqa: BLE001
            pass

    try:
        ingest_assistant_findings(session_id)
    except Exception:  # noqa: BLE001
        pass

    findings = aggregate_session_findings(session_id, sync=False)
    buckets = build_triage_buckets(findings)
    queue = buckets["queue"]

    def _auto_row(item: dict, status: str) -> dict:
        from backend.ai.report_model import enrich_finding

        enriched = enrich_finding(item)
        return {
            "id": str(item.get("id") or ""),
            "status": status,
            "surface_target": item.get("surface_target") or item.get("host") or "_session",
            "title": item.get("title") or "",
            "severity": enriched.get("severity") or item.get("severity") or "info",
            "severity_label": enriched.get("severity_label") or "",
            "kind": enriched.get("kind") or "",
            "suggestion": (item.get("triage") or {}).get("suggestion"),
        }

    auto_confirmed = [_auto_row(x, "confirmed") for x in buckets["auto_confirmed"] if x.get("id")]
    auto_fp = [
        _auto_row(x, "false_positive") for x in buckets["auto_false_positive"] if x.get("id")
    ]
    auto_disc = [
        _auto_row(x, "discarded") for x in buckets.get("auto_discarded") or [] if x.get("id")
    ]

    # Uma gravação só; não apaga evidência original
    patch_rows = auto_confirmed + auto_fp + auto_disc
    autos_persisted = False
    if patch_rows:
        try:
            patch_session_findings_batch(session_id, patch_rows, preserve_evidence=True)
            autos_persisted = True
        except Exception:  # noqa: BLE001
            for row in patch_rows:
                try:
                    patch_session_finding(
                        session_id,
                        str(row.get("surface_target") or "_session"),
                        str(row["id"]),
                        str(row["status"]),
                        preserve_evidence=True,
                    )
                except Exception:  # noqa: BLE001
                    pass
            autos_persisted = True

    findings_after = (
        aggregate_session_findings(session_id, sync=False) if patch_rows else findings
    )
    return {
        "session_id": session_id,
        "queue": queue,
        "queue_count": len(queue),
        "auto_confirmed": auto_confirmed,
        "auto_false_positive": auto_fp,
        "auto_discarded": auto_disc,
        "auto_count": len(auto_confirmed) + len(auto_fp) + len(auto_disc),
        "autos_persisted": autos_persisted,
        "findings_total": len(findings_after),
        "risk": residual_risk_score(findings_after),
        "severity": severity_counts(findings_after),
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


@router.post("/sessions/{session_id}/findings/{finding_id}/ai-review")
def api_intel_finding_ai_review(session_id: str, finding_id: str):
    """Segunda opinião LLM — não altera o status do achado."""
    session_id = _validate_session_id(session_id)
    fid = str(finding_id or "").strip()
    if not fid or len(fid) > 160:
        raise HTTPException(status_code=400, detail="Achado inválido.")
    findings = aggregate_session_findings(session_id, sync=False)
    finding = next((f for f in findings if str(f.get("id")) == fid), None)
    if not finding:
        raise HTTPException(status_code=404, detail="Achado não encontrado.")
    from backend.ai.fp_ai_review import review_finding

    was_cached = (
        isinstance(finding.get("ai_review"), dict) and finding["ai_review"].get("source") == "llm"
    )
    review = review_finding(finding)
    if review.get("source") == "llm":
        merge_session_finding_fields(session_id, fid, {"ai_review": review})
    return {"finding_id": fid, "ai_review": review, "cached": was_cached}


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
