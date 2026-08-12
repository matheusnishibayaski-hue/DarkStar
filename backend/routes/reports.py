"""API de PDFs de relatório persistidos no banco."""

from __future__ import annotations

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import Response

from backend.database.reports_store import (
    MAX_PDF_BYTES,
    delete_report,
    delete_reports_for_session,
    get_report,
    list_reports,
    save_report,
)

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("")
@router.get("/")
def api_list_reports(session_id: str | None = Query(default=None)):
    return {"reports": list_reports(session_id=session_id or None)}


@router.post("")
@router.post("/")
async def api_upload_report(
    file: UploadFile = File(...),
    session_id: str = Form(default=""),
    title: str = Form(default=""),
    file_name: str = Form(default=""),
):
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="empty file")
    if len(raw) > MAX_PDF_BYTES:
        raise HTTPException(status_code=413, detail=f"max {MAX_PDF_BYTES} bytes")
    name = (file_name or file.filename or "relatorio.pdf").strip()
    try:
        meta = save_report(
            content=raw,
            session_id=session_id,
            title=title or name,
            file_name=name,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "ok", "report": meta}


@router.delete("/session/{session_id}")
def api_delete_session_reports(session_id: str):
    n = delete_reports_for_session(session_id)
    return {"status": "ok", "deleted": n, "session_id": session_id}


@router.get("/{report_id}/meta")
def api_get_report_meta(report_id: str):
    row = get_report(report_id)
    if not row:
        raise HTTPException(status_code=404, detail="report not found")
    return {
        "id": row["id"],
        "sessionId": row["sessionId"],
        "title": row["title"],
        "fileName": row["fileName"],
        "createdAt": row["createdAt"],
        "size": row["size"],
    }


@router.get("/{report_id}")
def api_get_report(report_id: str):
    row = get_report(report_id)
    if not row:
        raise HTTPException(status_code=404, detail="report not found")
    return Response(
        content=row["content"],
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'inline; filename="{row["fileName"]}"',
            "X-Report-Id": row["id"],
            "X-Report-Title": row["title"][:200],
        },
    )


@router.delete("/{report_id}")
def api_delete_report(report_id: str):
    if not delete_report(report_id):
        raise HTTPException(status_code=404, detail="report not found")
    return {"status": "ok", "deleted": True, "id": report_id}
