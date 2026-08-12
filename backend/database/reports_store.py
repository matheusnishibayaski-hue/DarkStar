"""CRUD de PDFs no banco."""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from backend.database.db import ensure_dashboard_db, session_scope

logger = logging.getLogger(__name__)
MAX_PDF_BYTES = 25 * 1024 * 1024


def _now_ms() -> int:
    return int(time.time() * 1000)


def save_report(
    *,
    content: bytes,
    session_id: str = "",
    title: str = "",
    file_name: str = "",
    report_id: str | None = None,
) -> dict[str, Any]:
    from backend.database.models_store import StoredReport

    if not content:
        raise ValueError("empty report")
    if len(content) > MAX_PDF_BYTES:
        raise ValueError(f"report too large (max {MAX_PDF_BYTES} bytes)")
    rid = (report_id or uuid.uuid4().hex)[:64]
    ensure_dashboard_db()
    with session_scope() as db:
        row = StoredReport(
            id=rid,
            session_id=str(session_id or "")[:128],
            title=str(title or "Relatório")[:200],
            file_name=str(file_name or "relatorio.pdf")[:260],
            size=len(content),
            created_at_ms=_now_ms(),
            content=content,
        )
        db.merge(row)
        db.flush()
        return {
            "id": row.id,
            "sessionId": row.session_id,
            "title": row.title,
            "fileName": row.file_name,
            "createdAt": row.created_at_ms,
            "size": row.size,
        }


def list_reports(*, session_id: str | None = None) -> list[dict[str, Any]]:
    from backend.database.models_store import StoredReport

    ensure_dashboard_db()
    with session_scope() as db:
        q = db.query(StoredReport)
        if session_id:
            q = q.filter(StoredReport.session_id == session_id)
        rows = q.order_by(StoredReport.created_at_ms.desc()).limit(500).all()
        return [
            {
                "id": r.id,
                "sessionId": r.session_id,
                "title": r.title,
                "fileName": r.file_name,
                "createdAt": r.created_at_ms,
                "size": r.size,
            }
            for r in rows
        ]


def get_report(report_id: str) -> dict[str, Any] | None:
    from backend.database.models_store import StoredReport

    rid = (report_id or "").strip()
    if not rid:
        return None
    ensure_dashboard_db()
    with session_scope() as db:
        row = db.query(StoredReport).filter(StoredReport.id == rid).first()
        if not row:
            return None
        return {
            "id": row.id,
            "sessionId": row.session_id,
            "title": row.title,
            "fileName": row.file_name,
            "createdAt": row.created_at_ms,
            "size": row.size,
            "content": row.content,
        }


def delete_report(report_id: str) -> bool:
    from backend.database.models_store import StoredReport

    rid = (report_id or "").strip()
    if not rid:
        return False
    ensure_dashboard_db()
    with session_scope() as db:
        n = (
            db.query(StoredReport)
            .filter(StoredReport.id == rid)
            .delete(synchronize_session=False)
        )
        return bool(n)


def delete_reports_for_session(session_id: str) -> int:
    from backend.database.models_store import StoredReport

    sid = (session_id or "").strip()
    if not sid:
        return 0
    ensure_dashboard_db()
    with session_scope() as db:
        return int(
            db.query(StoredReport)
            .filter(StoredReport.session_id == sid)
            .delete(synchronize_session=False)
            or 0
        )
