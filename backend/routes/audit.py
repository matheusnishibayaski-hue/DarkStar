"""Rotas de auditoria — trilha imutável de execuções."""

from __future__ import annotations

from fastapi import APIRouter, Query

from backend.security.audit import list_events

router = APIRouter(prefix="/api", tags=["audit"])


@router.get("/audit")
def api_audit_list(
    limit: int = Query(100, ge=1, le=500),
    date: str | None = Query(None, pattern=r"^\d{4}-\d{2}-\d{2}$"),
):
    return {"events": list_events(limit=limit, date=date)}
