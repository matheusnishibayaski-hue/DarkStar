"""Rotas de auditoria — trilha imutável de execuções."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from backend.security.audit import list_events

router = APIRouter(prefix="/api", tags=["audit"])


@router.delete("/audit")
def api_audit_delete(
    all: bool = Query(default=False, alias="all"),
    date: str | None = Query(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$"),
):
    from backend.executor.data_cleanup import purge_audit

    if not all and not date:
        raise HTTPException(
            status_code=400,
            detail="Use ?all=true ou ?date=YYYY-MM-DD",
        )
    removed = purge_audit(date=None if all else date)
    if removed == 0:
        raise HTTPException(status_code=404, detail="Nenhum registro de auditoria.")
    return {"deleted": removed}


@router.get("/audit")
def api_audit_list(
    limit: int = Query(100, ge=1, le=500),
    date: str | None = Query(None, pattern=r"^\d{4}-\d{2}-\d{2}$"),
):
    return {"events": list_events(limit=limit, date=date)}
