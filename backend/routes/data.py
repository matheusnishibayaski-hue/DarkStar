"""Rotas para listar e excluir dados gerados automaticamente."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from backend.executor.data_cleanup import (
    PURGE_CATEGORIES,
    delete_execution_log,
    delete_logs_for_session,
    delete_output_file,
    delete_recon,
    delete_surface,
    purge_audit,
    purge_categories,
    storage_summary,
)

router = APIRouter(prefix="/api/data", tags=["data"])


class PurgeRequest(BaseModel):
    categories: list[str] = Field(..., min_length=1, max_length=16)
    target: str | None = Field(default=None, max_length=128)
    confirm: bool = Field(default=False)


class SessionLogsDeleteRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=128)
    log_ids: list[str] = Field(default_factory=list, max_length=200)


@router.get("/summary")
def api_data_summary():
    return storage_summary()


@router.get("/logs")
def api_data_logs_list(
    limit: int = Query(default=100, ge=1, le=500),
    session_id: str | None = Query(default=None, max_length=128),
):
    from backend.executor.logs import list_execution_logs

    return {"logs": list_execution_logs(limit=limit, session_id=session_id or None)}


@router.post("/logs/session")
def api_delete_session_logs(req: SessionLogsDeleteRequest):
    result = delete_logs_for_session(req.session_id, extra_log_ids=req.log_ids)
    return result


@router.post("/purge")
def api_data_purge(req: PurgeRequest):
    if not req.confirm:
        raise HTTPException(
            status_code=400,
            detail="Envie confirm=true para executar a exclusão.",
        )
    invalid = [c for c in req.categories if c.strip().lower() not in PURGE_CATEGORIES]
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Categorias inválidas: {', '.join(invalid)}. Use: {', '.join(sorted(PURGE_CATEGORIES))}",
        )
    if req.target and (".." in req.target or len(req.target) > 128):
        raise HTTPException(status_code=400, detail="Alvo inválido.")
    removed = purge_categories(req.categories, target=req.target)
    return {"removed": removed, "summary": storage_summary()}


@router.delete("/logs/{log_id}")
def api_delete_log(log_id: str):
    result = delete_execution_log(log_id)
    if not result.get("ok"):
        raise HTTPException(status_code=404, detail="Log não encontrado.")
    return {"deleted": True, "log_id": log_id, **result}


@router.delete("/recon/{target}")
def api_delete_recon(target: str):
    if not delete_recon(target):
        raise HTTPException(status_code=404, detail="Recon não encontrado para este alvo.")
    return {"deleted": True, "target": target}


@router.delete("/surface/{target}")
def api_delete_surface(target: str):
    if not delete_surface(target):
        raise HTTPException(status_code=404, detail="Engajamento/surface não encontrado.")
    return {"deleted": True, "target": target}


@router.delete("/audit")
def api_delete_audit(
    date: str | None = Query(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$"),
    all: bool = Query(default=False, alias="all"),
):
    if not all and not date:
        raise HTTPException(
            status_code=400,
            detail="Use ?all=true para apagar toda a auditoria ou ?date=YYYY-MM-DD para um dia.",
        )
    removed = purge_audit(date=None if all else date)
    if removed == 0:
        raise HTTPException(status_code=404, detail="Nenhum registro de auditoria para excluir.")
    return {"deleted": removed, "date": date if not all else None}


@router.delete("/files/{file_path:path}")
def api_delete_file(file_path: str):
    if not delete_output_file(file_path):
        raise HTTPException(status_code=404, detail="Arquivo não encontrado.")
    return {"deleted": True, "file": file_path}
