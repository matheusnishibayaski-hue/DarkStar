"""API de workspaces multi-cliente locais."""

from __future__ import annotations

from fastapi import APIRouter, File, Header, HTTPException, Query, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field

from backend.clients.backup import backup_client, restore_client, save_backup_file
from backend.clients.runtime import get_active_client_id, set_active_client_id
from backend.clients.store import (
    create_client,
    delete_client,
    ensure_default_client,
    get_client,
    list_clients,
    normalize_client_id,
    update_client,
)
from backend.executor.surface import list_surface_summaries

router = APIRouter(prefix="/api", tags=["clients"])


class ClientCreateRequest(BaseModel):
    client_id: str = Field(..., min_length=1, max_length=64)
    display_name: str = Field(default="", max_length=200)
    consulting_name: str = Field(default="", max_length=120)
    consulting_logo_path: str = Field(default="", max_length=500)
    consulting_color: str = Field(default="", max_length=32)
    consulting_footer: str = Field(default="", max_length=500)


class ClientPatchRequest(BaseModel):
    display_name: str | None = Field(default=None, max_length=200)
    consulting_name: str | None = Field(default=None, max_length=120)
    consulting_logo_path: str | None = Field(default=None, max_length=500)
    consulting_color: str | None = Field(default=None, max_length=32)
    consulting_footer: str | None = Field(default=None, max_length=500)


@router.get("/clients")
def api_clients_list():
    ensure_default_client()
    return {
        "clients": list_clients(),
        "active_client_id": get_active_client_id(),
    }


@router.get("/clients/_active")
def api_clients_active(
    x_client_id: str | None = Header(default=None, alias="X-Client-Id"),
):
    """Retorna cliente ativo (runtime) ou header X-Client-Id se válido."""
    ensure_default_client()
    if x_client_id:
        cid = normalize_client_id(x_client_id)
        if get_client(cid):
            return {
                "active_client_id": cid,
                "source": "header",
                "client": get_client(cid),
            }
    active = get_active_client_id()
    return {
        "active_client_id": active,
        "source": "runtime",
        "client": get_client(active),
    }


@router.post("/clients")
def api_clients_create(req: ClientCreateRequest):
    try:
        data = create_client(
            req.client_id,
            display_name=req.display_name,
            consulting_name=req.consulting_name,
            consulting_logo_path=req.consulting_logo_path,
            consulting_color=req.consulting_color,
            consulting_footer=req.consulting_footer,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return data


@router.get("/clients/{client_id}")
def api_clients_get(client_id: str):
    ensure_default_client()
    data = get_client(client_id)
    if not data:
        raise HTTPException(status_code=404, detail="Cliente não encontrado.")
    targets = list_surface_summaries(client_id=normalize_client_id(client_id))
    return {**data, "targets_count": len(targets), "targets": targets}


@router.patch("/clients/{client_id}")
def api_clients_patch(client_id: str, req: ClientPatchRequest):
    try:
        data = update_client(
            client_id,
            display_name=req.display_name,
            consulting_name=req.consulting_name,
            consulting_logo_path=req.consulting_logo_path,
            consulting_color=req.consulting_color,
            consulting_footer=req.consulting_footer,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return data


@router.post("/clients/{client_id}/activate")
def api_clients_activate(client_id: str):
    ensure_default_client()
    cid = normalize_client_id(client_id)
    if cid != "default" and not get_client(cid):
        raise HTTPException(status_code=404, detail="Cliente não encontrado.")
    active = set_active_client_id(cid)
    return {"active_client_id": active, "client": get_client(active)}


@router.delete("/clients/{client_id}")
def api_clients_delete(
    client_id: str,
    purge_surfaces: bool = Query(
        default=False,
        description="Se true, apaga também os engajamentos/surfaces do cliente.",
    ),
):
    """Exclui workspace do cliente (não permite apagar `default`)."""
    try:
        return delete_client(client_id, purge_surfaces=purge_surfaces)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/clients/{client_id}/backup")
def api_clients_backup(
    client_id: str,
    save: bool = Query(default=False),
):
    """Download tar.gz do workspace (uso interno — não é portal do cliente)."""
    try:
        raw = backup_client(client_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    saved = save_backup_file(client_id) if save else None
    cid = normalize_client_id(client_id)
    headers = {
        "Content-Disposition": f'attachment; filename="{cid}-backup.tar.gz"',
    }
    if saved:
        headers["X-Backup-Path"] = saved
    return Response(content=raw, media_type="application/gzip", headers=headers)


@router.post("/clients/{client_id}/restore")
async def api_clients_restore(
    client_id: str,
    file: UploadFile = File(...),
    overwrite: bool = Query(default=False),
):
    raw = await file.read()
    if len(raw) > 80 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Backup muito grande (máx 80MB).")
    try:
        result = restore_client(raw, overwrite=overwrite)
    except FileExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    # Se o archive tiver outro client_id, respeita o do manifest
    return result
