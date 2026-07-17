"""Rotas para listar e baixar artefatos do volume de outputs."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from backend.config import MAX_FILE_DOWNLOAD_BYTES
from backend.executor.files_store import (
    guess_media_type,
    is_allowed_extension,
    list_output_files,
    resolve_output_file,
)

router = APIRouter(prefix="/api", tags=["files"])


@router.get("/files")
def api_files_list():
    return {"files": list_output_files(), "root": "/tools/output"}


@router.delete("/files/{file_path:path}")
def api_files_delete(file_path: str):
    from backend.executor.data_cleanup import delete_output_file

    if not delete_output_file(file_path):
        raise HTTPException(status_code=404, detail="Arquivo não encontrado.")
    return {"deleted": True, "file": file_path}


@router.get("/files/{file_path:path}")
def api_files_download(file_path: str):
    path = resolve_output_file(file_path)
    if path is None:
        raise HTTPException(status_code=400, detail="Caminho inválido.")
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Arquivo não encontrado.")
    if not is_allowed_extension(path):
        raise HTTPException(status_code=403, detail="Tipo de arquivo não permitido.")

    size = path.stat().st_size
    if size > MAX_FILE_DOWNLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Arquivo excede o limite de download ({MAX_FILE_DOWNLOAD_BYTES // (1024 * 1024)} MB).",
        )

    return FileResponse(
        path,
        media_type=guess_media_type(path),
        filename=path.name,
    )
