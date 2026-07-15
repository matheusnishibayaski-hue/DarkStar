"""Rotas de playbooks pré-definidos."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from backend.playbooks.loader import list_playbooks, run_playbook
from backend.schemas import PlaybookRunRequest

router = APIRouter(prefix="/api", tags=["playbooks"])


@router.get("/playbooks")
def api_playbooks_list():
    return {"playbooks": list_playbooks()}


@router.post("/playbooks/{playbook_id}/run")
def api_playbook_run(playbook_id: str, req: PlaybookRunRequest):
    if not playbook_id or len(playbook_id) > 64:
        raise HTTPException(status_code=400, detail="ID de playbook inválido.")
    try:
        return run_playbook(playbook_id, req.target.strip(), mission_id=req.mission_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e)) from e
