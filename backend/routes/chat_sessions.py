"""API de conversas do chat — persistência no banco."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from backend.database.chat_store import (
    delete_chat_session,
    get_chat_session,
    list_chat_sessions,
    migrate_chat_sessions,
    patch_chat_session,
    upsert_chat_session,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/chat-sessions", tags=["chat-sessions"])


class ChatSessionBody(BaseModel):
    id: str = Field(..., min_length=8, max_length=128)
    title: str = Field(default="novo chat", max_length=120)
    preferredTool: str = Field(default="auto", max_length=64)
    messages: list[dict[str, Any]] = Field(default_factory=list)
    createdAt: int | None = None
    updatedAt: int | None = None
    client_id: str = Field(default="", max_length=64)


class ChatSessionPatch(BaseModel):
    title: str | None = Field(default=None, max_length=120)
    preferredTool: str | None = Field(default=None, max_length=64)


class MigrateBody(BaseModel):
    sessions: list[dict[str, Any]] = Field(default_factory=list)


@router.get("")
@router.get("/")
def api_list_sessions(
    client_id: str | None = Query(default=None, max_length=64),
):
    return {
        "sessions": list_chat_sessions(
            include_messages=True, client_id=(client_id or "").strip() or None
        )
    }


@router.post("/migrate")
def api_migrate(body: MigrateBody):
    result = migrate_chat_sessions(body.sessions)
    return {"status": "ok", **result}


@router.post("")
@router.post("/")
def api_upsert_session(body: ChatSessionBody):
    try:
        data = upsert_chat_session(body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "ok", "session": data}


@router.get("/{session_id}")
def api_get_session(session_id: str):
    data = get_chat_session(session_id)
    if not data:
        raise HTTPException(status_code=404, detail="session not found")
    return data


@router.put("/{session_id}")
def api_put_session(session_id: str, body: ChatSessionBody):
    if body.id != session_id:
        raise HTTPException(status_code=400, detail="id mismatch")
    try:
        data = upsert_chat_session(body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("chat_session_put_failed id=%s", session_id)
        raise HTTPException(status_code=500, detail=f"persist failed: {exc}") from exc
    return {"status": "ok", "session": data}


@router.patch("/{session_id}")
def api_patch_session(session_id: str, body: ChatSessionPatch):
    data = patch_chat_session(
        session_id,
        title=body.title,
        preferredTool=body.preferredTool,
    )
    if not data:
        raise HTTPException(status_code=404, detail="session not found")
    return {"status": "ok", "session": data}


@router.delete("/{session_id}")
def api_delete_session(session_id: str):
    """Idempotente: 200 mesmo se a conversa já não existir no banco."""
    try:
        delete_chat_session(session_id)
    except Exception as exc:  # noqa: BLE001
        logger.exception("chat_session_delete_failed id=%s", session_id)
        raise HTTPException(status_code=500, detail=f"delete failed: {exc}") from exc
    # Cascata best-effort: PDFs e intel da conversa
    try:
        from backend.database.reports_store import delete_reports_for_session

        delete_reports_for_session(session_id)
    except Exception:  # noqa: BLE001
        logger.debug("chat_delete_reports_skipped", exc_info=True)
    try:
        from backend.executor.session_intel import delete_session_intel

        delete_session_intel(session_id)
    except Exception:  # noqa: BLE001
        logger.debug("chat_delete_intel_skipped", exc_info=True)
    return {"status": "ok", "deleted": True, "session_id": session_id}
