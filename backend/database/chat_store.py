"""CRUD de conversas do chat no SQLAlchemy (Postgres ou SQLite)."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from backend.database.db import ensure_dashboard_db, session_scope

logger = logging.getLogger(__name__)


def _now_ms() -> int:
    return int(time.time() * 1000)


def _row_to_dict(row) -> dict[str, Any]:
    try:
        messages = json.loads(row.messages_json or "[]")
    except json.JSONDecodeError:
        messages = []
    if not isinstance(messages, list):
        messages = []
    return {
        "id": row.id,
        "title": row.title or "novo chat",
        "preferredTool": row.preferred_tool or "auto",
        "messages": messages,
        "createdAt": int(row.created_at_ms or 0),
        "updatedAt": int(row.updated_at_ms or 0),
        "client_id": row.client_id or "",
    }


def _row_client_id(row) -> str:
    return (getattr(row, "client_id", None) or "").strip() or "default"


def list_chat_sessions(
    *, include_messages: bool = True, client_id: str | None = None
) -> list[dict[str, Any]]:
    from backend.database.models_chat import ChatSession

    want = (client_id or "").strip()
    ensure_dashboard_db()
    with session_scope() as db:
        rows = db.query(ChatSession).order_by(ChatSession.updated_at_ms.desc()).all()
        out = []
        for row in rows:
            cid = _row_client_id(row)
            if want:
                if want == "default":
                    if cid not in {"", "default"}:
                        continue
                elif cid != want:
                    continue
            item = _row_to_dict(row)
            if not item.get("client_id"):
                item["client_id"] = "default"
            if not include_messages:
                item["messages"] = []
                item["message_count"] = len(json.loads(row.messages_json or "[]") or [])
            out.append(item)
        return out


def get_chat_session(session_id: str) -> dict[str, Any] | None:
    from backend.database.models_chat import ChatSession

    sid = (session_id or "").strip()
    if not sid:
        return None
    ensure_dashboard_db()
    with session_scope() as db:
        row = db.query(ChatSession).filter(ChatSession.id == sid).first()
        return _row_to_dict(row) if row else None


def upsert_chat_session(payload: dict[str, Any]) -> dict[str, Any]:
    """Cria ou atualiza conversa completa (mensagens inclusas)."""
    from backend.database.models_chat import ChatSession

    sid = str(payload.get("id") or "").strip()
    if not sid or len(sid) > 128:
        raise ValueError("invalid session id")

    messages = payload.get("messages")
    if not isinstance(messages, list):
        messages = []
    # Limite defensivo
    if len(messages) > 500:
        messages = messages[-500:]

    title = str(payload.get("title") or "novo chat")[:120]
    preferred = str(payload.get("preferredTool") or payload.get("preferred_tool") or "auto")[:64]
    created = int(payload.get("createdAt") or payload.get("created_at_ms") or _now_ms())
    updated = int(payload.get("updatedAt") or payload.get("updated_at_ms") or _now_ms())
    client_id = str(payload.get("client_id") or "")[:64] or "default"
    messages_json = json.dumps(messages, ensure_ascii=False)

    ensure_dashboard_db()
    with session_scope() as db:
        row = db.query(ChatSession).filter(ChatSession.id == sid).first()
        if row:
            row.title = title
            row.preferred_tool = preferred
            row.messages_json = messages_json
            row.updated_at_ms = updated
            if client_id:
                row.client_id = client_id
        else:
            row = ChatSession(
                id=sid,
                title=title,
                preferred_tool=preferred,
                messages_json=messages_json,
                created_at_ms=created,
                updated_at_ms=updated,
                client_id=client_id,
            )
            db.add(row)
        db.flush()
        return _row_to_dict(row)


def patch_chat_session(session_id: str, **fields: Any) -> dict[str, Any] | None:
    from backend.database.models_chat import ChatSession

    sid = (session_id or "").strip()
    if not sid:
        return None
    ensure_dashboard_db()
    with session_scope() as db:
        row = db.query(ChatSession).filter(ChatSession.id == sid).first()
        if not row:
            return None
        if "title" in fields and fields["title"] is not None:
            row.title = str(fields["title"])[:120] or "novo chat"
        if "preferredTool" in fields and fields["preferredTool"] is not None:
            row.preferred_tool = str(fields["preferredTool"])[:64] or "auto"
        if "preferred_tool" in fields and fields["preferred_tool"] is not None:
            row.preferred_tool = str(fields["preferred_tool"])[:64] or "auto"
        row.updated_at_ms = _now_ms()
        db.flush()
        return _row_to_dict(row)


def delete_chat_session(session_id: str) -> bool:
    from backend.database.models_chat import ChatSession

    sid = (session_id or "").strip()
    if not sid:
        return False
    ensure_dashboard_db()
    with session_scope() as db:
        n = (
            db.query(ChatSession)
            .filter(ChatSession.id == sid)
            .delete(synchronize_session=False)
        )
        return bool(n)


def migrate_chat_sessions(sessions: list[dict[str, Any]]) -> dict[str, Any]:
    """Importa lote (ex.: localStorage legado). Não apaga existentes sem match."""
    imported = 0
    skipped = 0
    errors = 0
    for item in sessions or []:
        if not isinstance(item, dict) or not item.get("id"):
            skipped += 1
            continue
        try:
            upsert_chat_session(item)
            imported += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning("chat_migrate_item_failed: %s", exc)
            errors += 1
    return {"imported": imported, "skipped": skipped, "errors": errors, "total": len(sessions or [])}
