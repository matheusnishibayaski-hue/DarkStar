"""Modelos SQLAlchemy — conversas do chat (mensagens no banco)."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.models_intelligence import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ChatSession(Base):
    """Conversa do shell (substitui localStorage darkstar-sessions)."""

    __tablename__ = "chat_sessions"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    title: Mapped[str] = mapped_column(String(120), default="novo chat", nullable=False)
    preferred_tool: Mapped[str] = mapped_column(String(64), default="auto", nullable=False)
    messages_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    created_at_ms: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False, index=True)
    updated_at_ms: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False, index=True)
    client_id: Mapped[str] = mapped_column(String(64), default="", nullable=False, index=True)
    db_updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )
