"""Modelos SQLAlchemy — PDFs, intel de sessão, clientes e agendas."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, Integer, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.models_intelligence import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class StoredReport(Base):
    """PDF de relatório baixado no shell."""

    __tablename__ = "stored_reports"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(128), default="", nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    file_name: Mapped[str] = mapped_column(String(260), default="", nullable=False)
    size: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at_ms: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False, index=True)
    content: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)


class IntelSessionRow(Base):
    """Intel da conversa (antes: backend/intel_sessions/*.json)."""

    __tablename__ = "intel_sessions"

    session_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    payload_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False, index=True
    )


class ClientRecord(Base):
    """Meta do workspace cliente (antes: backend/clients/*/meta.json)."""

    __tablename__ = "client_records"

    client_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    payload_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )


class ScheduleJobRow(Base):
    """Job de agenda (antes: backend/schedules/*.json)."""

    __tablename__ = "schedule_jobs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    client_id: Mapped[str] = mapped_column(
        String(64), default="default", nullable=False, index=True
    )
    target: Mapped[str] = mapped_column(String(256), default="", nullable=False, index=True)
    next_run_at: Mapped[str] = mapped_column(String(64), default="", nullable=False, index=True)
    payload_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )


class FpSuppressPattern(Base):
    """Padrão marcado como falso positivo (antes: backend/fp_suppress.json)."""

    __tablename__ = "fp_suppress_patterns"

    pattern_key: Mapped[str] = mapped_column(String(256), primary_key=True)
    finding_type: Mapped[str] = mapped_column(String(64), default="title", nullable=False)
    title: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    hits: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    targets_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )
