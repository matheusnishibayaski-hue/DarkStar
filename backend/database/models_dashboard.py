"""Modelos SQLAlchemy do dashboard / histórico de scans."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.models_intelligence import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanHistory(Base):
    """Registro de um scan (CLI, autonomous, scheduled)."""

    __tablename__ = "scan_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    target: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    risk_profile: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    scan_profile: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    vulnerability_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    medium: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    low: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    rounds: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="completed", nullable=False)
    error_message: Mapped[str] = mapped_column(Text, default="", nullable=False)
    scan_type: Mapped[str] = mapped_column(String(32), default="manual", nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False, index=True
    )


class VulnerabilityTracking(Base):
    """Tracking de vulnerabilidades recorrentes por alvo."""

    __tablename__ = "vulnerability_tracking"
    __table_args__ = (UniqueConstraint("vuln_key", name="uq_vuln_tracking_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vuln_key: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), default="", nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), default="unknown", nullable=False, index=True)
    target: Mapped[str] = mapped_column(String(256), default="", nullable=False, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    seen_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False)
    remediation: Mapped[str] = mapped_column(Text, default="", nullable=False)
