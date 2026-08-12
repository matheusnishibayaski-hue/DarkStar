"""Modelos SQLAlchemy do Intelligence Hub."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class PentestRecord(Base):
    """Snapshot de um engajamento/surface gravado no hub."""

    __tablename__ = "pentests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    industry: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tools_used: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    phase: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    summary_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    findings: Mapped[list[FindingHistory]] = relationship(
        "FindingHistory", back_populates="pentest", cascade="all, delete-orphan"
    )


class FindingHistory(Base):
    """Finding compacto associado a um pentest."""

    __tablename__ = "findings_history"
    __table_args__ = (Index("ix_findings_history_cve", "cve_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    pentest_id: Mapped[int] = mapped_column(ForeignKey("pentests.id", ondelete="CASCADE"))
    finding_key: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    cve_id: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    template_id: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="unknown", nullable=False)
    title: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    tool: Mapped[str] = mapped_column(String(64), default="", nullable=False)

    pentest: Mapped[PentestRecord] = relationship("PentestRecord", back_populates="findings")


class IndustryPattern(Base):
    """Padrão agregado (template/cve/título) visto ao longo do tempo."""

    __tablename__ = "industry_patterns"
    __table_args__ = (
        UniqueConstraint("industry", "pattern_key", name="uq_industry_pattern"),
        Index("ix_industry_patterns_freq", "frequency"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    industry: Mapped[str] = mapped_column(String(64), default="generic", nullable=False)
    pattern_key: Mapped[str] = mapped_column(String(256), nullable=False)
    finding_type: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    frequency: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class TargetIntelligence(Base):
    """Metadados / agregados por alvo."""

    __tablename__ = "target_intelligence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    industry: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    company_size: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    findings_aggregate: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    threat_model_json: Mapped[str] = mapped_column(Text, default="", nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class SimilarOverlapCache(Base):
    """Cache opcional de overlaps (não obrigatório para o hub funcionar)."""

    __tablename__ = "similar_overlap_cache"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_a: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    target_b: Mapped[str] = mapped_column(String(128), nullable=False)
    score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
