"""Engine/sessão SQLAlchemy — Intelligence Hub + dashboard (Postgres ou SQLite)."""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import create_engine, func
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from backend.config import BASE_DIR, DATABASE_URL

logger = logging.getLogger(__name__)

_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None
_using_sqlite: bool = False
_dashboard_ready: bool = False

_SQLITE_PATH = BASE_DIR / "backend" / "data" / "dashboard.db"


def _sqlite_url() -> str:
    _SQLITE_PATH.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{_SQLITE_PATH.as_posix()}"


def resolve_database_url() -> str:
    """Postgres se DATABASE_URL set; senão SQLite local para dashboard."""
    use_postgres = bool(DATABASE_URL) and not _using_sqlite
    if not use_postgres:
        sqlite_url = _sqlite_url()
        return sqlite_url
    chosen_url = str(DATABASE_URL)
    return chosen_url


def using_sqlite_fallback() -> bool:
    return _using_sqlite or not bool(DATABASE_URL)


def get_engine() -> Engine:
    """Retorna engine singleton (Postgres ou SQLite fallback)."""
    global _engine, _SessionLocal, _using_sqlite
    if _engine is None:
        url = resolve_database_url()
        if url.startswith("sqlite"):
            _using_sqlite = True
            _engine = create_engine(
                url,
                connect_args={"check_same_thread": False},
            )
        else:
            try:
                if "psycopg2" in url:
                    import psycopg2  # noqa: F401
                candidate = create_engine(
                    url,
                    pool_pre_ping=True,
                    pool_size=5,
                    max_overflow=10,
                )
                from sqlalchemy import text

                with candidate.connect() as conn:
                    conn.execute(text("SELECT 1"))
                _engine = candidate
            except Exception as exc:  # noqa: BLE001
                logger.warning("postgres_unavailable_falling_back_sqlite: %s", exc)
                _using_sqlite = True
                _engine = create_engine(
                    _sqlite_url(),
                    connect_args={"check_same_thread": False},
                )
        _SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False)
    return _engine


def get_session() -> Session:
    get_engine()
    assert _SessionLocal is not None
    return _SessionLocal()


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """Context manager com commit/rollback."""
    session = get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db() -> None:
    """Cria tabelas Intelligence (se Postgres) + dashboard + chat."""
    # Import models so metadata is populated
    from backend.database import models_chat as _mc  # noqa: F401
    from backend.database import models_dashboard as _md  # noqa: F401
    from backend.database import models_store as _ms  # noqa: F401
    from backend.database.models_intelligence import Base

    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    logger.info("database_initialized sqlite_fallback=%s", using_sqlite_fallback())


def _ensure_scan_history_columns() -> None:
    """Migração leve: adiciona chat_session_id se a tabela já existia."""
    from sqlalchemy import inspect, text

    try:
        engine = get_engine()
        insp = inspect(engine)
        if "scan_history" not in insp.get_table_names():
            return
        cols = {c["name"] for c in insp.get_columns("scan_history")}
        if "chat_session_id" in cols:
            return
        with engine.begin() as conn:
            conn.execute(
                text(
                    "ALTER TABLE scan_history ADD COLUMN chat_session_id "
                    "VARCHAR(128) NOT NULL DEFAULT ''"
                )
            )
        logger.info("scan_history_added_chat_session_id")
    except Exception as exc:  # noqa: BLE001
        logger.warning("scan_history_migrate_failed: %s", exc)


def ensure_dashboard_db() -> None:
    """Garante tabelas do dashboard uma vez (evita create_all em todo request)."""
    global _dashboard_ready
    if _dashboard_ready:
        return
    try:
        init_db()
        _ensure_scan_history_columns()
        _dashboard_ready = True
    except Exception as exc:  # noqa: BLE001
        logger.warning("dashboard_db_init_failed: %s", exc)


def reset_engine_for_tests() -> None:
    """Reinicia singleton (apenas testes)."""
    global _engine, _SessionLocal, _using_sqlite, _dashboard_ready
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None
    _using_sqlite = False
    _dashboard_ready = False


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _vuln_key(target: str, finding: dict[str, Any]) -> str:
    fid = str(finding.get("id") or "").strip()
    title = str(finding.get("title") or "unknown").strip()[:120]
    base = fid or title
    return f"{target}|{base}".replace(" ", "_")[:500]


def save_scan_result(scan_result: dict[str, Any]) -> bool:
    """Persiste resultado de scan + tracking de vulns."""
    from backend.database.models_dashboard import ScanHistory, VulnerabilityTracking

    try:
        ensure_dashboard_db()
        findings = scan_result.get("findings") or []
        if not isinstance(findings, list):
            findings = []
        # Limit stored findings payload
        compact = []
        for f in findings[:200]:
            if isinstance(f, dict):
                compact.append(
                    {
                        "id": f.get("id"),
                        "title": f.get("title"),
                        "severity": f.get("severity"),
                        "status": f.get("status"),
                        "host": f.get("host"),
                        "url": f.get("url"),
                        "tool": f.get("tool"),
                        "remediation": f.get("remediation"),
                        "cve": f.get("cve"),
                        "template_id": f.get("template_id"),
                    }
                )
        scan_id = str(scan_result.get("scan_id") or uuid.uuid4().hex[:16])
        chat_session_id = str(scan_result.get("chat_session_id") or "")[:128]
        with session_scope() as db:
            row = ScanHistory(
                scan_id=scan_id,
                target=str(scan_result.get("target") or "")[:256],
                risk_profile=str(scan_result.get("risk_profile") or "")[:32],
                scan_profile=str(scan_result.get("scan_profile") or "")[:32],
                vulnerability_count=int(scan_result.get("vulnerability_count") or 0),
                critical=int(scan_result.get("critical") or 0),
                high=int(scan_result.get("high") or 0),
                medium=int(scan_result.get("medium") or 0),
                low=int(scan_result.get("low") or 0),
                findings_json=json.dumps(compact, ensure_ascii=False),
                rounds=float(
                    scan_result.get("rounds") or scan_result.get("execution_time_seconds") or 0
                ),
                status=str(scan_result.get("status") or "completed")[:32],
                error_message=str(scan_result.get("error_message") or "")[:2000],
                scan_type=str(scan_result.get("scan_type") or "manual")[:32],
                chat_session_id=chat_session_id,
                timestamp=_utcnow(),
            )
            db.add(row)
            target = str(scan_result.get("target") or "")
            for finding in compact:
                key = _vuln_key(target, finding)
                existing = (
                    db.query(VulnerabilityTracking)
                    .filter(VulnerabilityTracking.vuln_key == key)
                    .first()
                )
                now = _utcnow()
                if existing:
                    existing.last_seen = now
                    existing.seen_count = int(existing.seen_count or 0) + 1
                    if finding.get("remediation"):
                        existing.remediation = str(finding.get("remediation") or "")[:4000]
                    sev = str(finding.get("severity") or existing.severity)
                    existing.severity = sev[:16]
                else:
                    db.add(
                        VulnerabilityTracking(
                            vuln_key=key,
                            title=str(finding.get("title") or "")[:512],
                            severity=str(finding.get("severity") or "unknown")[:16],
                            target=target[:256],
                            first_seen=now,
                            last_seen=now,
                            seen_count=1,
                            status="open",
                            remediation=str(finding.get("remediation") or "")[:4000],
                        )
                    )
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("save_scan_result_failed: %s", exc)
        return False


def record_scan_from_target(
    target: str,
    *,
    risk_profile: str = "",
    scan_profile: str = "",
    rounds: int | float = 0,
    status: str = "completed",
    scan_type: str = "autonomous",
    error_message: str = "",
    include_candidates: bool = True,
    chat_session_id: str = "",
) -> dict[str, Any] | None:
    """Monta report a partir do surface e grava no histórico."""
    try:
        from backend.cli_report import build_cli_report

        report = build_cli_report(
            target,
            risk_profile=risk_profile,
            scan_profile=scan_profile,
            rounds=int(rounds or 0),
            include_candidates=include_candidates,
        )
        report["scan_type"] = scan_type
        report["status"] = status
        report["error_message"] = error_message
        report["scan_id"] = uuid.uuid4().hex[:16]
        report["chat_session_id"] = str(chat_session_id or "")[:128]
        ok = save_scan_result(report)
        return report if ok else None
    except Exception as exc:  # noqa: BLE001
        logger.warning("record_scan_from_target_failed: %s", exc)
        return None


def _session_targets(session_id: str) -> list[str]:
    if not session_id:
        return []
    try:
        from backend.executor.session_intel import load_session

        data = load_session(session_id) or {}
        return [str(t) for t in (data.get("targets") or []) if t]
    except Exception:  # noqa: BLE001
        return []


def purge_scans_for_session(session_id: str) -> int:
    """Remove scans do dashboard ligados a uma conversa apagada."""
    from backend.database.models_dashboard import ScanHistory

    sid = str(session_id or "").strip()
    if not sid:
        return 0
    try:
        ensure_dashboard_db()
        with session_scope() as db:
            n = (
                db.query(ScanHistory)
                .filter(ScanHistory.chat_session_id == sid)
                .delete(synchronize_session=False)
            )
            return int(n or 0)
    except Exception as exc:  # noqa: BLE001
        logger.warning("purge_scans_for_session_failed: %s", exc)
        return 0


def get_scan_history(
    days: int = 30,
    target: str | None = None,
    limit: int = 100,
    session_id: str | None = None,
) -> list[dict[str, Any]]:
    from backend.database.models_dashboard import ScanHistory

    sid = str(session_id or "").strip()
    if not sid:
        return []

    try:
        ensure_dashboard_db()
        cutoff = _utcnow() - timedelta(days=max(1, days))
        with session_scope() as db:
            q = db.query(ScanHistory).filter(
                ScanHistory.timestamp >= cutoff,
                ScanHistory.chat_session_id == sid,
            )
            if target:
                q = q.filter(ScanHistory.target == target)
            rows = q.order_by(ScanHistory.timestamp.desc()).limit(max(1, min(limit, 1000))).all()
            return [
                {
                    "scan_id": s.scan_id,
                    "target": s.target,
                    "risk_profile": s.risk_profile,
                    "scan_profile": s.scan_profile,
                    "vulnerability_count": s.vulnerability_count,
                    "critical": s.critical,
                    "high": s.high,
                    "medium": s.medium,
                    "low": s.low,
                    "rounds": s.rounds,
                    "timestamp": s.timestamp.isoformat() if s.timestamp else None,
                    "status": s.status,
                    "scan_type": s.scan_type,
                    "chat_session_id": s.chat_session_id,
                }
                for s in rows
            ]
    except Exception as exc:  # noqa: BLE001
        logger.warning("get_scan_history_failed: %s", exc)
        return []


def _session_finding_keys(
    db, *, session_id: str, cutoff
) -> tuple[int, set[str], list[tuple[str, dict[str, Any]]]]:
    """Retorna (total_scans, vuln_keys, findings_list) só dos scans desta conversa no período."""
    from backend.database.models_dashboard import ScanHistory

    rows = (
        db.query(ScanHistory)
        .filter(
            ScanHistory.timestamp >= cutoff,
            ScanHistory.chat_session_id == session_id,
        )
        .all()
    )
    keys: set[str] = set()
    findings_flat: list[tuple[str, dict[str, Any]]] = []
    for s in rows:
        target = str(s.target or "")
        try:
            items = json.loads(s.findings_json or "[]")
        except json.JSONDecodeError:
            items = []
        if not isinstance(items, list):
            continue
        for f in items:
            if not isinstance(f, dict):
                continue
            key = _vuln_key(target, f)
            keys.add(key)
            findings_flat.append((target, f))
    return len(rows), keys, findings_flat


def compute_metrics(days: int = 30, session_id: str | None = None) -> dict[str, Any]:
    from backend.database.models_dashboard import ScanHistory, VulnerabilityTracking

    empty = {
        "total_scans": 0,
        "avg_critical": 0.0,
        "avg_high": 0.0,
        "total_vulnerabilities": 0,
        "open_vulnerabilities": 0,
        "period_days": days,
        "session_id": session_id or "",
    }
    sid = str(session_id or "").strip()
    if not sid:
        return empty

    try:
        ensure_dashboard_db()
        cutoff = _utcnow() - timedelta(days=max(1, days))
        with session_scope() as db:
            base = [
                ScanHistory.timestamp >= cutoff,
                ScanHistory.chat_session_id == sid,
            ]
            total_scans = db.query(func.count(ScanHistory.id)).filter(*base).scalar() or 0
            if int(total_scans) == 0:
                return {**empty, "session_id": sid, "period_days": days}

            avg_critical = db.query(func.avg(ScanHistory.critical)).filter(*base).scalar() or 0
            avg_high = db.query(func.avg(ScanHistory.high)).filter(*base).scalar() or 0
            total_vulns = (
                db.query(func.sum(ScanHistory.vulnerability_count)).filter(*base).scalar() or 0
            )
            _, finding_keys, _ = _session_finding_keys(db, session_id=sid, cutoff=cutoff)
            if not finding_keys:
                open_vulns = 0
            else:
                open_vulns = (
                    db.query(func.count(VulnerabilityTracking.id))
                    .filter(
                        VulnerabilityTracking.status == "open",
                        VulnerabilityTracking.vuln_key.in_(finding_keys),
                    )
                    .scalar()
                    or 0
                )
            return {
                "total_scans": int(total_scans),
                "avg_critical": float(avg_critical),
                "avg_high": float(avg_high),
                "total_vulnerabilities": int(total_vulns),
                "open_vulnerabilities": int(open_vulns),
                "period_days": days,
                "session_id": sid,
            }
    except Exception as exc:  # noqa: BLE001
        logger.warning("compute_metrics_failed: %s", exc)
        return empty


def get_top_issues(limit: int = 10, session_id: str | None = None) -> list[dict[str, Any]]:
    """Top issues abertos só dos findings dos scans desta conversa."""
    return get_top_issues_for_period(limit, days=3650, session_id=session_id)


def get_top_issues_for_period(
    limit: int = 10, *, days: int = 30, session_id: str | None = None
) -> list[dict[str, Any]]:
    """Top issues abertos só dos findings dos scans da conversa no período."""
    from backend.database.models_dashboard import VulnerabilityTracking

    sid = str(session_id or "").strip()
    if not sid:
        return []
    try:
        ensure_dashboard_db()
        cutoff = _utcnow() - timedelta(days=max(1, days))
        with session_scope() as db:
            total, keys, _ = _session_finding_keys(db, session_id=sid, cutoff=cutoff)
            if total == 0 or not keys:
                return []
            rows = (
                db.query(VulnerabilityTracking)
                .filter(
                    VulnerabilityTracking.status == "open",
                    VulnerabilityTracking.vuln_key.in_(keys),
                )
                .order_by(VulnerabilityTracking.seen_count.desc())
                .limit(max(1, min(limit, 50)))
                .all()
            )
            return [
                {
                    "title": r.title,
                    "severity": r.severity,
                    "count": r.seen_count,
                    "target": r.target,
                }
                for r in rows
            ]
    except Exception as exc:  # noqa: BLE001
        logger.warning("get_top_issues_for_period_failed: %s", exc)
        return []


def dashboard_bundle(
    *, days: int = 30, session_id: str | None = None, history_limit: int = 20, top_limit: int = 10
) -> dict[str, Any]:
    """Um payload com metrics + trend + top_issues + history (menos round-trips)."""
    sid = str(session_id or "").strip()
    return {
        "metrics": compute_metrics(days=days, session_id=sid),
        "trend": vulnerability_trend(days=days, session_id=sid),
        "top_issues": get_top_issues_for_period(top_limit, days=days, session_id=sid),
        "history": get_scan_history(days=days, limit=history_limit, session_id=sid),
    }


def vulnerability_trend(days: int = 30, session_id: str | None = None) -> list[dict[str, Any]]:
    """Série diária a partir de ScanHistory da conversa."""
    from backend.database.models_dashboard import ScanHistory

    sid = str(session_id or "").strip()
    if not sid:
        return []

    try:
        ensure_dashboard_db()
        cutoff = _utcnow() - timedelta(days=max(1, days))
        by_date: dict[str, dict[str, Any]] = {}
        with session_scope() as db:
            rows = (
                db.query(ScanHistory)
                .filter(
                    ScanHistory.timestamp >= cutoff,
                    ScanHistory.chat_session_id == sid,
                )
                .order_by(ScanHistory.timestamp.asc())
                .all()
            )
            for s in rows:
                if not s.timestamp:
                    continue
                day = s.timestamp.astimezone(timezone.utc).date().isoformat()
                slot = by_date.setdefault(
                    day,
                    {
                        "date": day,
                        "scans": 0,
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "total": 0,
                    },
                )
                slot["scans"] += 1
                slot["critical"] += int(s.critical or 0)
                slot["high"] += int(s.high or 0)
                slot["medium"] += int(s.medium or 0)
                slot["low"] += int(s.low or 0)
                slot["total"] += int(s.vulnerability_count or 0)

        return [by_date[k] for k in sorted(by_date.keys())]
    except Exception as exc:  # noqa: BLE001
        logger.warning("vulnerability_trend_failed: %s", exc)
        return []


def summary_report(days: int = 30, session_id: str | None = None) -> dict[str, Any]:
    from backend.database.models_dashboard import ScanHistory

    empty = {
        "period_days": days,
        "total_scans": 0,
        "success_rate": "100.0%",
        "total_critical": 0,
        "unique_targets": 0,
        "latest_scans": [],
        "session_id": session_id or "",
    }
    sid = str(session_id or "").strip()
    if not sid:
        return empty

    try:
        ensure_dashboard_db()
        cutoff = _utcnow() - timedelta(days=max(1, days))
        with session_scope() as db:
            base = [
                ScanHistory.timestamp >= cutoff,
                ScanHistory.chat_session_id == sid,
            ]
            total_scans = db.query(func.count(ScanHistory.id)).filter(*base).scalar() or 0
            failed = (
                db.query(func.count(ScanHistory.id))
                .filter(*base, ScanHistory.status != "completed")
                .scalar()
                or 0
            )
            total_critical = db.query(func.sum(ScanHistory.critical)).filter(*base).scalar() or 0
            unique_targets = (
                db.query(func.count(func.distinct(ScanHistory.target))).filter(*base).scalar() or 0
            )
            latest = (
                db.query(ScanHistory)
                .filter(*base)
                .order_by(ScanHistory.timestamp.desc())
                .limit(5)
                .all()
            )
            return {
                "period_days": days,
                "total_scans": int(total_scans),
                "success_rate": f"{100 * (1 - failed / max(int(total_scans), 1)):.1f}%",
                "total_critical": int(total_critical),
                "unique_targets": int(unique_targets),
                "latest_scans": [
                    {
                        "target": s.target,
                        "vulnerabilities": s.vulnerability_count,
                        "critical": s.critical,
                        "timestamp": s.timestamp.isoformat() if s.timestamp else None,
                    }
                    for s in latest
                ],
                "session_id": sid,
            }
    except Exception as exc:  # noqa: BLE001
        logger.warning("summary_report_failed: %s", exc)
        return empty
