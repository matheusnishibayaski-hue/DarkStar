"""Facade do Intelligence Hub — record / suggest / stats / similar."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from backend.config import INTELLIGENCE_ENABLED
from backend.executor.recon_db import normalize_target
from backend.executor.surface import load_surface, surface_summary
from backend.intelligence import store
from backend.intelligence.exceptions import SurfaceNotFound
from backend.intelligence.patterns import bump_patterns, compact_finding, top_patterns
from backend.intelligence.suggest import build_suggestions

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def record_from_surface(target: str, *, industry: str = "") -> dict[str, Any]:
    """Lê o Attack Surface e grava snapshot + padrões (Postgres ou JSON)."""
    if not INTELLIGENCE_ENABLED:
        return {"enabled": False, "recorded": False}

    norm = normalize_target(target)
    data = load_surface(norm)
    if not data:
        raise SurfaceNotFound(f"Nenhum Attack Surface para '{norm}'.")

    findings = [compact_finding(f) for f in (data.get("findings") or [])]
    industry_key = (industry or data.get("label") or "generic").strip().lower() or "generic"
    summary = surface_summary(data)
    tools = data.get("tools_run") or []
    snapshot = {
        "target": norm,
        "industry": industry_key,
        "recorded_at": _utcnow().isoformat(),
        "findings_count": len(findings),
        "findings": findings,
        "summary": summary,
        "tools_used": tools,
        "phase": str(data.get("phase") or ""),
    }

    if store.use_postgres():
        result = _record_postgres(snapshot, industry_key)
    else:
        result = _record_json(snapshot, industry_key)

    logger.info("intelligence_recorded target=%s findings=%s", norm, len(findings))
    return result


def _record_json(snapshot: dict[str, Any], industry: str) -> dict[str, Any]:
    store.append_history_json(snapshot["target"], snapshot)
    patterns = store.load_patterns_json()
    bump_patterns(patterns, snapshot.get("findings") or [], industry=industry)
    store.save_patterns_json(patterns)
    return {
        "enabled": True,
        "storage": "json",
        "target": snapshot["target"],
        "findings_count": snapshot["findings_count"],
        "patterns_top": top_patterns(patterns, industry=industry, limit=5),
    }


def _record_postgres(snapshot: dict[str, Any], industry: str) -> dict[str, Any]:
    from backend.database.db import init_db, session_scope
    from backend.database.models_intelligence import (
        FindingHistory,
        IndustryPattern,
        PentestRecord,
        TargetIntelligence,
    )

    init_db()
    with session_scope() as session:
        record = PentestRecord(
            target=snapshot["target"],
            industry=industry,
            findings_count=int(snapshot["findings_count"]),
            tools_used=json.dumps(snapshot.get("tools_used") or [], ensure_ascii=False),
            phase=str(snapshot.get("phase") or ""),
            summary_json=json.dumps(snapshot.get("summary") or {}, ensure_ascii=False),
            recorded_at=_utcnow(),
        )
        session.add(record)
        session.flush()

        for f in snapshot.get("findings") or []:
            session.add(
                FindingHistory(
                    pentest_id=record.id,
                    finding_key=str(f.get("finding_key") or ""),
                    cve_id=str(f.get("cve") or "")[:32],
                    template_id=str(f.get("template_id") or "")[:128],
                    severity=str(f.get("severity") or "unknown")[:16],
                    title=str(f.get("title") or "")[:512],
                    status=str(f.get("status") or "")[:32],
                    tool=",".join(f.get("sources") or [])[:64],
                )
            )

        for f in snapshot.get("findings") or []:
            from backend.intelligence.patterns import pattern_key_for_finding

            key, ftype = pattern_key_for_finding(f)
            row = (
                session.query(IndustryPattern)
                .filter_by(industry=industry, pattern_key=key)
                .one_or_none()
            )
            if row is None:
                row = IndustryPattern(
                    industry=industry,
                    pattern_key=key,
                    finding_type=ftype,
                    frequency=1,
                    last_seen=_utcnow(),
                )
                session.add(row)
            else:
                row.frequency = int(row.frequency or 0) + 1
                row.last_seen = _utcnow()

        ti = (
            session.query(TargetIntelligence)
            .filter_by(target_name=snapshot["target"])
            .one_or_none()
        )
        agg = {
            "findings_count": snapshot["findings_count"],
            "summary": snapshot.get("summary") or {},
            "last_recorded_at": snapshot["recorded_at"],
        }
        if ti is None:
            session.add(
                TargetIntelligence(
                    target_name=snapshot["target"],
                    industry=industry,
                    findings_aggregate=json.dumps(agg, ensure_ascii=False),
                    updated_at=_utcnow(),
                )
            )
        else:
            ti.industry = industry or ti.industry
            ti.findings_aggregate = json.dumps(agg, ensure_ascii=False)
            ti.updated_at = _utcnow()

        session.flush()
        top = (
            session.query(IndustryPattern)
            .filter_by(industry=industry)
            .order_by(IndustryPattern.frequency.desc())
            .limit(5)
            .all()
        )
        patterns_top = [
            {
                "industry": p.industry,
                "pattern_key": p.pattern_key,
                "finding_type": p.finding_type,
                "frequency": p.frequency,
            }
            for p in top
        ]
        return {
            "enabled": True,
            "storage": "postgres",
            "target": snapshot["target"],
            "pentest_id": record.id,
            "findings_count": snapshot["findings_count"],
            "patterns_top": patterns_top,
        }


def suggest(
    target: str,
    *,
    industry: str | None = None,
    limit: int = 10,
) -> dict[str, Any]:
    norm = normalize_target(target)
    data = load_surface(norm) or {
        "target": norm,
        "findings": [],
        "ports": [],
        "urls": [],
        "tools_run": [],
    }
    patterns = _load_patterns_blob(industry)
    items = build_suggestions(data, patterns, industry=industry, limit=max(1, min(limit, 30)))
    return {
        "target": norm,
        "suggestions": items,
        "storage": "postgres" if store.use_postgres() else "json",
    }


def stats() -> dict[str, Any]:
    if store.use_postgres():
        return _stats_postgres()
    patterns = store.load_patterns_json()
    targets = store.list_history_targets_json()
    return {
        "storage": "json",
        "targets_count": len(targets),
        "targets": targets[:50],
        "top_patterns": top_patterns(patterns, limit=15),
    }


def similar_targets(target: str, *, limit: int = 10) -> dict[str, Any]:
    norm = normalize_target(target)
    data = load_surface(norm) or {}
    keys = {compact_finding(f)["finding_key"] for f in (data.get("findings") or [])}
    if store.use_postgres():
        return _similar_postgres(norm, keys, limit=limit)

    scored: list[dict[str, Any]] = []
    for other in store.list_history_targets_json():
        if other == norm:
            continue
        hist = store.read_history_json(other, limit=1)
        if not hist:
            continue
        other_keys = {f.get("finding_key") for f in (hist[-1].get("findings") or [])}
        overlap = len(keys & other_keys)
        if overlap <= 0:
            continue
        scored.append({"target": other, "overlap": overlap, "score": float(overlap)})
    scored.sort(key=lambda x: x["score"], reverse=True)
    return {"target": norm, "targets": scored[:limit], "storage": "json"}


def _load_patterns_blob(industry: str | None) -> dict[str, Any]:
    if not store.use_postgres():
        return store.load_patterns_json()
    from backend.database.db import init_db, session_scope
    from backend.database.models_intelligence import IndustryPattern

    init_db()
    with session_scope() as session:
        q = session.query(IndustryPattern)
        if industry:
            q = q.filter(IndustryPattern.industry == industry.strip().lower())
        rows = q.order_by(IndustryPattern.frequency.desc()).limit(200).all()
        patterns = {
            "patterns": {
                f"{r.industry}|{r.pattern_key}": {
                    "industry": r.industry,
                    "pattern_key": r.pattern_key,
                    "finding_type": r.finding_type,
                    "frequency": r.frequency,
                    "title_sample": r.pattern_key,
                }
                for r in rows
            }
        }
        return patterns


def _stats_postgres() -> dict[str, Any]:
    from backend.database.db import init_db, session_scope
    from backend.database.models_intelligence import (
        IndustryPattern,
        PentestRecord,
        TargetIntelligence,
    )

    init_db()
    with session_scope() as session:
        targets = [t.target_name for t in session.query(TargetIntelligence).limit(100).all()]
        pentests = session.query(PentestRecord).count()
        top = (
            session.query(IndustryPattern)
            .order_by(IndustryPattern.frequency.desc())
            .limit(15)
            .all()
        )
        return {
            "storage": "postgres",
            "targets_count": len(targets),
            "targets": targets,
            "pentests_count": pentests,
            "top_patterns": [
                {
                    "industry": p.industry,
                    "pattern_key": p.pattern_key,
                    "finding_type": p.finding_type,
                    "frequency": p.frequency,
                }
                for p in top
            ],
        }


def _similar_postgres(norm: str, keys: set[str], *, limit: int) -> dict[str, Any]:
    from backend.database.db import init_db, session_scope
    from backend.database.models_intelligence import FindingHistory, PentestRecord

    init_db()
    scored: list[dict[str, Any]] = []
    with session_scope() as session:
        # últimos pentests por alvo
        targets = {
            r.target
            for r in session.query(PentestRecord.target).distinct().all()
            if r.target != norm
        }
        for other in targets:
            last = (
                session.query(PentestRecord)
                .filter_by(target=other)
                .order_by(PentestRecord.id.desc())
                .first()
            )
            if not last:
                continue
            rows = session.query(FindingHistory).filter_by(pentest_id=last.id).all()
            other_keys = {r.finding_key for r in rows if r.finding_key}
            overlap = len(keys & other_keys)
            if overlap > 0:
                scored.append({"target": other, "overlap": overlap, "score": float(overlap)})
    scored.sort(key=lambda x: x["score"], reverse=True)
    return {"target": norm, "targets": scored[:limit], "storage": "postgres"}


def try_record_from_surface(target: str) -> None:
    """Best-effort: nunca propaga erro para o fluxo de pentest."""
    if not INTELLIGENCE_ENABLED:
        return
    try:
        record_from_surface(target)
    except Exception as exc:  # noqa: BLE001 — isolado de propósito
        logger.warning("intelligence_record_skipped target=%s err=%s", target, exc)
