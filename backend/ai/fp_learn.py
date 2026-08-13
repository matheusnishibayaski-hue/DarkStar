"""Aprendizado de falso positivo — padrões no SQLite/Postgres."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from backend.config import FP_SUPPRESS_PATH
from backend.intelligence.patterns import pattern_key_for_finding

logger = logging.getLogger(__name__)

_migrated = False


def reset_for_tests() -> None:
    """Só testes: permite reimportar o JSON legado."""
    global _migrated
    _migrated = False


def _row_to_dict(row) -> dict[str, Any]:
    try:
        targets = json.loads(row.targets_json or "[]")
    except json.JSONDecodeError:
        targets = []
    if not isinstance(targets, list):
        targets = []
    return {
        "pattern_key": row.pattern_key,
        "finding_type": row.finding_type or "title",
        "title": row.title or "",
        "hits": int(row.hits or 0),
        "targets": [str(t) for t in targets][:40],
    }


def _migrate_legacy_json() -> None:
    global _migrated
    if _migrated:
        return
    _migrated = True
    path = Path(FP_SUPPRESS_PATH)
    if not path.is_file():
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return
    patterns = data.get("patterns") if isinstance(data, dict) else None
    if not isinstance(patterns, dict) or not patterns:
        _unlink_legacy(path)
        return
    from backend.database.db import ensure_dashboard_db, session_scope
    from backend.database.models_store import FpSuppressPattern

    ensure_dashboard_db()
    imported = 0
    with session_scope() as db:
        for key, entry in patterns.items():
            if not isinstance(entry, dict):
                continue
            pk = str(entry.get("pattern_key") or key)[:256]
            if not pk:
                continue
            row = db.query(FpSuppressPattern).filter(FpSuppressPattern.pattern_key == pk).first()
            targets = list(entry.get("targets") or [])
            hits = int(entry.get("hits") or 1)
            if row:
                row.hits = max(int(row.hits or 0), hits)
                try:
                    existing = json.loads(row.targets_json or "[]")
                except json.JSONDecodeError:
                    existing = []
                merged = list(dict.fromkeys([*(existing or []), *targets]))[:40]
                row.targets_json = json.dumps(merged, ensure_ascii=False)
                if not row.title:
                    row.title = str(entry.get("title") or "")[:200]
            else:
                db.add(
                    FpSuppressPattern(
                        pattern_key=pk,
                        finding_type=str(entry.get("finding_type") or "title")[:64],
                        title=str(entry.get("title") or "")[:200],
                        hits=hits,
                        targets_json=json.dumps(targets[:40], ensure_ascii=False),
                    )
                )
                imported += 1
    logger.info("fp_suppress_migrated_from_json imported=%s", imported)
    _unlink_legacy(path)


def _unlink_legacy(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def remember_false_positive(finding: dict[str, Any], *, target: str = "") -> dict[str, Any]:
    from backend.database.db import ensure_dashboard_db, session_scope
    from backend.database.models_store import FpSuppressPattern

    _migrate_legacy_json()
    key, ftype = pattern_key_for_finding(finding)
    ensure_dashboard_db()
    with session_scope() as db:
        row = db.query(FpSuppressPattern).filter(FpSuppressPattern.pattern_key == key).first()
        if row:
            row.hits = int(row.hits or 0) + 1
            try:
                targets = json.loads(row.targets_json or "[]")
            except json.JSONDecodeError:
                targets = []
            if not isinstance(targets, list):
                targets = []
            if target and target not in targets:
                targets.append(target)
                row.targets_json = json.dumps(targets[:40], ensure_ascii=False)
            if not row.title:
                row.title = str(finding.get("title") or "")[:200]
            db.flush()
            return _row_to_dict(row)
        targets = [target] if target else []
        row = FpSuppressPattern(
            pattern_key=key,
            finding_type=ftype[:64],
            title=str(finding.get("title") or "")[:200],
            hits=1,
            targets_json=json.dumps(targets, ensure_ascii=False),
        )
        db.add(row)
        db.flush()
        return _row_to_dict(row)


def is_suppressed(finding: dict[str, Any]) -> bool:
    from backend.database.db import ensure_dashboard_db, session_scope
    from backend.database.models_store import FpSuppressPattern

    _migrate_legacy_json()
    key, _ = pattern_key_for_finding(finding)
    ensure_dashboard_db()
    with session_scope() as db:
        row = db.query(FpSuppressPattern).filter(FpSuppressPattern.pattern_key == key).first()
        return row is not None


def list_suppressed(*, limit: int = 100) -> list[dict[str, Any]]:
    from backend.database.db import ensure_dashboard_db, session_scope
    from backend.database.models_store import FpSuppressPattern

    _migrate_legacy_json()
    ensure_dashboard_db()
    cap = max(1, min(int(limit or 100), 500))
    with session_scope() as db:
        rows = db.query(FpSuppressPattern).order_by(FpSuppressPattern.hits.desc()).limit(cap).all()
        return [_row_to_dict(r) for r in rows]


def clear_suppressed(pattern_key: str | None = None) -> int:
    from backend.database.db import ensure_dashboard_db, session_scope
    from backend.database.models_store import FpSuppressPattern

    _migrate_legacy_json()
    ensure_dashboard_db()
    with session_scope() as db:
        if pattern_key:
            n = (
                db.query(FpSuppressPattern)
                .filter(FpSuppressPattern.pattern_key == pattern_key)
                .delete()
            )
            return int(n or 0)
        n = db.query(FpSuppressPattern).delete()
        return int(n or 0)
