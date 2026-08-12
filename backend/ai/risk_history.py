"""Histórico temporal de risk_score por alvo (JSONL)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.config import RISK_HISTORY_DIR
from backend.executor.recon_db import normalize_target


def _path(target: str) -> Path:
    return RISK_HISTORY_DIR / f"{normalize_target(target)}.jsonl"


def record_risk_snapshot(target: str, risk: dict[str, Any], *, source: str = "") -> dict[str, Any]:
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "score": float(risk.get("score") or 0),
        "band": risk.get("band"),
        "label": risk.get("label"),
        "critical": risk.get("critical", 0),
        "high": risk.get("high", 0),
        "count": risk.get("count", 0),
        "source": source,
    }
    path = _path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def load_risk_history(target: str, *, limit: int = 90) -> list[dict[str, Any]]:
    path = _path(target)
    if not path.is_file():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    items: list[dict[str, Any]] = []
    for line in lines[-max(1, limit) :]:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            items.append(row)
    return items


def previous_score(target: str) -> float | None:
    hist = load_risk_history(target, limit=2)
    if len(hist) < 1:
        return None
    # último antes do atual — se só 1, usa ele como referência prévia
    if len(hist) == 1:
        return None
    try:
        return float(hist[-2].get("score") or 0)
    except (TypeError, ValueError):
        return None
