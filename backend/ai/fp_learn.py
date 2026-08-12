"""Aprendizado de falso positivo — suprime padrões marcados FP em futuros scans."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.config import FP_SUPPRESS_PATH
from backend.intelligence.patterns import pattern_key_for_finding


def _load() -> dict[str, Any]:
    path = Path(FP_SUPPRESS_PATH)
    if not path.is_file():
        return {"patterns": {}, "updated_at": None}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"patterns": {}, "updated_at": None}
    if not isinstance(data, dict):
        return {"patterns": {}, "updated_at": None}
    data.setdefault("patterns", {})
    return data


def _save(data: dict[str, Any]) -> None:
    path = Path(FP_SUPPRESS_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def remember_false_positive(finding: dict[str, Any], *, target: str = "") -> dict[str, Any]:
    key, ftype = pattern_key_for_finding(finding)
    data = _load()
    entry = data["patterns"].get(key) or {
        "pattern_key": key,
        "finding_type": ftype,
        "title": str(finding.get("title") or "")[:200],
        "hits": 0,
        "targets": [],
    }
    entry["hits"] = int(entry.get("hits") or 0) + 1
    targets = list(entry.get("targets") or [])
    if target and target not in targets:
        targets.append(target)
        entry["targets"] = targets[:40]
    data["patterns"][key] = entry
    _save(data)
    return entry


def is_suppressed(finding: dict[str, Any]) -> bool:
    key, _ = pattern_key_for_finding(finding)
    return key in (_load().get("patterns") or {})


def list_suppressed(*, limit: int = 100) -> list[dict[str, Any]]:
    items = list((_load().get("patterns") or {}).values())
    items.sort(key=lambda x: int(x.get("hits") or 0), reverse=True)
    return items[:limit]


def clear_suppressed(pattern_key: str | None = None) -> int:
    data = _load()
    if pattern_key:
        if pattern_key in data["patterns"]:
            del data["patterns"][pattern_key]
            _save(data)
            return 1
        return 0
    n = len(data["patterns"])
    data["patterns"] = {}
    _save(data)
    return n
