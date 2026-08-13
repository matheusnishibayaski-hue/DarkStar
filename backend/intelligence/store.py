"""Persistência do Intelligence Hub — PostgreSQL ou JSON."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.config import DATABASE_URL, INTELLIGENCE_DIR, INTELLIGENCE_STORAGE
from backend.intelligence.exceptions import StorageUnavailable


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def use_postgres() -> bool:
    return INTELLIGENCE_STORAGE == "postgres" and bool(DATABASE_URL)


def ensure_json_dirs() -> Path:
    root = Path(INTELLIGENCE_DIR)
    (root / "history").mkdir(parents=True, exist_ok=True)
    root.mkdir(parents=True, exist_ok=True)
    return root


def patterns_path() -> Path:
    return ensure_json_dirs() / "patterns.json"


def load_patterns_json() -> dict[str, Any]:
    path = patterns_path()
    if not path.is_file():
        return {"patterns": {}, "updated_at": None}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"patterns": {}, "updated_at": None}


def save_patterns_json(data: dict[str, Any]) -> None:
    path = patterns_path()
    data["updated_at"] = _utcnow()
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def append_history_json(target: str, snapshot: dict[str, Any]) -> None:
    root = ensure_json_dirs()
    path = root / "history" / f"{target}.jsonl"
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(snapshot, ensure_ascii=False) + "\n")


def read_history_json(target: str, limit: int = 50) -> list[dict[str, Any]]:
    path = ensure_json_dirs() / "history" / f"{target}.jsonl"
    if not path.is_file():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    out: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def list_history_targets_json() -> list[str]:
    hist = ensure_json_dirs() / "history"
    return sorted(p.stem for p in hist.glob("*.jsonl"))


def threat_model_path(target: str) -> Path:
    return ensure_json_dirs() / "threat_models" / f"{target}.json"


def save_threat_model_json(target: str, payload: dict[str, Any]) -> None:
    path = threat_model_path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def load_threat_model_json(target: str) -> dict[str, Any] | None:
    path = threat_model_path(target)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def require_postgres() -> None:
    if not use_postgres():
        raise StorageUnavailable("INTELLIGENCE_STORAGE=postgres exige DATABASE_URL configurado.")
