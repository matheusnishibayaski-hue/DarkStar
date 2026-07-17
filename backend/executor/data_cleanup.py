"""Exclusão segura de dados gerados automaticamente pelo sistema."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from backend.config import AUDIT_DIR, LOG_DIR, OUTPUTS_DIR, RECON_DIR, SURFACE_DIR
from backend.executor.files_store import resolve_output_file
from backend.executor.recon_db import normalize_target

PURGE_CATEGORIES = frozenset(
    {
        "logs",
        "recon",
        "audit",
        "surface",
        "outputs",
        "evidence",
        "delivery",
    }
)


def _dir_stats(root: Path, pattern: str = "*") -> dict[str, Any]:
    if not root.is_dir():
        return {"count": 0, "bytes": 0}
    count = 0
    total = 0
    for path in root.rglob(pattern) if "**" in pattern else root.glob(pattern):
        if path.is_file():
            count += 1
            try:
                total += path.stat().st_size
            except OSError:
                pass
    return {"count": count, "bytes": total}


def storage_summary() -> dict[str, Any]:
    """Resumo de tudo que o sistema persiste automaticamente."""
    evidence_root = OUTPUTS_DIR / "evidence"
    delivery_root = OUTPUTS_DIR / "delivery"
    outputs_other = 0
    outputs_other_bytes = 0
    if OUTPUTS_DIR.is_dir():
        for path in OUTPUTS_DIR.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(OUTPUTS_DIR).as_posix()
            if rel.startswith("evidence/") or rel.startswith("delivery/"):
                continue
            outputs_other += 1
            try:
                outputs_other_bytes += path.stat().st_size
            except OSError:
                pass

    return {
        "categories": {
            "logs": {
                "label": "Logs de execução",
                "path": str(LOG_DIR),
                **_dir_stats(LOG_DIR, "*.log"),
            },
            "recon": {
                "label": "Recon por alvo",
                "path": str(RECON_DIR),
                **_dir_stats(RECON_DIR, "*.json"),
            },
            "audit": {
                "label": "Auditoria (JSONL)",
                "path": str(AUDIT_DIR),
                **_dir_stats(AUDIT_DIR, "*.jsonl"),
            },
            "surface": {
                "label": "Attack Surface / engajamentos",
                "path": str(SURFACE_DIR),
                **_dir_stats(SURFACE_DIR, "*.json"),
            },
            "evidence": {
                "label": "Evidências PoC",
                "path": str(evidence_root),
                **_dir_stats(evidence_root, "**/*"),
            },
            "delivery": {
                "label": "Bundles ZIP de entrega",
                "path": str(delivery_root),
                **_dir_stats(delivery_root, "*.zip"),
            },
            "outputs": {
                "label": "Artefatos em /tools/output",
                "path": str(OUTPUTS_DIR),
                "count": outputs_other,
                "bytes": outputs_other_bytes,
            },
        },
        "purge_categories": sorted(PURGE_CATEGORIES),
    }


def delete_execution_log(log_id: str) -> dict[str, Any]:
    """Remove arquivo .log, meta e/ou referências na auditoria."""
    if not log_id or not log_id.isalnum():
        return {"ok": False, "file_deleted": False, "audit_removed": 0}

    file_deleted = False
    path = LOG_DIR / f"{log_id}.log"
    if path.is_file():
        path.unlink()
        file_deleted = True
    meta = LOG_DIR / f"{log_id}.meta.json"
    if meta.is_file():
        meta.unlink()

    from backend.security.audit import remove_entries_by_log_id

    audit_removed = remove_entries_by_log_id(log_id)
    ok = file_deleted or audit_removed > 0
    return {
        "ok": ok,
        "file_deleted": file_deleted,
        "audit_removed": audit_removed,
    }


def delete_logs_for_session(session_id: str, extra_log_ids: list[str] | None = None) -> dict[str, Any]:
    """Remove todos os logs vinculados a um chat (sessão do navegador)."""
    from backend.executor.logs import list_log_ids_for_session

    if not session_id or len(session_id) > 128:
        return {"deleted": 0, "session_id": session_id or ""}

    ids: set[str] = set(list_log_ids_for_session(session_id))
    for lid in extra_log_ids or []:
        if lid and str(lid).isalnum():
            ids.add(str(lid))

    deleted = 0
    for log_id in ids:
        result = delete_execution_log(log_id)
        if result.get("ok"):
            deleted += 1

    index = LOG_DIR / "by_session" / f"{session_id}.json"
    if index.is_file():
        index.unlink()

    return {"deleted": deleted, "session_id": session_id}


def delete_recon(target: str) -> bool:
    if not target or len(target) > 128 or ".." in target:
        return False
    path = RECON_DIR / f"{normalize_target(target)}.json"
    if not path.is_file():
        return False
    path.unlink()
    return True


def delete_surface(target: str) -> bool:
    if not target or len(target) > 128 or ".." in target:
        return False
    path = SURFACE_DIR / f"{normalize_target(target)}.json"
    removed = False
    if path.is_file():
        path.unlink()
        removed = True
    ev_count = delete_evidence_for_target(target)
    return removed or ev_count > 0


def delete_evidence_for_target(target: str) -> int:
    root = OUTPUTS_DIR / "evidence" / normalize_target(target)
    if not root.is_dir():
        return 0
    count = sum(1 for p in root.rglob("*") if p.is_file())
    shutil.rmtree(root, ignore_errors=True)
    return count


def delete_output_file(rel_path: str) -> bool:
    path = resolve_output_file(rel_path)
    if path is None or not path.is_file():
        return False
    path.unlink()
    return True


def purge_audit(*, date: str | None = None) -> int:
    """Remove ficheiros de auditoria. date=YYYY-MM-DD ou None = todos."""
    if not AUDIT_DIR.is_dir():
        return 0
    removed = 0
    if date:
        path = AUDIT_DIR / f"events-{date}.jsonl"
        if path.is_file():
            path.unlink()
            return 1
        return 0
    for path in AUDIT_DIR.glob("events-*.jsonl"):
        if path.is_file():
            path.unlink()
            removed += 1
    return removed


def purge_category(category: str, *, target: str | None = None) -> int:
    """Remove todos os registos de uma categoria (opcionalmente por alvo)."""
    cat = category.strip().lower()
    if cat not in PURGE_CATEGORIES:
        raise ValueError(f"Categoria inválida: {category}")

    if cat == "logs":
        return _purge_glob(LOG_DIR, "*.log")

    if cat == "recon":
        if target:
            return 1 if delete_recon(target) else 0
        return _purge_glob(RECON_DIR, "*.json")

    if cat == "audit":
        return purge_audit()

    if cat == "surface":
        if target:
            return 1 if delete_surface(target) else 0
        count = _purge_glob(SURFACE_DIR, "*.json")
        ev_root = OUTPUTS_DIR / "evidence"
        if ev_root.is_dir():
            shutil.rmtree(ev_root, ignore_errors=True)
        return count

    if cat == "evidence":
        if target:
            return delete_evidence_for_target(target)
        root = OUTPUTS_DIR / "evidence"
        if not root.is_dir():
            return 0
        count = sum(1 for p in root.rglob("*") if p.is_file())
        shutil.rmtree(root, ignore_errors=True)
        return count

    if cat == "delivery":
        root = OUTPUTS_DIR / "delivery"
        return _purge_glob(root, "*.zip")

    if cat == "outputs":
        if target:
            prefix = normalize_target(target)
            removed = 0
            if OUTPUTS_DIR.is_dir():
                for path in list(OUTPUTS_DIR.rglob("*")):
                    if not path.is_file():
                        continue
                    rel = path.relative_to(OUTPUTS_DIR).as_posix().lower()
                    if prefix in rel:
                        path.unlink()
                        removed += 1
            return removed
        removed = 0
        if OUTPUTS_DIR.is_dir():
            for path in OUTPUTS_DIR.rglob("*"):
                if path.is_file():
                    path.unlink()
                    removed += 1
        return removed

    return 0


def _purge_glob(root: Path, pattern: str) -> int:
    if not root.is_dir():
        return 0
    removed = 0
    for path in root.glob(pattern):
        if path.is_file():
            path.unlink()
            removed += 1
    return removed


def purge_categories(
    categories: list[str],
    *,
    target: str | None = None,
) -> dict[str, int]:
    results: dict[str, int] = {}
    for raw in categories:
        cat = raw.strip().lower()
        if cat not in PURGE_CATEGORIES:
            continue
        results[cat] = purge_category(cat, target=target)
    return results
