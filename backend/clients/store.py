"""CRUD de clientes — meta no banco; dirs locais para surface/logs."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.config import CLIENTS_DIR, CONSULTING_PRIMARY_COLOR, SURFACE_DIR

logger = logging.getLogger(__name__)
_CLIENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{0,62}[a-z0-9]$|^[a-z0-9]$")
# Pasta CLIENTS_DIR também hospeda o pacote Python — não são workspaces.
_RESERVED_DIR_NAMES = frozenset(
    {
        "__pycache__",
        ".git",
        "store",
        "backup",
        "runtime",
        "tests",
        "test",
    }
)


def normalize_client_id(value: str | None) -> str:
    raw = (value or "").strip().lower()
    raw = re.sub(r"[^a-z0-9\-]+", "-", raw).strip("-")
    if not raw:
        return "default"
    if len(raw) > 64:
        raw = raw[:64].rstrip("-")
    if not _CLIENT_ID_RE.match(raw) and raw != "default":
        raw = re.sub(r"[^a-z0-9\-]", "", raw) or "default"
    return raw or "default"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_allowed_targets(value: Any) -> list[str]:
    """Lista de alvos do ROE do cliente (mesmo normalizador do .env)."""
    from backend.config import _normalize_scope_target

    if value is None:
        return []
    if isinstance(value, str):
        parts = [p.strip() for p in value.replace(";", ",").split(",") if p.strip()]
    elif isinstance(value, list | tuple | set | frozenset):
        parts = [str(p).strip() for p in value if str(p).strip()]
    else:
        return []
    seen: list[str] = []
    for part in parts[:80]:
        normalized = _normalize_scope_target(part)
        if normalized and normalized != "unknown" and normalized not in seen:
            seen.append(normalized)
    return seen


def _with_client_defaults(data: dict[str, Any]) -> dict[str, Any]:
    out = dict(data)
    out["allowed_targets"] = _normalize_allowed_targets(out.get("allowed_targets"))
    out["contract_id"] = str(out.get("contract_id") or "").strip()[:80]
    return out


def client_dir(client_id: str) -> Path:
    cid = normalize_client_id(client_id)
    path = CLIENTS_DIR / cid
    if ".." in cid or cid.startswith(("/", "\\")):
        raise ValueError("client_id inválido")
    return path


def meta_path(client_id: str) -> Path:
    return client_dir(client_id) / "meta.json"


def surface_dir(client_id: str) -> Path:
    d = client_dir(client_id) / "surface"
    d.mkdir(parents=True, exist_ok=True)
    return d


def logs_dir(client_id: str) -> Path:
    d = client_dir(client_id) / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _ensure_dirs(client_id: str) -> None:
    cid = normalize_client_id(client_id)
    client_dir(cid).mkdir(parents=True, exist_ok=True)
    surface_dir(cid)
    logs_dir(cid)


def _read_meta_file(client_id: str) -> dict[str, Any] | None:
    path = meta_path(client_id)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


def _persist_client(data: dict[str, Any]) -> dict[str, Any]:
    from backend.database.db import ensure_dashboard_db, session_scope
    from backend.database.models_store import ClientRecord

    cid = normalize_client_id(str(data.get("client_id") or ""))
    data = _with_client_defaults({**data, "client_id": cid})
    _ensure_dirs(cid)
    ensure_dashboard_db()
    with session_scope() as db:
        row = db.query(ClientRecord).filter(ClientRecord.client_id == cid).first()
        payload = json.dumps(data, ensure_ascii=False)
        if row:
            row.payload_json = payload
        else:
            db.add(ClientRecord(client_id=cid, payload_json=payload))
        db.flush()
    # Espelho legado (opcional) — remove após migrar
    try:
        meta_path(cid).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass
    return data


def get_client(client_id: str) -> dict[str, Any] | None:
    from backend.database.db import ensure_dashboard_db, session_scope
    from backend.database.models_store import ClientRecord

    cid = normalize_client_id(client_id)
    try:
        ensure_dashboard_db()
        with session_scope() as db:
            row = db.query(ClientRecord).filter(ClientRecord.client_id == cid).first()
            if row:
                try:
                    data = json.loads(row.payload_json or "{}")
                except json.JSONDecodeError:
                    data = {}
                if isinstance(data, dict) and data:
                    _ensure_dirs(cid)
                    return _with_client_defaults(data)
    except Exception as exc:  # noqa: BLE001
        logger.debug("client_db_get_failed: %s", exc)

    file_data = _read_meta_file(cid)
    if file_data:
        try:
            return _with_client_defaults(_persist_client(file_data))
        except Exception as exc:  # noqa: BLE001
            logger.warning("client_migrate_failed: %s", exc)
            return _with_client_defaults(file_data)
    return None


def ensure_default_client() -> dict[str, Any]:
    """Garante workspace `default` para surfaces legados."""
    existing = get_client("default")
    if existing:
        return existing
    return create_client(
        "default",
        display_name="Padrão",
        consulting_name="",
        consulting_color="",
    )


def create_client(
    client_id: str,
    *,
    display_name: str = "",
    consulting_name: str = "",
    consulting_logo_path: str = "",
    consulting_color: str = "",
    consulting_footer: str = "",
    allowed_targets: Any = None,
    contract_id: str = "",
) -> dict[str, Any]:
    cid = normalize_client_id(client_id)
    if cid != "default" and not _CLIENT_ID_RE.match(cid):
        raise ValueError("client_id inválido — use slug [a-z0-9-] (1–64 chars).")
    if get_client(cid):
        raise FileExistsError(f"Cliente '{cid}' já existe.")
    data = {
        "client_id": cid,
        "display_name": (display_name or cid).strip()[:200],
        "consulting_name": (consulting_name or "").strip()[:120],
        "consulting_logo_path": (consulting_logo_path or "").strip()[:500],
        "consulting_color": (consulting_color or CONSULTING_PRIMARY_COLOR).strip()[:32],
        "consulting_footer": (consulting_footer or "").strip()[:500],
        "allowed_targets": _normalize_allowed_targets(allowed_targets),
        "contract_id": (contract_id or "").strip()[:80],
        "created_at": _now(),
        "updated_at": _now(),
    }
    return _persist_client(data)


def update_client(client_id: str, **fields: Any) -> dict[str, Any]:
    data = get_client(client_id)
    if not data:
        raise FileNotFoundError(f"Cliente '{client_id}' não encontrado.")
    allowed = {
        "display_name",
        "consulting_name",
        "consulting_logo_path",
        "consulting_color",
        "consulting_footer",
        "allowed_targets",
        "contract_id",
    }
    for key, value in fields.items():
        if key not in allowed or value is None:
            continue
        if key == "allowed_targets":
            data[key] = _normalize_allowed_targets(value)
        elif key == "contract_id":
            data[key] = str(value).strip()[:80]
        else:
            data[key] = str(value).strip()[:500]
    data["updated_at"] = _now()
    return _persist_client(data)


def list_client_targets(client_id: str) -> list[str]:
    """Targets sob o workspace do cliente (+ legado com client_id correspondente)."""
    from backend.executor.recon_db import normalize_target

    cid = normalize_client_id(client_id)
    found: set[str] = set()
    sdir = client_dir(cid) / "surface"
    if sdir.is_dir():
        for p in sdir.glob("*.json"):
            found.add(p.stem)
    if SURFACE_DIR.is_dir():
        for p in SURFACE_DIR.glob("*.json"):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            if not isinstance(data, dict):
                continue
            scid = normalize_client_id(str(data.get("client_id") or ""))
            if scid == cid or (
                cid == "default" and not data.get("client_id") and not data.get("client")
            ):
                found.add(normalize_target(str(data.get("target") or p.stem)))
    return sorted(found)


def _is_client_workspace_dir(path: Path) -> bool:
    if not path.is_dir():
        return False
    name = path.name
    if name.startswith(".") or name in _RESERVED_DIR_NAMES:
        return False
    # Workspace real tem meta.json (ou será criado via API)
    return bool(_CLIENT_ID_RE.match(normalize_client_id(name))) or (path / "meta.json").is_file()


def _migrate_all_client_files() -> None:
    if not CLIENTS_DIR.is_dir():
        return
    for path in CLIENTS_DIR.iterdir():
        if not _is_client_workspace_dir(path):
            continue
        get_client(path.name)


def list_clients() -> list[dict[str, Any]]:
    from backend.database.db import ensure_dashboard_db, session_scope
    from backend.database.models_store import ClientRecord

    ensure_default_client()
    items: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add_meta(meta: dict[str, Any] | None) -> None:
        if not meta:
            return
        cid = str(meta.get("client_id") or "")
        if not cid or cid in seen:
            return
        seen.add(cid)
        sdir = client_dir(cid) / "surface"
        file_n = sum(1 for _ in sdir.glob("*.json")) if sdir.is_dir() else 0
        allowed_n = len(meta.get("allowed_targets") or [])
        items.append({**meta, "targets_count": max(file_n, allowed_n), "targets": []})

    try:
        ensure_dashboard_db()
        with session_scope() as db:
            snapshots = [(row.client_id, row.payload_json) for row in db.query(ClientRecord).all()]
        for cid, payload in snapshots:
            try:
                data = json.loads(payload or "{}")
            except json.JSONDecodeError:
                data = {}
            if isinstance(data, dict):
                add_meta(_with_client_defaults({**data, "client_id": cid}))
    except Exception as exc:  # noqa: BLE001
        logger.warning("client_list_db_failed: %s", exc)

    if CLIENTS_DIR.is_dir():
        for path in CLIENTS_DIR.iterdir():
            if not _is_client_workspace_dir(path) or path.name in seen:
                continue
            add_meta(get_client(path.name))

    items.sort(key=lambda x: str(x.get("client_id") or ""))
    return items


def _erase_client_related(cid: str, targets: list[str]) -> dict[str, int]:
    """Limpa recon, agenda, chats/intel/PDF/logs e auditoria com este client_id."""
    counts = {"recon": 0, "schedules": 0, "sessions": 0, "audit_lines": 0}
    try:
        from backend.executor.data_cleanup import delete_logs_for_session, delete_recon

        for target in targets:
            if delete_recon(target):
                counts["recon"] += 1
    except Exception as exc:  # noqa: BLE001
        logger.warning("client_erase_recon_failed: %s", exc)

    try:
        from backend.schedule.store import delete_job, list_jobs

        for job in list_jobs(client_id=cid):
            jid = str(job.get("id") or "")
            if jid and delete_job(jid):
                counts["schedules"] += 1
    except Exception as exc:  # noqa: BLE001
        logger.warning("client_erase_schedule_failed: %s", exc)

    try:
        from backend.database.chat_store import delete_chat_session, list_chat_sessions
        from backend.database.reports_store import delete_reports_for_session
        from backend.executor.session_intel import delete_session_intel

        for sess in list_chat_sessions(include_messages=False, client_id=cid):
            sid = str(sess.get("id") or "")
            if not sid:
                continue
            try:
                delete_reports_for_session(sid)
            except Exception:  # noqa: BLE001
                logger.debug("client_erase_reports_skipped", exc_info=True)
            try:
                delete_session_intel(sid)
            except Exception:  # noqa: BLE001
                logger.debug("client_erase_intel_skipped", exc_info=True)
            try:
                delete_logs_for_session(sid)
            except Exception:  # noqa: BLE001
                logger.debug("client_erase_logs_skipped", exc_info=True)
            if delete_chat_session(sid):
                counts["sessions"] += 1
    except Exception as exc:  # noqa: BLE001
        logger.warning("client_erase_sessions_failed: %s", exc)

    try:
        from backend.security.audit import remove_entries_by_client_id

        counts["audit_lines"] = remove_entries_by_client_id(cid)
    except Exception as exc:  # noqa: BLE001
        logger.warning("client_erase_audit_failed: %s", exc)
    return counts


def delete_client(
    client_id: str, *, purge_surfaces: bool = False, erase_all: bool = False
) -> dict[str, Any]:
    """
    Remove workspace do cliente.
    Não permite apagar `default`.
    Com purge_surfaces=True, apaga também surfaces associados a esse client_id.
    Com erase_all=True, implica purge_surfaces e ainda apaga recon, agenda,
    chats/intel/PDFs/logs da sessão e linhas de auditoria com este client_id.
    Eventos de audit anteriores à feature (sem client_id) não são apagados.
    Idempotente: pasta/DB órfãos também são limpos (não 404 se já sumiu do meta).
    """
    import shutil

    from backend.clients.runtime import get_active_client_id, set_active_client_id
    from backend.database.db import ensure_dashboard_db, session_scope
    from backend.database.models_store import ClientRecord
    from backend.executor.data_cleanup import delete_surface

    cid = normalize_client_id(client_id)
    if cid == "default":
        raise ValueError("Não é permitido excluir o cliente padrão (default).")
    if erase_all:
        purge_surfaces = True

    meta = get_client(cid)
    cdir = client_dir(cid)
    has_dir = cdir.is_dir()
    has_db = False
    try:
        ensure_dashboard_db()
        with session_scope() as db:
            has_db = (
                db.query(ClientRecord).filter(ClientRecord.client_id == cid).first() is not None
            )
    except Exception as exc:  # noqa: BLE001
        logger.debug("client_db_exists_check_failed: %s", exc)

    if not meta and not has_dir and not has_db:
        # Já inexistente — trata como sucesso para o UI não ficar preso
        if get_active_client_id() == cid:
            set_active_client_id("default")
        return {
            "deleted": True,
            "client_id": cid,
            "already_gone": True,
            "targets_cleared": 0,
            "targets_listed": 0,
            "purge_surfaces": purge_surfaces,
            "erase_all": erase_all,
            "recon_cleared": 0,
            "schedules_cleared": 0,
            "sessions_cleared": 0,
            "audit_lines": 0,
            "active_client_id": get_active_client_id(),
        }

    targets = list_client_targets(cid) if (meta or has_dir) else []
    removed_surfaces = 0
    if purge_surfaces:
        for t in targets:
            if delete_surface(t):
                removed_surfaces += 1
    erase_counts = (
        _erase_client_related(cid, targets)
        if erase_all
        else {"recon": 0, "schedules": 0, "sessions": 0, "audit_lines": 0}
    )

    try:
        ensure_dashboard_db()
        with session_scope() as db:
            db.query(ClientRecord).filter(ClientRecord.client_id == cid).delete(
                synchronize_session=False
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("client_db_delete_failed: %s", exc)

    if cdir.is_dir():
        shutil.rmtree(cdir, ignore_errors=True)

    if get_active_client_id() == cid:
        set_active_client_id("default")

    return {
        "deleted": True,
        "client_id": cid,
        "already_gone": False,
        "targets_cleared": removed_surfaces if purge_surfaces else 0,
        "targets_listed": len(targets),
        "purge_surfaces": purge_surfaces,
        "erase_all": erase_all,
        "recon_cleared": erase_counts["recon"],
        "schedules_cleared": erase_counts["schedules"],
        "sessions_cleared": erase_counts["sessions"],
        "audit_lines": erase_counts["audit_lines"],
        "active_client_id": get_active_client_id(),
    }
