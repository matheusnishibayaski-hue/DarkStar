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
    data = {**data, "client_id": cid}
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
        meta_path(cid).write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )
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
                    return data
    except Exception as exc:  # noqa: BLE001
        logger.debug("client_db_get_failed: %s", exc)

    file_data = _read_meta_file(cid)
    if file_data:
        try:
            return _persist_client(file_data)
        except Exception as exc:  # noqa: BLE001
            logger.warning("client_migrate_failed: %s", exc)
            return file_data
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
) -> dict[str, Any]:
    cid = normalize_client_id(client_id)
    if cid != "default" and not _CLIENT_ID_RE.match(cid):
        raise ValueError(
            "client_id inválido — use slug [a-z0-9-] (1–64 chars)."
        )
    if get_client(cid):
        raise FileExistsError(f"Cliente '{cid}' já existe.")
    data = {
        "client_id": cid,
        "display_name": (display_name or cid).strip()[:200],
        "consulting_name": (consulting_name or "").strip()[:120],
        "consulting_logo_path": (consulting_logo_path or "").strip()[:500],
        "consulting_color": (consulting_color or CONSULTING_PRIMARY_COLOR).strip()[:32],
        "consulting_footer": (consulting_footer or "").strip()[:500],
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
    }
    for key, value in fields.items():
        if key in allowed and value is not None:
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
                cid == "default"
                and not data.get("client_id")
                and not data.get("client")
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
    return bool(_CLIENT_ID_RE.match(normalize_client_id(name))) or (
        path / "meta.json"
    ).is_file()


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
    _migrate_all_client_files()

    ids: list[str] = []
    try:
        ensure_dashboard_db()
        with session_scope() as db:
            ids = [r.client_id for r in db.query(ClientRecord.client_id).all()]
    except Exception as exc:  # noqa: BLE001
        logger.warning("client_list_db_failed: %s", exc)

    if not ids and CLIENTS_DIR.is_dir():
        ids = [p.name for p in CLIENTS_DIR.iterdir() if p.is_dir()]

    items: list[dict[str, Any]] = []
    for cid in sorted(set(ids)):
        meta = get_client(cid)
        if not meta:
            continue
        targets = list_client_targets(meta["client_id"])
        items.append({**meta, "targets_count": len(targets), "targets": targets})
    return items


def delete_client(client_id: str, *, purge_surfaces: bool = False) -> dict[str, Any]:
    """
    Remove workspace do cliente.
    Não permite apagar `default`.
    Com purge_surfaces=True, apaga também surfaces associados a esse client_id.
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

    meta = get_client(cid)
    cdir = client_dir(cid)
    has_dir = cdir.is_dir()
    has_db = False
    try:
        ensure_dashboard_db()
        with session_scope() as db:
            has_db = (
                db.query(ClientRecord)
                .filter(ClientRecord.client_id == cid)
                .first()
                is not None
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
            "active_client_id": get_active_client_id(),
        }

    targets = list_client_targets(cid) if (meta or has_dir) else []
    removed_surfaces = 0
    if purge_surfaces:
        for t in targets:
            if delete_surface(t):
                removed_surfaces += 1

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
        "active_client_id": get_active_client_id(),
    }
