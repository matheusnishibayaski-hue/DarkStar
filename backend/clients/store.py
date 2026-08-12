"""CRUD de clientes locais — meta em backend/clients/{id}/meta.json."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.config import CLIENTS_DIR, CONSULTING_PRIMARY_COLOR

_CLIENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{0,62}[a-z0-9]$|^[a-z0-9]$")


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


def get_client(client_id: str) -> dict[str, Any] | None:
    path = meta_path(client_id)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


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
    path = meta_path(cid)
    if path.is_file():
        raise FileExistsError(f"Cliente '{cid}' já existe.")
    client_dir(cid).mkdir(parents=True, exist_ok=True)
    surface_dir(cid)
    logs_dir(cid)
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
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return data


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
    meta_path(client_id).write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return data


def list_client_targets(client_id: str) -> list[str]:
    """Targets sob o workspace do cliente (+ legado com client_id correspondente)."""
    from backend.executor.recon_db import normalize_target
    from backend.config import SURFACE_DIR

    cid = normalize_client_id(client_id)
    found: set[str] = set()
    sdir = client_dir(cid) / "surface"
    if sdir.is_dir():
        for p in sdir.glob("*.json"):
            found.add(p.stem)
    # Surfaces legados com client_id / client display
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


def list_clients() -> list[dict[str, Any]]:
    ensure_default_client()
    items: list[dict[str, Any]] = []
    if not CLIENTS_DIR.is_dir():
        return items
    for path in sorted(CLIENTS_DIR.iterdir()):
        if not path.is_dir():
            continue
        meta = get_client(path.name)
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
    """
    import shutil

    from backend.clients.runtime import get_active_client_id, set_active_client_id
    from backend.executor.data_cleanup import delete_surface

    cid = normalize_client_id(client_id)
    if cid == "default":
        raise ValueError("Não é permitido excluir o cliente padrão (default).")
    if not get_client(cid):
        raise FileNotFoundError(f"Cliente '{cid}' não encontrado.")

    targets = list_client_targets(cid)
    removed_surfaces = 0
    if purge_surfaces:
        for t in targets:
            if delete_surface(t):
                removed_surfaces += 1

    cdir = client_dir(cid)
    if cdir.is_dir():
        shutil.rmtree(cdir, ignore_errors=True)

    if get_active_client_id() == cid:
        set_active_client_id("default")

    return {
        "deleted": True,
        "client_id": cid,
        "targets_cleared": removed_surfaces if purge_surfaces else 0,
        "targets_listed": len(targets),
        "purge_surfaces": purge_surfaces,
        "active_client_id": get_active_client_id(),
    }
