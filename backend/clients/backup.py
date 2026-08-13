"""Backup/restore de workspace de cliente (tar.gz)."""

from __future__ import annotations

import io
import json
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.clients.store import client_dir, get_client, normalize_client_id
from backend.config import CLIENTS_DIR, OUTPUTS_DIR, SURFACE_DIR
from backend.executor.recon_db import normalize_target


def backup_client(client_id: str) -> bytes:
    """Empacota meta + surfaces do cliente (+ legado associado)."""
    from backend.clients.store import list_client_targets
    from backend.executor.surface import load_surface

    cid = normalize_client_id(client_id)
    meta = get_client(cid)
    if not meta and cid != "default":
        raise FileNotFoundError(f"Cliente '{cid}' não encontrado")

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        manifest = {
            "client_id": cid,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "meta": meta,
            "targets": list_client_targets(cid),
        }
        raw = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
        info = tarfile.TarInfo(name="manifest.json")
        info.size = len(raw)
        tar.addfile(info, io.BytesIO(raw))

        cdir = client_dir(cid)
        if cdir.is_dir():
            for path in cdir.rglob("*"):
                if path.is_file():
                    arc = Path(cid) / path.relative_to(cdir)
                    tar.add(path, arcname=str(arc).replace("\\", "/"))

        # Surfaces legados associados
        for t in list_client_targets(cid):
            data = load_surface(t)
            if not data:
                continue
            # se já está no client dir, skip duplicata
            client_surf = cdir / "surface" / f"{normalize_target(t)}.json"
            if client_surf.is_file():
                continue
            legacy = SURFACE_DIR / f"{normalize_target(t)}.json"
            if legacy.is_file():
                tar.add(legacy, arcname=f"legacy_surface/{normalize_target(t)}.json")

    return buf.getvalue()


def restore_client(archive: bytes, *, overwrite: bool = False) -> dict[str, Any]:
    buf = io.BytesIO(archive)
    restored: list[str] = []
    with tarfile.open(fileobj=buf, mode="r:gz") as tar:
        members = tar.getmembers()
        manifest_member = next((m for m in members if m.name == "manifest.json"), None)
        if not manifest_member:
            raise ValueError("Arquivo inválido: sem manifest.json")
        f = tar.extractfile(manifest_member)
        if not f:
            raise ValueError("manifest ilegível")
        manifest = json.loads(f.read().decode("utf-8"))
        cid = normalize_client_id(str(manifest.get("client_id") or "default"))
        dest = CLIENTS_DIR / cid
        if dest.exists() and any(dest.iterdir()) and not overwrite:
            raise FileExistsError(f"Cliente '{cid}' já tem dados — use overwrite=true")
        dest.mkdir(parents=True, exist_ok=True)
        for m in members:
            if m.name in {"manifest.json"} or not m.isfile():
                continue
            name = m.name.replace("\\", "/")
            if name.startswith("legacy_surface/"):
                fname = Path(name).name
                out = SURFACE_DIR / fname
                SURFACE_DIR.mkdir(parents=True, exist_ok=True)
                src = tar.extractfile(m)
                if src:
                    out.write_bytes(src.read())
                    restored.append(f"legacy:{fname}")
                continue
            # strip client_id prefix
            parts = name.split("/", 1)
            rel = parts[1] if len(parts) == 2 and parts[0] == cid else name
            if ".." in rel:
                continue
            out = dest / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            src = tar.extractfile(m)
            if src:
                out.write_bytes(src.read())
                restored.append(rel)
    return {
        "client_id": cid,
        "restored_files": len(restored),
        "files": restored[:50],
        "manifest": manifest,
    }


def save_backup_file(client_id: str) -> str:
    raw = backup_client(client_id)
    out_dir = OUTPUTS_DIR / "backups"
    out_dir.mkdir(parents=True, exist_ok=True)
    cid = normalize_client_id(client_id)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = out_dir / f"{cid}-{stamp}.tar.gz"
    path.write_bytes(raw)
    return f"backups/{path.name}"
