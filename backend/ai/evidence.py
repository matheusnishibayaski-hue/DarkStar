"""Pacotes de evidência por finding (arquivos em /tools/output + surface)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from backend.config import OUTPUTS_DIR
from backend.executor.recon_db import normalize_target
from backend.executor.surface import load_surface, save_surface


def evidence_dir(target: str) -> Path:
    root = OUTPUTS_DIR / "evidence" / normalize_target(target)
    root.mkdir(parents=True, exist_ok=True)
    return root


def write_finding_evidence(
    target: str,
    finding: dict[str, Any],
    *,
    command: str,
    stdout: str,
    stderr: str,
    reason: str,
    pass_number: int,
) -> str:
    """
    Persiste pacote de prova em OUTPUTS_DIR/evidence/{target}/{id}.txt
    e anexa path no finding. Retorna path relativo.
    """
    fid = str(finding.get("id") or "unknown")
    path = evidence_dir(target) / f"{fid}.txt"
    body = "\n".join(
        [
            f"# Evidence pack — {fid}",
            f"title: {finding.get('title')}",
            f"severity: {finding.get('severity')}",
            f"status: {finding.get('status')}",
            f"confidence: {finding.get('confidence')}",
            f"template_id: {finding.get('template_id')}",
            f"cve: {finding.get('cve')}",
            f"matched_at: {finding.get('matched_at') or finding.get('url')}",
            f"curl_command: {finding.get('curl_command')}",
            f"verify_pass: {pass_number}",
            f"reason: {reason}",
            "",
            "## PoC command",
            command or "(none)",
            "",
            "## stdout",
            (stdout or "")[:8000],
            "",
            "## stderr",
            (stderr or "")[:2000],
            "",
        ]
    )
    path.write_text(body, encoding="utf-8")
    rel = f"evidence/{normalize_target(target)}/{fid}.txt"
    # Atualiza finding no surface
    data = load_surface(target)
    if data:
        for f in data.get("findings") or []:
            if f.get("id") == fid:
                f["evidence_path"] = rel
                packs = list(f.get("evidence_packs") or [])
                if rel not in packs:
                    packs.append(rel)
                f["evidence_packs"] = packs[:5]
                save_surface(target, data)
                break
    return rel


def list_evidence_files(target: str) -> list[dict[str, Any]]:
    root = evidence_dir(target)
    items = []
    for p in sorted(root.glob("*.txt")):
        try:
            st = p.stat()
        except OSError:
            continue
        items.append(
            {
                "name": p.name,
                "path": f"evidence/{normalize_target(target)}/{p.name}",
                "size": st.st_size,
            }
        )
    return items


def read_evidence(target: str, finding_id: str) -> str:
    path = evidence_dir(target) / f"{finding_id}.txt"
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")[:20000]
