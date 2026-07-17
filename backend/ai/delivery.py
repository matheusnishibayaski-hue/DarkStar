"""Bundle de entrega: ZIP com relatório + evidências + delta."""

from __future__ import annotations

import io
import json
import zipfile
from typing import Any

from backend.ai.delta import compute_delta
from backend.ai.evidence import list_evidence_files, read_evidence
from backend.ai.report import generate_report, generate_report_html
from backend.ai.risk_score import risk_score_for_target
from backend.ai.verify import confidence_gate_buckets
from backend.config import OUTPUTS_DIR
from backend.executor.recon_db import normalize_target
from backend.executor.surface import load_surface, surface_summary


def build_delivery_bundle(target: str) -> bytes:
    """Retorna bytes ZIP prontos para download."""
    data = load_surface(target)
    if not data:
        raise FileNotFoundError("Engajamento não encontrado.")

    t = normalize_target(target)
    client = data.get("client") or t
    title = f"Relatório — {client}"
    history = [
        {
            "role": "user",
            "content": (
                f"[Engajamento] Alvo: {target}\n"
                f"Cliente: {data.get('client') or '—'}\n"
                f"Objetivo: {data.get('objective') or '—'}\n"
                f"Escopo: {data.get('scope_notes') or '—'}"
            ),
        },
        {
            "role": "assistant",
            "content": f"Risk score e findings do surface {t}.",
        },
    ]
    md = generate_report(
        history, [], title=title, surface_target=target, snapshot_baseline=False
    )
    html_doc = generate_report_html(
        history, [], title=title, surface_target=target, snapshot_baseline=False
    )
    gate = confidence_gate_buckets(target)
    delta = compute_delta(target)
    risk = risk_score_for_target(target)
    meta: dict[str, Any] = {
        "target": t,
        "client": data.get("client"),
        "summary": surface_summary(data),
        "risk": risk,
        "gate_counts": {k: len(v) for k, v in gate.items()},
        "delta": {
            "has_baseline": delta.get("has_baseline"),
            "fixed": len(delta.get("fixed") or []),
            "new": len(delta.get("new") or []),
            "still_open": len(delta.get("still_open") or []),
        },
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("relatorio.md", md)
        zf.writestr("relatorio.html", html_doc)
        zf.writestr("meta.json", json.dumps(meta, ensure_ascii=False, indent=2))
        zf.writestr("delta.json", json.dumps(delta, ensure_ascii=False, indent=2))
        zf.writestr(
            "findings_executive.json",
            json.dumps(gate.get("executive") or [], ensure_ascii=False, indent=2),
        )
        # Evidências
        for ev in list_evidence_files(target):
            fid = ev["name"].replace(".txt", "")
            content = read_evidence(target, fid)
            if content:
                zf.writestr(f"evidencias/{ev['name']}", content)
        # Surface completo (auditoria)
        zf.writestr("surface.json", json.dumps(data, ensure_ascii=False, indent=2))

    return buf.getvalue()


def save_delivery_bundle(target: str) -> str:
    """Salva ZIP em OUTPUTS_DIR e retorna path relativo."""
    raw = build_delivery_bundle(target)
    t = normalize_target(target)
    out_dir = OUTPUTS_DIR / "delivery"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{t}-delivery.zip"
    path.write_bytes(raw)
    return f"delivery/{t}-delivery.zip"
