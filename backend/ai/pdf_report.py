"""Geração de relatório PDF simplificado para entrega ao cliente."""

from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from typing import Any
from xml.sax.saxutils import escape

from backend.deps import APP_VERSION
from backend.executor.recon_db import normalize_target
from backend.executor.surface import load_surface

_STATUS_LABELS = {
    "confirmed": "Positivo",
    "false_positive": "Falso positivo",
    "discarded": "Descartado",
    "candidate": "Pendente",
    "inconclusive": "Pendente",
}


def _sev_bucket(severity: str) -> str:
    s = (severity or "").lower()
    if s in {"critical", "high"}:
        return "alto"
    if s == "medium":
        return "medio"
    return "baixo"


def _group_findings(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups = {"alto": [], "medio": [], "baixo": []}
    for f in findings:
        groups[_sev_bucket(str(f.get("severity") or ""))].append(f)
    for key in groups:
        groups[key].sort(
            key=lambda x: (
                0
                if x.get("status") == "confirmed"
                else 1
                if x.get("status") == "false_positive"
                else 2
            )
        )
    return groups


def _pdf_text(value: Any) -> str:
    return escape(str(value or ""))


def generate_report_pdf(
    *,
    surface_target: str | None = None,
    session_id: str | None = None,
    title: str = "Relatório de Pentest",
    tool_executions: list[dict[str, Any]] | None = None,
) -> bytes:
    """PDF com achados por severidade e classificação manual (Positivo/FP/Descartado)."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:
        raise RuntimeError(
            "Dependência reportlab ausente. Rode: pip install -r requirements.txt"
        ) from exc

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=title,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontSize=18,
        spaceAfter=12,
        textColor=colors.HexColor("#0d3b2e"),
    )
    h2 = ParagraphStyle(
        "H2",
        parent=styles["Heading2"],
        fontSize=13,
        spaceBefore=14,
        spaceAfter=6,
        textColor=colors.HexColor("#14532d"),
    )
    h3 = ParagraphStyle(
        "H3",
        parent=styles["Heading3"],
        fontSize=11,
        spaceBefore=10,
        spaceAfter=4,
        textColor=colors.HexColor("#1b4332"),
    )
    body = styles["BodyText"]
    body.fontSize = 10
    body.leading = 14

    story: list[Any] = []
    now = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")

    findings: list[dict[str, Any]] = []
    display_name = ""
    target = ""
    surface = None
    session_targets: list[str] = []

    if session_id:
        from backend.executor.session_intel import (
            aggregate_session_findings,
            collect_session_tool_executions,
            load_session,
        )

        meta = load_session(session_id)
        findings = aggregate_session_findings(session_id)
        session_targets = list(meta.get("targets") or [])
        display_name = str(meta.get("label") or "").strip()
        if not display_name and session_targets:
            display_name = ", ".join(session_targets[:3])
            if len(session_targets) > 3:
                display_name += f" (+{len(session_targets) - 3})"
        if tool_executions is None:
            tool_executions = collect_session_tool_executions(session_id)
    else:
        target = normalize_target(surface_target) if surface_target else ""
        surface = load_surface(target) if target else None
        findings = list(surface.get("findings") or []) if surface else []
        if surface:
            display_name = str(surface.get("label") or surface.get("client") or "").strip()
        if not display_name and target:
            display_name = target

    groups = _group_findings(findings)
    doc_title = title if title and title != "Relatório de Pentest" else f"Relatório — {_pdf_text(display_name)}"

    story.append(Paragraph(_pdf_text(doc_title), title_style))
    meta_lines = [
        f"<b>Data:</b> {now}",
        f"<b>Ferramenta:</b> DarkStar v{APP_VERSION}",
    ]
    if display_name and display_name != target:
        meta_lines.append(f"<b>Nome:</b> {_pdf_text(display_name)}")
    if session_id and session_targets:
        targets_txt = ", ".join(_pdf_text(t) for t in session_targets[:8])
        meta_lines.append(f"<b>Alvos testados:</b> {targets_txt}")
        if len(session_targets) > 8:
            meta_lines[-1] += f" (+{len(session_targets) - 8})"
    elif target:
        meta_lines.append(f"<b>Alvo:</b> {_pdf_text(target)}")
    if surface:
        if surface.get("client") and surface.get("client") != display_name:
            meta_lines.append(f"<b>Cliente:</b> {_pdf_text(surface.get('client'))}")
        if surface.get("objective"):
            meta_lines.append(f"<b>Objetivo:</b> {_pdf_text(surface.get('objective'))}")
    story.append(Paragraph("<br/>".join(meta_lines), body))
    story.append(Spacer(1, 0.4 * cm))

    confirmed = [f for f in findings if f.get("status") == "confirmed"]
    fp = [f for f in findings if f.get("status") == "false_positive"]
    discarded = [f for f in findings if f.get("status") == "discarded"]
    pending = [f for f in findings if f.get("status") in {"candidate", "inconclusive", None, ""}]

    story.append(
        Paragraph(
            f"<b>Resumo:</b> {len(confirmed)} positivo(s) · "
            f"{len(fp)} falso(s) positivo(s) · {len(discarded)} descartado(s) · "
            f"{len(pending)} pendente(s)",
            body,
        )
    )
    story.append(Spacer(1, 0.5 * cm))

    sev_titles = {
        "alto": "Achados — Severidade ALTA",
        "medio": "Achados — Severidade MÉDIA",
        "baixo": "Achados — Severidade BAIXA",
    }
    for bucket, heading in sev_titles.items():
        items = groups[bucket]
        story.append(Paragraph(heading, h2))
        if not items:
            story.append(Paragraph("<i>Nenhum achado nesta faixa.</i>", body))
            story.append(Spacer(1, 0.2 * cm))
            continue
        rows = [["Título", "Classificação", "Ferramenta", "Alvo"]]
        for f in items:
            status = _STATUS_LABELS.get(str(f.get("status") or ""), "Pendente")
            host = str(f.get("surface_target") or f.get("host") or "—")[:40]
            rows.append(
                [
                    _pdf_text(f.get("title") or "—")[:120],
                    status,
                    _pdf_text(f.get("tool") or "—")[:40],
                    _pdf_text(host)[:40],
                ]
            )
        table = Table(rows, colWidths=[7 * cm, 3 * cm, 2.5 * cm, 3 * cm])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8f5e9")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#14532d")),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafafa")]),
                ]
            )
        )
        story.append(table)
        story.append(Spacer(1, 0.35 * cm))

    from backend.ai.remediation import remediation_for

    detail_items = [f for f in findings if str(f.get("status") or "") != "discarded"]
    if detail_items:
        story.append(Paragraph("Detalhamento — comando, evidência e correção", h2))
        for i, f in enumerate(detail_items, 1):
            status = _STATUS_LABELS.get(str(f.get("status") or ""), "Pendente")
            rem = remediation_for(f)
            host = str(f.get("surface_target") or f.get("host") or "—")
            cmd = str(f.get("command") or "—")
            evidence = str(f.get("evidence") or f.get("title") or "—")
            story.append(
                Paragraph(
                    f"<b>{i}. {_pdf_text(f.get('title') or 'Achado')}</b> "
                    f"({_pdf_text(status)} · {_pdf_text(f.get('severity') or '—')})",
                    h3,
                )
            )
            story.append(
                Paragraph(
                    f"<b>Alvo:</b> {_pdf_text(host)}<br/>"
                    f"<b>Comando executado:</b> "
                    f"<font face='Courier' size='8'>{_pdf_text(cmd)[:500]}</font>",
                    body,
                )
            )
            story.append(
                Paragraph(
                    f"<b>O que foi encontrado:</b><br/>{_pdf_text(evidence)[:1200]}",
                    body,
                )
            )
            story.append(
                Paragraph(
                    f"<b>Como corrigir — {_pdf_text(rem.get('title'))}:</b><br/>"
                    f"{_pdf_text(rem.get('action'))}",
                    body,
                )
            )
            story.append(Spacer(1, 0.25 * cm))

    execs = tool_executions or []
    if execs:
        story.append(Paragraph("Histórico de comandos executados", h2))
        for i, ex in enumerate(execs[:40], 1):
            cmd = _pdf_text(ex.get("command") or "")
            ok = "OK" if ex.get("success") else "FALHA"
            out = _pdf_text((ex.get("stdout") or ex.get("stderr") or "")[:400])
            story.append(
                Paragraph(
                    f"{i}. [{ok}] <font face='Courier' size='8'>{cmd[:200]}</font>",
                    body,
                )
            )
            if out:
                story.append(
                    Paragraph(
                        f"<font face='Courier' size='7'>{out}</font>",
                        body,
                    )
                )
        story.append(Spacer(1, 0.3 * cm))

    story.append(Spacer(1, 0.5 * cm))
    story.append(
        Paragraph(
            "<i>Uso autorizado apenas. Relatório gerado automaticamente — "
            "revise achados pendentes antes de entregar ao cliente.</i>",
            body,
        )
    )

    doc.build(story)
    return buf.getvalue()
