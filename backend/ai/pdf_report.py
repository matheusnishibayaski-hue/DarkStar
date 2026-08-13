"""Geração de relatório PDF comercial — capa DarkStar + executivo + técnico."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from backend.deps import APP_VERSION
from backend.executor.recon_db import normalize_target
from backend.executor.surface import load_surface

_STATUS_LABELS = {
    "confirmed": "Vulnerabilidade confirmada",
    "false_positive": "Falso positivo",
    "discarded": "Descartado",
    "candidate": "Pendente de triagem",
    "inconclusive": "Inconclusivo",
}

_HEX_COLOR_RE = re.compile(r"^#?[0-9a-fA-F]{6}$")
_DEFAULT_LOGO = "assets/darkstar-logo.png"
_DEFAULT_COLOR = "#1E90FF"


def _sev_bucket(severity: str) -> str:
    s = (severity or "").lower()
    if s in {"critical", "high", "alto", "grave"}:
        return "alto"
    if s in {"medium", "medio", "média", "atencao", "atenção"}:
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


def _md_to_flowables(text: str, styles: dict[str, Any]) -> list[Any]:
    from reportlab.platypus import Paragraph, Spacer
    from reportlab.lib.units import cm

    flow: list[Any] = []
    for raw_line in (text or "").splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            flow.append(Spacer(1, 0.12 * cm))
            continue
        if line.startswith("### "):
            flow.append(Paragraph(_pdf_text(line[4:]), styles["h3"]))
            continue
        if line.startswith("## "):
            flow.append(Paragraph(_pdf_text(line[3:]), styles["h2"]))
            continue
        bullet = False
        if line.lstrip().startswith(("- ", "* ")):
            bullet = True
            line = line.lstrip()[2:]
        html = _pdf_text(line)
        html = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", html)
        if bullet:
            html = f"• {html}"
        flow.append(Paragraph(html, styles["body"]))
    return flow


def _resolve_brand(surface: dict[str, Any] | None) -> dict[str, str]:
    from backend.config import (
        CONSULTING_FOOTER,
        CONSULTING_LOGO_PATH,
        CONSULTING_NAME,
        CONSULTING_PRIMARY_COLOR,
        REPORT_BRAND_NAME,
    )

    name = CONSULTING_NAME or REPORT_BRAND_NAME or "DarkStar"
    color = CONSULTING_PRIMARY_COLOR or _DEFAULT_COLOR
    logo = CONSULTING_LOGO_PATH or _DEFAULT_LOGO
    footer = CONSULTING_FOOTER or "Documento confidencial — uso autorizado apenas."
    if surface:
        if surface.get("brand_name"):
            name = str(surface["brand_name"])
        cid = str(surface.get("client_id") or "")
        if cid and cid != "default":
            try:
                from backend.clients.store import get_client

                meta = get_client(cid)
                if meta:
                    if meta.get("consulting_name"):
                        name = str(meta["consulting_name"])
                    if meta.get("consulting_color"):
                        color = str(meta["consulting_color"])
                    if meta.get("consulting_logo_path"):
                        logo = str(meta["consulting_logo_path"])
                    if meta.get("consulting_footer"):
                        footer = str(meta["consulting_footer"])
            except Exception:  # noqa: BLE001
                pass
    if not _HEX_COLOR_RE.match(color):
        color = _DEFAULT_COLOR
    if not color.startswith("#"):
        color = f"#{color}"
    return {
        "name": name,
        "color": color,
        "logo": logo or _DEFAULT_LOGO,
        "footer": footer,
    }


def _safe_logo_path(logo_rel: str) -> Path | None:
    from backend.config import BASE_DIR

    candidates: list[str] = []
    if logo_rel:
        candidates.append(logo_rel)
    candidates.append(_DEFAULT_LOGO)
    for rel in candidates:
        raw = Path(rel)
        cand = raw.resolve() if raw.is_absolute() else (BASE_DIR / rel).resolve()
        try:
            cand.relative_to(BASE_DIR.resolve())
        except ValueError:
            continue
        if cand.is_file() and cand.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif"}:
            return cand
    return None


def _section_banner(title: str, subtitle: str, primary, header_bg, styles) -> list[Any]:
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors

    inner = [
        [
            Paragraph(f"<b>{_pdf_text(title)}</b>", styles["banner_title"]),
            Paragraph(_pdf_text(subtitle), styles["banner_sub"]),
        ]
    ]
    t = Table(inner, colWidths=[16 * cm])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), header_bg),
                ("BOX", (0, 0), (-1, -1), 1.2, primary),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    return [Spacer(1, 0.15 * cm), t, Spacer(1, 0.35 * cm)]


def _meta_table(rows: list[list[str]], primary, header_bg) -> Any:
    from reportlab.platypus import Table, TableStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors

    data = [[_pdf_text(a), _pdf_text(b)] for a, b in rows]
    t = Table(data, colWidths=[4.2 * cm, 11.8 * cm])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), header_bg),
                ("TEXTCOLOR", (0, 0), (0, -1), primary),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.Color(0.75, 0.75, 0.78)),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return t


def _append_iso_soc2(
    story,
    findings,
    target,
    h2,
    h3,
    body,
    primary,
    header_bg,
    *,
    page_break: bool = True,
    report: dict | None = None,
) -> None:
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.platypus import PageBreak, Paragraph, Spacer, Table, TableStyle

    try:
        if report is None:
            from backend.compliance.reporter import generate_compliance_report

            report = generate_compliance_report(
                str(target or "session"), ["ISO27001", "SOC2"], findings=findings or []
            )
    except Exception:  # noqa: BLE001
        return
    if not report:
        return
    if page_break:
        story.append(PageBreak())
        story.append(Paragraph("03  ·  Conformidade indicativa ISO 27001 / SOC 2", h2))
    story.append(
        Paragraph(
            f"<i>{_pdf_text(report.get('disclaimer_pt'))}</i>",
            body,
        )
    )
    story.append(
        Paragraph(
            "Cobertura <b>indicativa</b> (mapeamento por palavras-chave dos achados). "
            "Não substitui certificação ISO/IEC 27001 nem atestado SOC 2 Type I/II.",
            body,
        )
    )
    story.append(Spacer(1, 0.2 * cm))
    for fw_id, fw in (report.get("frameworks") or {}).items():
        cov = fw.get("indicative_coverage_0_100", 0)
        story.append(
            Paragraph(
                f"{_pdf_text(fw.get('name') or fw_id)} — cobertura indicativa {cov}% "
                f"({fw.get('gaps', 0)} gap(s) / {fw.get('controls_total', 0)} controles)",
                h3,
            )
        )
        rows = [["Controle", "Crítico", "Gap", "Achados"]]
        for c in fw.get("controls") or []:
            rows.append(
                [
                    f"{c.get('id')} {c.get('name')}"[:70],
                    "sim" if c.get("critical") else "não",
                    "sim" if c.get("gap") else "não",
                    str(len(c.get("matched_findings") or [])),
                ]
            )
        table = Table(rows, colWidths=[9 * cm, 2.2 * cm, 2.2 * cm, 2.6 * cm])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), primary),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.Color(0.8, 0.82, 0.85)),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, header_bg]),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(table)
        story.append(Spacer(1, 0.25 * cm))


def _append_triage_annex(story, fp, pending, h2, body) -> None:
    from reportlab.platypus import Paragraph, Spacer
    from reportlab.lib.units import cm

    story.append(Paragraph("Anexo — rastreabilidade da triagem humana", h2))
    story.append(
        Paragraph(
            f"Falsos positivos: {len(fp or [])}. Pendentes (não validados): {len(pending or [])}. "
            "Pendentes não entram no risco residual executivo.",
            body,
        )
    )
    for f in (fp or [])[:15]:
        story.append(
            Paragraph(
                f"• FP: {_pdf_text(f.get('title') or '—')[:160]}",
                body,
            )
        )
    for f in (pending or [])[:15]:
        story.append(
            Paragraph(
                f"• Pendente: {_pdf_text(f.get('title') or '—')[:160]}",
                body,
            )
        )
    story.append(Spacer(1, 0.25 * cm))


def _bar_drawing(
    rows: list[tuple[str, int, str]],
    width: float = 460,
    row_h: float = 16,
    max_value: int | None = None,
):
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.lib import colors as rlcolors

    if not rows:
        from reportlab.platypus import Spacer as _Sp

        return _Sp(1, 1)
    maxv = int(max_value) if max_value and max_value > 0 else max((int(v) for _, v, _ in rows), default=1)
    maxv = max(1, maxv)
    h = 8 + len(rows) * (row_h + 3)
    d = Drawing(width, h)
    y = h - 12
    for label, value, col in rows:
        d.add(String(0, y, str(label)[:22], fontSize=8, fillColor=rlcolors.HexColor("#4B5563")))
        d.add(Rect(110, y - 2, 300, 10, fillColor=rlcolors.HexColor("#E5E7EB"), strokeColor=None))
        bar_w = min(300.0, 300.0 * max(0, int(value)) / maxv)
        d.add(Rect(110, y - 2, bar_w, 10, fillColor=rlcolors.HexColor(col), strokeColor=None))
        d.add(String(418, y, str(int(value)), fontSize=8, fillColor=rlcolors.HexColor("#111827")))
        y -= row_h + 3
    return d


def _pdf_from_session_model(
    *,
    session_id: str,
    title: str,
    tool_executions: list[dict[str, Any]] | None,
    history: list[dict[str, Any]] | None,
) -> bytes:
    """PDF da conversa no mesmo modelo da pré-visualização."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        KeepTogether,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    from backend.ai.report_model import assemble_session_report
    from backend.deps import APP_VERSION

    model = assemble_session_report(
        history=history,
        tool_executions=tool_executions,
        session_id=session_id,
        title=title,
    )
    primary = colors.HexColor("#1E90FF")
    ink = colors.HexColor("#111827")
    muted = colors.HexColor("#6B7280")
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=1.8 * cm,
        rightMargin=1.8 * cm,
        topMargin=1.6 * cm,
        bottomMargin=1.6 * cm,
        title=model["title"],
        author="DarkStar Argus",
    )
    base = getSampleStyleSheet()
    h1 = ParagraphStyle(
        "S1",
        parent=base["Heading1"],
        fontSize=18,
        textColor=ink,
        spaceAfter=6,
        fontName="Helvetica-Bold",
    )
    h2 = ParagraphStyle(
        "S2",
        parent=base["Heading2"],
        fontSize=12,
        textColor=primary,
        spaceBefore=14,
        spaceAfter=8,
        fontName="Helvetica-Bold",
        borderPadding=2,
    )
    h3 = ParagraphStyle(
        "S3",
        parent=base["Heading3"],
        fontSize=11,
        textColor=ink,
        spaceBefore=8,
        spaceAfter=4,
        fontName="Helvetica-Bold",
    )
    body = ParagraphStyle("SB", parent=base["BodyText"], fontSize=9.5, leading=13, textColor=ink)
    small = ParagraphStyle("SS", parent=body, fontSize=8, textColor=muted)
    brand = ParagraphStyle(
        "BR",
        parent=body,
        fontSize=8,
        textColor=primary,
        fontName="Helvetica-Bold",
        spaceAfter=4,
    )

    story: list[Any] = []
    alvos = ", ".join(str(t) for t in (model["targets"] or [])) or "—"
    story.append(Paragraph(f"DARKSTAR · ARGUS v{_pdf_text(APP_VERSION)}", brand))
    story.append(Paragraph(_pdf_text(model["title"]), h1))
    story.append(
        Paragraph(
            f"CONFIDENCIAL · {_pdf_text(model['now'])} · Alvo(s): {_pdf_text(alvos)}",
            small,
        )
    )
    story.append(Spacer(1, 0.25 * cm))
    risk = model["risk"] or {}
    kpi = Table(
        [
            [
                f"{len(model['executions'])}\ntestes",
                f"{len(model['findings'])}\nachados",
                f"{len(model['confirmed'])}\nconfirmados",
                f"{len(model['fps'])}\nfalsos +",
                f"{risk.get('score', 0)}\nrisco",
            ]
        ],
        colWidths=[3.2 * cm] * 5,
    )
    kpi.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E5E7EB")),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(kpi)
    story.append(Paragraph(f"Risco residual: <b>{_pdf_text(risk.get('label'))}</b> (somente confirmados).", body))

    sev = model.get("severity") or {}
    score = max(0, min(100, int(risk.get("score") or 0)))
    risk_color = "#166534" if score < 20 else "#d97706" if score < 45 else "#dc2626"
    story.append(Paragraph("Indicadores", h2))
    story.append(Paragraph("Risco residual (somente confirmados)", h3))
    story.append(_bar_drawing([("Risco /100", score, risk_color)], max_value=100))
    story.append(Paragraph("Gravidade (achados ativos)", h3))
    story.append(
        _bar_drawing(
            [
                ("Crítico", int(sev.get("critical") or 0), "#7f1d1d"),
                ("Grave", int(sev.get("high") or 0), "#dc2626"),
                ("Atenção", int(sev.get("medium") or 0), "#d97706"),
                ("Leve", int(sev.get("low") or 0), "#2563eb"),
                ("Informação", int(sev.get("info") or 0), "#6b7280"),
            ]
        )
    )
    story.append(Spacer(1, 0.15 * cm))
    story.append(Paragraph("Triagem", h3))
    story.append(
        _bar_drawing(
            [
                ("Confirmados", len(model["confirmed"]), "#166534"),
                ("Alarme falso", len(model["fps"]), "#d97706"),
                ("Pendentes", len(model["pending"]), "#2563eb"),
                ("Descartados", len(model.get("discarded") or []), "#9ca3af"),
            ]
        )
    )
    story.append(Spacer(1, 0.15 * cm))
    story.append(Paragraph("ISO 27001 / SOC 2 (indicativo %)", h3))
    story.append(
        _bar_drawing(
            [
                ("ISO 27001", int(model.get("iso_cov") or 0), "#166534"),
                ("SOC 2", int(model.get("soc_cov") or 0), "#1e90ff"),
            ],
            max_value=100,
        )
    )
    kinds = list((model.get("kinds") or {}).items())[:8]
    if kinds:
        story.append(Spacer(1, 0.12 * cm))
        story.append(Paragraph("Tipos de achado", h3))
        story.append(_bar_drawing([(k, int(v), "#1e90ff") for k, v in kinds]))
    tools = list((model.get("tools") or {}).items())[:8]
    if tools:
        story.append(Paragraph("Ferramentas usadas", h3))
        story.append(_bar_drawing([(k, int(v), "#111827") for k, v in tools]))

    story.append(Paragraph("1. Resumo executivo", h2))
    story.append(Paragraph(_pdf_text(model.get("executive") or ""), body))

    story.append(Paragraph("2. Escopo", h2))
    story.append(Paragraph(_pdf_text(model["scope"]), body))
    story.append(
        Paragraph(
            "Engajamento assistido (reconhecimento → enumeração → varredura → verificação). "
            "Testes em container Kali isolado.",
            body,
        )
    )

    story.append(Paragraph("3. Testes realizados", h2))
    story.append(
        Paragraph(
            f"{model['ok_exec']} execução(ões) com sucesso · {model['fail_exec']} falha(s)/bloqueio(s).",
            body,
        )
    )
    if not model["executions"]:
        story.append(Paragraph("Nenhum comando executado ainda.", body))
    for i, ex in enumerate(model["executions"][:60], 1):
        ok = "OK" if ex.get("success") else "FALHA"
        cmd = _pdf_text(ex.get("command") or "—")[:500]
        out = _pdf_text((ex.get("stdout") or ex.get("stderr") or "")[:2500])
        block = [
            Paragraph(f"<b>{i}.</b> [{ok}] <font face='Courier' size='8'>{cmd}</font>", body),
        ]
        if out.strip():
            block.append(Paragraph(f"<font face='Courier' size='7'>{out}</font>", small))
        block.append(Spacer(1, 0.12 * cm))
        story.append(KeepTogether(block))

    story.append(Paragraph("4. O que foi encontrado", h2))
    if not model["findings"]:
        story.append(Paragraph("Nenhum achado estruturado ainda.", body))
    for i, f in enumerate(model["findings"][:120], 1):
        status = _STATUS_LABELS.get(str(f.get("status") or ""), str(f.get("status") or "Pendente"))
        sev_l = f.get("severity_label") or f.get("severity") or "—"
        headline = f.get("plain_title") or f.get("title") or "Achado"
        host = f.get("surface_target") or f.get("host") or "—"
        cmd = str(f.get("command") or "")[:500]
        evidence = str(f.get("evidence") or "")[:1600]
        bits = [
            Paragraph(f"<b>{i}. {_pdf_text(headline)}</b>", h3),
            Paragraph(
                f"{_pdf_text(sev_l)} · {_pdf_text(status)} · "
                f"{_pdf_text(f.get('kind_label') or '—')} · "
                f"{_pdf_text(f.get('tool') or '—')} · {_pdf_text(host)}",
                small,
            ),
        ]
        tech = str(f.get("title") or "")
        if tech and tech != headline:
            bits.append(Paragraph(f"Nome técnico: {_pdf_text(tech)}", small))
        if f.get("what_it_is"):
            bits.append(Paragraph(_pdf_text(f["what_it_is"]), body))
        if f.get("everyday"):
            bits.append(Paragraph(f"<i>{_pdf_text(f['everyday'])}</i>", body))
        if f.get("why_it_matters"):
            bits.append(Paragraph(f"<b>Por que importa:</b> {_pdf_text(f['why_it_matters'])}", body))
        for hap in (f.get("could_happen") or [])[:4]:
            bits.append(Paragraph(f"• {_pdf_text(hap)}", body))
        decide = list(f.get("how_to_decide") or [])[:4]
        if decide:
            bits.append(Paragraph("<b>Como decidir:</b>", body))
            for d in decide:
                bits.append(Paragraph(f"• {_pdf_text(d)}", body))
        if cmd:
            bits.append(
                Paragraph(
                    f"<b>Comando:</b> <font face='Courier' size='8'>{_pdf_text(cmd)}</font>",
                    body,
                )
            )
        if evidence:
            bits.append(Paragraph(f"<b>Evidência:</b> {_pdf_text(evidence)}", body))
        bits.append(Spacer(1, 0.12 * cm))
        story.append(KeepTogether(bits))

    story.append(Paragraph("5. Como corrigir", h2))
    rems = model["remediations"] or []
    if not rems:
        story.append(
            Paragraph(
                "Sem plano de correção ainda — aparece quando houver achados (além de logs de teste).",
                body,
            )
        )
    for i, r in enumerate(rems[:60], 1):
        bits = [
            Paragraph(f"<b>{i}. {_pdf_text(r.get('remediation_title') or 'Correção')}</b>", h3),
            Paragraph(
                f"Achado: {_pdf_text(r.get('finding_title'))} · "
                f"{_pdf_text(r.get('severity_label') or r.get('severity') or '')}",
                body,
            ),
        ]
        if r.get("who"):
            bits.append(Paragraph(f"<b>Quem faz:</b> {_pdf_text(r['who'])}", body))
        if r.get("why"):
            bits.append(Paragraph(_pdf_text(r["why"]), body))
        steps = list(r.get("steps") or [])
        if steps:
            bits.append(Paragraph("<b>Passo a passo</b>", body))
            for n, s in enumerate(steps, 1):
                bits.append(Paragraph(f"{n}. {_pdf_text(s)}", body))
        elif r.get("action"):
            bits.append(Paragraph(_pdf_text(r["action"]), body))
        if r.get("verify"):
            bits.append(
                Paragraph(f"<b>Como saber que corrigiu:</b> {_pdf_text(r['verify'])}", body)
            )
        bits.append(Spacer(1, 0.15 * cm))
        story.append(KeepTogether(bits))

    story.append(Paragraph("6. Notas da conversa", h2))
    notes = list(model.get("notes") or [])
    if notes:
        for n, text in enumerate(notes[-4:], 1):
            story.append(Paragraph(f"<b>Nota {n}</b>", h3))
            story.append(Paragraph(_pdf_text(text[:2200]), body))
    else:
        story.append(Paragraph("A Argus ainda não registrou análise nesta conversa.", body))

    story.append(Paragraph("7. Conformidade indicativa ISO 27001 / SOC 2", h2))
    _append_iso_soc2(
        story,
        model["findings"],
        model["target"] or "session",
        h2,
        h3,
        body,
        primary,
        colors.HexColor("#E8F4FF"),
        page_break=False,
        report=model.get("compliance"),
    )

    story.append(Paragraph("8. Metodologia e limitações", h2))
    story.append(
        Paragraph(
            "Reconhecimento, enumeração, varredura e verificação PoC não destrutiva. "
            "WAF/CDN podem gerar falsos negativos; ausência de achado não garante segurança. "
            "Gravidade usa o tipo do achado e a tag do scanner. "
            "ISO/SOC 2 é mapeamento indicativo, não certificação. "
            "Revise pendentes antes da entrega ao cliente.",
            body,
        )
    )
    story.append(Spacer(1, 0.4 * cm))
    story.append(
        Paragraph(
            "Documento gerado automaticamente a partir desta conversa — mesmo conteúdo da pré-visualização.",
            small,
        )
    )

    def _on_page(canvas, doc_):  # noqa: ANN001
        canvas.saveState()
        canvas.setFillColor(primary)
        canvas.rect(0, A4[1] - 0.28 * cm, A4[0], 0.28 * cm, fill=1, stroke=0)
        canvas.setFillColor(muted)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(1.8 * cm, 0.9 * cm, "DarkStar · Argus · confidencial")
        canvas.drawRightString(A4[0] - 1.8 * cm, 0.9 * cm, f"p. {doc_.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    return buf.getvalue()


def generate_report_pdf(
    *,
    surface_target: str | None = None,
    session_id: str | None = None,
    title: str = "Relatório de Pentest",
    tool_executions: list[dict[str, Any]] | None = None,
    history: list[dict[str, Any]] | None = None,
    regenerate_executive: bool = False,
) -> bytes:
    """PDF profissional: capa + sumário executivo + sumário técnico."""
    if session_id:
        return _pdf_from_session_model(
            session_id=session_id,
            title=title,
            tool_executions=tool_executions,
            history=history,
        )
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            HRFlowable,
            Image,
            KeepTogether,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise RuntimeError(
            "Dependência reportlab ausente. Rode: pip install -r requirements.txt"
        ) from exc

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
            display_name = str(
                surface.get("label") or surface.get("client") or ""
            ).strip()
        if not display_name and target:
            display_name = target

    brand = _resolve_brand(surface)
    primary = colors.HexColor(brand["color"])
    ink = colors.HexColor("#111827")
    muted = colors.HexColor("#6B7280")
    try:
        header_bg = colors.Color(
            min(primary.red * 0.12 + 0.92, 1),
            min(primary.green * 0.12 + 0.94, 1),
            min(primary.blue * 0.18 + 0.97, 1),
        )
    except Exception:  # noqa: BLE001
        header_bg = colors.HexColor("#E8F4FF")

    buf = BytesIO()
    integrity_holder: dict[str, str] = {"hash": ""}
    logo_path = _safe_logo_path(brand["logo"])

    def _on_page(canvas, doc):  # noqa: ANN001
        canvas.saveState()
        # Barra superior
        canvas.setFillColor(primary)
        canvas.rect(0, A4[1] - 0.35 * cm, A4[0], 0.35 * cm, fill=1, stroke=0)
        # Mini logo no header (páginas 2+)
        if doc.page > 1 and logo_path:
            try:
                canvas.drawImage(
                    str(logo_path),
                    1.6 * cm,
                    A4[1] - 1.55 * cm,
                    width=1.1 * cm,
                    height=1.1 * cm,
                    preserveAspectRatio=True,
                    mask="auto",
                )
            except Exception:  # noqa: BLE001
                pass
        canvas.setFillColor(ink)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawString(
            2.9 * cm if doc.page > 1 and logo_path else 2 * cm,
            A4[1] - 1.15 * cm,
            brand["name"][:50],
        )
        canvas.setFillColor(muted)
        canvas.setFont("Helvetica", 7)
        canvas.drawRightString(A4[0] - 2 * cm, A4[1] - 1.15 * cm, "Relatório de Segurança")
        # Linha sob header
        canvas.setStrokeColor(primary)
        canvas.setLineWidth(0.6)
        canvas.line(2 * cm, A4[1] - 1.45 * cm, A4[0] - 2 * cm, A4[1] - 1.45 * cm)
        # Footer
        canvas.setStrokeColor(colors.Color(0.85, 0.85, 0.87))
        canvas.line(2 * cm, 1.55 * cm, A4[0] - 2 * cm, 1.55 * cm)
        canvas.setFillColor(muted)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(2 * cm, 1.05 * cm, brand["footer"][:85])
        right = f"p. {doc.page}"
        if integrity_holder["hash"]:
            right = f"SHA-256 {integrity_holder['hash'][:12]}…  ·  {right}"
        canvas.drawRightString(A4[0] - 2 * cm, 1.05 * cm, right)
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2.4 * cm,
        bottomMargin=2.2 * cm,
        title=title,
        author=brand["name"],
    )
    base = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=base["Heading1"],
        fontSize=22,
        leading=26,
        spaceAfter=6,
        textColor=ink,
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
    )
    cover_sub = ParagraphStyle(
        "CoverSub",
        parent=base["Normal"],
        fontSize=11,
        leading=14,
        textColor=muted,
        alignment=TA_CENTER,
        spaceAfter=4,
    )
    conf_badge = ParagraphStyle(
        "ConfBadge",
        parent=base["Normal"],
        fontSize=9,
        textColor=primary,
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
        spaceBefore=8,
        spaceAfter=14,
    )
    h2 = ParagraphStyle(
        "H2",
        parent=base["Heading2"],
        fontSize=13,
        spaceBefore=12,
        spaceAfter=6,
        textColor=primary,
        fontName="Helvetica-Bold",
    )
    h3 = ParagraphStyle(
        "H3",
        parent=base["Heading3"],
        fontSize=11,
        spaceBefore=10,
        spaceAfter=4,
        textColor=ink,
        fontName="Helvetica-Bold",
    )
    body = ParagraphStyle(
        "BodyCustom",
        parent=base["BodyText"],
        fontSize=10,
        leading=14,
        textColor=ink,
    )
    banner_title = ParagraphStyle(
        "BannerTitle",
        parent=base["Normal"],
        fontSize=12,
        textColor=primary,
        fontName="Helvetica-Bold",
        alignment=TA_LEFT,
    )
    banner_sub = ParagraphStyle(
        "BannerSub",
        parent=base["Normal"],
        fontSize=8,
        textColor=muted,
        spaceBefore=2,
    )
    md_styles = {"h2": h2, "h3": h3, "body": body}
    styles_extra = {
        "banner_title": banner_title,
        "banner_sub": banner_sub,
    }

    story: list[Any] = []
    now = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")
    groups = _group_findings(findings)
    doc_title = (
        title
        if title and title != "Relatório de Pentest"
        else f"Relatório de Segurança — {display_name or target or 'Engajamento'}"
    )

    # ========== CAPA ==========
    story.append(Spacer(1, 1.8 * cm))
    if logo_path:
        try:
            img = Image(str(logo_path), width=5.2 * cm, height=5.2 * cm, kind="proportional")
            img.hAlign = "CENTER"
            story.append(img)
            story.append(Spacer(1, 0.45 * cm))
        except Exception:  # noqa: BLE001
            pass
    story.append(Paragraph(_pdf_text(brand["name"]).upper(), cover_sub))
    story.append(Paragraph(_pdf_text(doc_title), title_style))
    story.append(Paragraph("CONFIDENCIAL", conf_badge))
    story.append(
        HRFlowable(
            width="60%",
            thickness=1.5,
            color=primary,
            spaceBefore=2,
            spaceAfter=16,
            hAlign="CENTER",
        )
    )

    meta_rows: list[list[str]] = [
        ["Data", now],
        ["Plataforma", f"DarkStar · Argus v{APP_VERSION}"],
        ["Emitido por", brand["name"]],
    ]
    if display_name and display_name != target:
        meta_rows.append(["Cliente / Nome", display_name])
    if session_id and session_targets:
        meta_rows.append(["Alvos", ", ".join(session_targets[:8])])
    elif target:
        meta_rows.append(["Alvo", target])
    if surface:
        if surface.get("client") and surface.get("client") != display_name:
            meta_rows.append(["Cliente", str(surface.get("client"))])
        if surface.get("client_id"):
            meta_rows.append(["Workspace", str(surface.get("client_id"))])
        if surface.get("objective"):
            meta_rows.append(["Objetivo", str(surface.get("objective"))[:180]])
        if surface.get("lifecycle"):
            meta_rows.append(["Status", str(surface.get("lifecycle"))])
    story.append(_meta_table(meta_rows, primary, header_bg))
    story.append(Spacer(1, 1.2 * cm))
    story.append(
        Paragraph(
            "<i>Este documento contém informações sensíveis de segurança. "
            "Distribuição restrita às partes autorizadas do engajamento.</i>",
            cover_sub,
        )
    )
    story.append(PageBreak())

    # ========== PARTE A — SUMÁRIO EXECUTIVO ==========
    story.extend(
        _section_banner(
            "01  ·  Sumário Executivo",
            "Linguagem de negócios · apenas achados confirmados pelo gate",
            primary,
            header_bg,
            styles_extra,
        )
    )

    if target and surface:
        from backend.ai.delta import compute_delta, format_delta_markdown
        from backend.ai.executive_summary import (
            business_delta_narrative,
            generate_executive_summary,
        )
        from backend.ai.risk_score import risk_score_for_target
        from backend.ai.verify import confidence_gate_buckets

        risk = risk_score_for_target(target)
        delta = compute_delta(target)
        gate = confidence_gate_buckets(target)
        exec_count = len(gate.get("executive") or [])

        kpi = Table(
            [
                [
                    Paragraph(
                        f"<b>{_pdf_text(risk.get('score', 0))}</b><br/>"
                        f"<font size='8' color='#6B7280'>Score de risco</font>",
                        body,
                    ),
                    Paragraph(
                        f"<b>{_pdf_text(risk.get('label', '—'))}</b><br/>"
                        f"<font size='8' color='#6B7280'>Postura</font>",
                        body,
                    ),
                    Paragraph(
                        f"<b>{exec_count}</b><br/>"
                        f"<font size='8' color='#6B7280'>Achados executivos</font>",
                        body,
                    ),
                    Paragraph(
                        f"<b>{len(delta.get('new') or []) if delta.get('has_baseline') else '—'}</b><br/>"
                        f"<font size='8' color='#6B7280'>Novos vs baseline</font>",
                        body,
                    ),
                ]
            ],
            colWidths=[4 * cm, 4 * cm, 4 * cm, 4 * cm],
        )
        kpi.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), header_bg),
                    ("BOX", (0, 0), (-1, -1), 0.8, primary),
                    ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.Color(0.8, 0.85, 0.9)),
                    ("TOPPADDING", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        story.append(kpi)
        story.append(Spacer(1, 0.35 * cm))
        narrative = business_delta_narrative(delta)
        story.append(Paragraph(f"<b>Evolução:</b> {_pdf_text(narrative)}", body))
        story.append(Spacer(1, 0.25 * cm))

        summary = generate_executive_summary(
            target, regenerate=regenerate_executive, use_llm=True
        )
        story.append(Paragraph("Análise executiva", h3))
        story.extend(_md_to_flowables(summary["text"], md_styles))
        story.append(
            Paragraph(
                f"<font size='8' color='#6B7280'>Fonte do sumário: "
                f"{_pdf_text(summary.get('source'))}</font>",
                body,
            )
        )

        try:
            from backend.ai.chains import infer_attack_chains

            chains = infer_attack_chains(surface)
            if chains:
                story.append(Paragraph("Cadeias de ataque prováveis", h3))
                for ch in chains[:6]:
                    story.append(
                        Paragraph(
                            f"• <b>{_pdf_text(ch.get('title'))}</b> — "
                            f"{_pdf_text(ch.get('detail') or ch.get('rationale') or '')[:240]}",
                            body,
                        )
                    )
        except Exception:  # noqa: BLE001
            pass

        try:
            from backend.config import COMPLIANCE_ENABLED
            from backend.compliance.reporter import generate_compliance_report

            if COMPLIANCE_ENABLED:
                crep = generate_compliance_report(
                    target, ["LGPD", "PCI-DSS"], findings=findings
                )
                story.append(Paragraph("Postura regulatória indicativa", h3))
                story.append(
                    Paragraph(
                        f"<i><font size='8'>{_pdf_text(crep.get('disclaimer_pt'))}</font></i>",
                        body,
                    )
                )
                for fw_id, fw in (crep.get("frameworks") or {}).items():
                    cov = fw.get(
                        "indicative_coverage_0_100",
                        fw.get("coverage_pct", fw.get("coverage", "—")),
                    )
                    story.append(
                        Paragraph(
                            f"• <b>{_pdf_text(fw_id)}</b>: cobertura indicativa "
                            f"{_pdf_text(cov)}%",
                            body,
                        )
                    )
        except Exception:  # noqa: BLE001
            pass

        if delta.get("has_baseline"):
            story.append(Paragraph("Evolução desde o último scan", h3))
            story.extend(
                _md_to_flowables(format_delta_markdown(delta)[:2500], md_styles)
            )
    else:
        confirmed = [f for f in findings if f.get("status") == "confirmed"]
        story.append(
            Paragraph(
                f"<b>Resumo:</b> {len(confirmed)} positivo(s) nesta sessão. "
                "Sumário executivo completo disponível em engajamentos com Attack Surface.",
                body,
            )
        )

    # ========== PARTE B — SUMÁRIO TÉCNICO ==========
    story.append(PageBreak())
    story.extend(
        _section_banner(
            "02  ·  Sumário Técnico",
            "CVEs · portas · evidências · remediação para equipes de TI",
            primary,
            header_bg,
            styles_extra,
        )
    )

    confirmed = [f for f in findings if f.get("status") == "confirmed"]
    fp = [f for f in findings if f.get("status") == "false_positive"]
    discarded = [f for f in findings if f.get("status") == "discarded"]
    pending = [
        f
        for f in findings
        if f.get("status") in {"candidate", "inconclusive", None, ""}
    ]

    story.append(
        _meta_table(
            [
                ["Positivos", str(len(confirmed))],
                ["Falsos positivos", str(len(fp))],
                ["Descartados", str(len(discarded))],
                ["Pendentes", str(len(pending))],
            ],
            primary,
            header_bg,
        )
    )
    story.append(Spacer(1, 0.35 * cm))

    if surface:
        ports = surface.get("ports") or []
        hosts = surface.get("hosts") or []
        story.append(
            Paragraph(
                f"<b>Superfície mapeada:</b> {len(hosts)} host(s) · {len(ports)} porta(s) "
                f"· {len(surface.get('services') or [])} serviço(s)",
                body,
            )
        )
        if ports:
            story.append(Paragraph("Portas abertas (amostra)", h3))
            rows = [["Host", "Porta", "Proto", "Serviço"]]
            for p in ports[:40]:
                if isinstance(p, dict):
                    rows.append(
                        [
                            _pdf_text(p.get("host"))[:40],
                            _pdf_text(p.get("port")),
                            _pdf_text(p.get("proto") or "tcp"),
                            _pdf_text(p.get("service") or "—")[:30],
                        ]
                    )
            table = Table(rows, colWidths=[5 * cm, 2 * cm, 2 * cm, 7 * cm])
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), primary),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 0.25, colors.Color(0.8, 0.82, 0.85)),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.white, header_bg],
                        ),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )
            story.append(table)

    story.append(Spacer(1, 0.35 * cm))
    sev_titles = {
        "alto": "Achados — Severidade ALTA / CRÍTICA",
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
        rows = [["Título", "Classificação", "CVE / Tool", "Alvo"]]
        for f in items:
            status = _STATUS_LABELS.get(str(f.get("status") or ""), "Pendente")
            host = str(f.get("surface_target") or f.get("host") or "—")[:40]
            cve_tool = str(f.get("cve") or f.get("tool") or "—")[:40]
            rows.append(
                [
                    _pdf_text(f.get("title") or "—")[:120],
                    status,
                    _pdf_text(cve_tool),
                    _pdf_text(host)[:40],
                ]
            )
        table = Table(rows, colWidths=[7 * cm, 3 * cm, 2.8 * cm, 3.2 * cm])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), primary),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.Color(0.8, 0.82, 0.85)),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, header_bg],
                    ),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
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
            cve = str(f.get("cve") or "—")
            block = [
                Paragraph(
                    f"<b>{i}. {_pdf_text(f.get('title') or 'Achado')}</b> "
                    f"({_pdf_text(status)} · {_pdf_text(f.get('severity') or '—')} · "
                    f"CVE {_pdf_text(cve)})",
                    h3,
                ),
                Paragraph(
                    f"<b>Alvo:</b> {_pdf_text(host)}<br/>"
                    f"<b>Comando:</b> "
                    f"<font face='Courier' size='8'>{_pdf_text(cmd)[:500]}</font>",
                    body,
                ),
                Paragraph(
                    f"<b>Evidência:</b><br/>{_pdf_text(evidence)[:1200]}",
                    body,
                ),
                Paragraph(
                    f"<b>Remediação — {_pdf_text(rem.get('title'))}:</b><br/>"
                    f"{_pdf_text(rem.get('action'))}",
                    body,
                ),
                Spacer(1, 0.2 * cm),
            ]
            story.append(KeepTogether(block))

    _append_iso_soc2(story, findings, target or display_name or "session", h2, h3, body, primary, header_bg)
    _append_triage_annex(story, fp, pending, h2, body)

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
                    Paragraph(f"<font face='Courier' size='7'>{out}</font>", body)
                )

    story.append(Spacer(1, 0.6 * cm))
    story.append(
        HRFlowable(width="100%", thickness=0.6, color=primary, spaceBefore=4, spaceAfter=8)
    )
    digest_src = f"{doc_title}|{target}|{now}|{len(findings)}|{brand['name']}"
    integrity_holder["hash"] = hashlib.sha256(digest_src.encode("utf-8")).hexdigest()
    story.append(
        Paragraph(
            f"<b>Integridade do documento</b><br/>"
            f"SHA-256: <font face='Courier' size='8'>{_pdf_text(integrity_holder['hash'])}</font><br/>"
            f"<font size='8' color='#6B7280'>{_pdf_text(brand['footer'])} "
            f"Gerado automaticamente — revise achados pendentes antes da entrega.</font>",
            body,
        )
    )

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    raw = buf.getvalue()

    try:
        from backend.security.audit import record_event

        record_event(
            "report_pdf_generated",
            {
                "target": target or "",
                "session_id": session_id or "",
                "findings": len(findings),
                "brand": brand["name"],
                "sha256_prefix": integrity_holder["hash"][:16],
                "bytes": len(raw),
            },
        )
    except Exception:  # noqa: BLE001
        pass

    return raw
