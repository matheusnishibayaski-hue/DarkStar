"""Geração de relatório de compliance indicativo."""

from __future__ import annotations

from typing import Any

from backend.compliance.mapper import map_findings_to_controls
from backend.compliance.scoring import indicative_coverage
from backend.executor.recon_db import normalize_target
from backend.executor.surface import load_surface

DISCLAIMER_PT = (
    "Mapeamento indicativo de controles ISO/IEC 27001:2022 Annex A e SOC 2 TSC — "
    "NÃO constitui auditoria, certificação nem opinião de conformidade "
    "(ISO 27001 / SOC 2 / LGPD / GDPR / PCI / HIPAA)."
)
DISCLAIMER_EN = (
    "Indicative control mapping only — NOT an audit, certification, "
    "or compliance opinion."
)


def generate_compliance_report(
    target: str,
    frameworks: list[str],
    *,
    findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    norm = normalize_target(target)
    if findings is None:
        surface = load_surface(norm)
        if not surface:
            raise ValueError(f"Nenhum Attack Surface para '{norm}'.")
        findings = list(surface.get("findings") or [])

    maps: dict[str, Any] = {}
    for fw_id in frameworks:
        cmap = map_findings_to_controls(findings, fw_id)
        score = indicative_coverage(cmap)
        maps[fw_id] = {**cmap, **score}

    payload = {
        "target": norm,
        "findings_considered": len(findings),
        "frameworks": maps,
        "disclaimer_pt": DISCLAIMER_PT,
        "disclaimer_en": DISCLAIMER_EN,
    }
    payload["report_md"] = render_markdown(payload)
    return payload


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# Compliance indicativo — `{report.get('target')}`",
        "",
        f"> **Disclaimer (PT):** {DISCLAIMER_PT}",
        f"> **Disclaimer (EN):** {DISCLAIMER_EN}",
        "",
        f"Findings considerados: **{report.get('findings_considered', 0)}**",
        "",
    ]
    for fw_id, block in (report.get("frameworks") or {}).items():
        lines.append(f"## {block.get('name', fw_id)}")
        lines.append(
            f"- Cobertura indicativa: **{block.get('indicative_coverage_0_100')}%**"
        )
        lines.append(f"- Status: `{block.get('status')}`")
        lines.append(f"- Gaps: {block.get('gaps')} / {block.get('controls_total')} controles")
        lines.append("")
        lines.append("| Controle | Crítico | Gap | Achados |")
        lines.append("|----------|---------|-----|---------|")
        for c in block.get("controls") or []:
            n = len(c.get("matched_findings") or [])
            lines.append(
                f"| {c.get('id')} {c.get('name')} | "
                f"{'sim' if c.get('critical') else 'não'} | "
                f"{'sim' if c.get('gap') else 'não'} | {n} |"
            )
        lines.append("")
        # remediação simples
        gap_controls = [c for c in (block.get("controls") or []) if c.get("gap")]
        if gap_controls:
            lines.append("### Plano de remediação (indicativo)")
            for c in sorted(gap_controls, key=lambda x: (not x.get("critical"), x.get("id"))):
                lines.append(
                    f"1. **{c.get('id')}** — revisar/corrigir achados ligados a "
                    f"`{c.get('name')}` ({len(c.get('matched_findings') or [])} match)."
                )
            lines.append("")
    return "\n".join(lines)
