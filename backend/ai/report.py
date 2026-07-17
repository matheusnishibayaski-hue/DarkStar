"""Geração de relatórios Markdown/HTML comerciais assertivos."""

from __future__ import annotations

import html
import re
from datetime import datetime, timezone

from backend.deps import APP_VERSION
from backend.executor.files_store import list_output_files
from backend.executor.recon_db import list_recon_summaries


def _extract_vulnerabilities(tool_executions: list[dict]) -> list[dict]:
    vulns: list[dict] = []
    seen: set[str] = set()
    for ex in tool_executions:
        output = "\n".join(filter(None, [ex.get("stdout", ""), ex.get("stderr", "")]))
        command = ex.get("command", "")
        for match in re.finditer(
            r"\[(critical|high|medium|low|info)\][^\n]*", output, re.I
        ):
            line = match.group(0).strip()
            if line not in seen:
                seen.add(line)
                vulns.append(
                    {"severity": match.group(1).upper(), "detail": line, "source": command}
                )
        for match in re.finditer(r"CVE-\d{4}-\d+", output, re.I):
            cve = match.group(0).upper()
            if cve not in seen:
                seen.add(cve)
                vulns.append({"severity": "HIGH", "detail": cve, "source": command})
    return vulns


def _structured_executive(
    executive: list,
    risk: dict,
    client: str,
    target: str,
    scope_notes: str,
) -> list[str]:
    """Resumo executivo 100% derivado dos confirmados do gate (não do chat)."""
    lines = [
        f"**Postura de risco:** {risk.get('label', '—')} "
        f"(score {risk.get('score', 0)}/100)  ",
        f"**Alvo:** {target}  ",
    ]
    if client:
        lines.append(f"**Cliente:** {client}  ")
    if scope_notes:
        lines.append(f"**Escopo declarado:** {scope_notes[:300]}  ")
    lines.extend(
        [
            "",
            f"Foram **{len(executive)}** achado(s) confirmados por PoC elegíveis "
            "ao sumário executivo (gate rígido: confiança alta ou média com "
            "template/CVE + multi-fonte).",
            "",
        ]
    )
    if not executive:
        lines.append(
            "Nenhum achado atingiu o limiar executivo. Isso **não** significa "
            "ausência total de risco — ver limitações e fila humana."
        )
        lines.append("")
        return lines

    lines.append("### Principais riscos")
    lines.append("")
    for i, f in enumerate(executive[:5], 1):
        cvss = f.get("cvss_score", "—")
        impact = str(f.get("impact") or "")[:160]
        lines.append(
            f"{i}. **[{str(f.get('severity', '?')).upper()}]** {f.get('title')} "
            f"— CVSS {cvss}; {impact}"
        )
    lines.append("")
    lines.append("### Próximos passos recomendados")
    lines.append("")
    lines.append("1. Corrigir primeiro os itens **critical/high** com evidência anexada.")
    lines.append("2. Validar remediações com reteste (mesmo template-id/CVE).")
    lines.append("3. Revisar a **fila humana** (WAF/inconclusivos) antes da entrega final.")
    lines.append("")
    return lines


_METHODOLOGY = """\
Este engajamento seguiu metodologia assistida alinhada a práticas **PTES** e \
**OWASP WSTG** (reconhecimento → enumeração → varredura → verificação PoC → relatório):

1. **Reconhecimento** — descoberta de hosts/subdomínios/presença HTTP
2. **Enumeração** — portas, serviços, URLs e tecnologias
3. **Varredura** — candidatos via scanners (ex.: Nuclei, Nikto, sslscan)
4. **Verificação** — PoC não destrutivo (até 3 passes; WAF → fila humana)
5. **Relatório** — somente confirmados no executivo; FP/descartados no anexo

Ferramentas executadas em container Kali isolado, com whitelist e perfil de risco.
"""

_LIMITATIONS = """\
- Testes **não autenticados** por padrão (sem credenciais de usuário/admin no escopo).
- Lógica de negócio, IDOR contextual e cadeias avançadas exigem revisão humana.
- WAF/CDN/rate-limit podem gerar **falsos negativos** ou inconclusivos.
- CVSS sem NVD online é **estimado** (ou herdado do Nuclei quando disponível).
- Cobertura depende do escopo, tempo, templates e perfil de risco (`passive`/`safe-active`/`full`).
- Achados fora do lote de verificação podem ter sido descartados por prioridade — re-rode verify se necessário.
"""

_DISCLAIMER = """\
Documento confidencial destinado ao cliente autorizado. Uso exclusivo para melhoria \
da postura de segurança. Exploração destrutiva e testes fora do escopo não foram \
autorizados neste engajamento. A ausência de achados no executivo não garante \
inexistência de vulnerabilidades.
"""


def generate_report(
    history: list[dict],
    tool_executions: list[dict],
    title: str = "Relatório de Pentest",
    surface_target: str | None = None,
    *,
    snapshot_baseline: bool = True,
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    user_messages = [m["content"] for m in history if m.get("role") == "user"]
    scope_fallback = user_messages[0][:200] if user_messages else "Não especificado"

    brand = "Chat IA Kali"
    client = ""
    scope_notes = ""
    surface = None
    bucket = None
    gate = None
    delta_md = ""
    remediations: list = []
    risk: dict = {}
    chains: list = []
    executive: list = []

    if surface_target:
        from backend.ai.chains import infer_attack_chains
        from backend.ai.delta import compute_delta, format_delta_markdown, snapshot_confirmed
        from backend.ai.findings import findings_for_report
        from backend.ai.remediation import remediations_for_findings
        from backend.ai.risk_score import risk_score_for_target
        from backend.ai.verify import confidence_gate_buckets
        from backend.config import REPORT_BRAND_NAME
        from backend.executor.surface import load_surface

        surface = load_surface(surface_target)
        if surface:
            brand = surface.get("brand_name") or REPORT_BRAND_NAME
            client = str(surface.get("client") or "")
            scope_notes = str(surface.get("scope_notes") or "")
            bucket = findings_for_report(surface_target)
            gate = confidence_gate_buckets(surface_target)
            executive = list(gate.get("executive") or [])
            # Remediação / enriquecimento só do executivo
            from backend.ai.cvss import enrich_finding

            for f in executive:
                enrich_finding(f)
            remediations = remediations_for_findings(executive)
            delta_md = format_delta_markdown(compute_delta(surface_target))
            risk = risk_score_for_target(surface_target)
            chains = infer_attack_chains(surface)
            if snapshot_baseline:
                snapshot_confirmed(surface_target)

    lines = [
        f"# {title}",
        "",
        f"**Data:** {now}  ",
        f"**Ferramenta:** {brand} v{APP_VERSION}  ",
    ]
    if client:
        lines.append(f"**Cliente:** {client}  ")
    if risk:
        lines.append(
            f"**Risk score:** {risk.get('score', 0)}/100 — **{risk.get('label', '—')}**  "
        )
    lines.extend(
        [
            f"**Execuções registradas:** {len(tool_executions)}",
            "",
            "---",
            "",
            "## 1. Escopo e limitações",
            "",
            f"**Escopo:** {scope_notes or scope_fallback}",
            "",
            "### Limitações da automação",
            "",
            _LIMITATIONS,
            "",
            "---",
            "",
            "## 2. Metodologia",
            "",
            _METHODOLOGY,
            "",
            "---",
            "",
            "## 3. Resumo Executivo",
            "",
        ]
    )

    if bucket is not None:
        lines.extend(
            _structured_executive(
                executive,
                risk,
                client,
                surface_target or "",
                scope_notes,
            )
        )
        lines.extend(
            [
                f"**Confirmados (gate executivo):** {len(executive)}  ",
                f"**Falsos positivos (anexo):** {len(bucket['false_positive'])}  ",
                f"**Descartados (anexo):** {len(bucket['discarded'])}  ",
                f"**Fila humana:** {len((gate or {}).get('human_queue') or [])}  ",
                "",
            ]
        )
    else:
        assistant_messages = [m["content"] for m in history if m.get("role") == "assistant"]
        lines.append(
            assistant_messages[-1][:800]
            if assistant_messages
            else "Sessão sem conclusões registradas."
        )
        lines.append("")

    lines.extend(
        [
            "---",
            "",
            "## 4. Resumo Técnico (comandos)",
            "",
            "| # | Comando | Status | Motivo |",
            "|---|---------|--------|--------|",
        ]
    )
    for i, ex in enumerate(tool_executions, 1):
        status = (
            "OK"
            if ex.get("success")
            else ("BLOQUEADO" if ex.get("blocked") else f"EXIT {ex.get('exit_code')}")
        )
        cmd = ex.get("command", "").replace("|", "\\|")
        reason = ex.get("reason", "").replace("|", "\\|")[:80]
        lines.append(f"| {i} | `{cmd}` | {status} | {reason} |")

    lines.extend(["", "---", "", "## 5. Achados Confirmados (executivo)", ""])

    if bucket is not None and surface is not None:
        from backend.executor.surface import surface_summary

        summary = surface_summary(surface)
        lines.extend(
            [
                f"**Fase:** {summary.get('phase')} · **Perfil:** {summary.get('risk_profile')}  ",
                f"**Hosts:** {summary.get('hosts_count')} · **Portas:** {summary.get('ports_count')} · "
                f"**URLs:** {summary.get('urls_count')}",
                "",
            ]
        )
        if executive:
            lines.extend(
                [
                    "| Sev | Título | CVSS | Conf | Esforço | PoC | Evidência |",
                    "|-----|--------|------|------|---------|-----|-----------|",
                ]
            )
            for f in executive[:40]:
                ev = str(f.get("evidence") or "").replace("|", "\\|").replace("\n", " ")[:60]
                epath = str(f.get("evidence_path") or "")[:40]
                lines.append(
                    f"| {str(f.get('severity', '')).upper()} | "
                    f"{str(f.get('title', '')).replace('|', '\\|')[:80]} | "
                    f"{f.get('cvss_score', '—')} | "
                    f"{f.get('confidence', '—')} | "
                    f"{f.get('effort', '—')} | "
                    f"`{str(f.get('verify_command', '')).replace('|', '\\|')[:40]}` | "
                    f"{epath or ev} |"
                )
            lines.append("")
            lines.append("### Detalhamento (impacto)")
            lines.append("")
            for f in executive[:20]:
                lines.append(
                    f"#### [{str(f.get('severity', '?')).upper()}] {f.get('title')}"
                )
                lines.append("")
                lines.append(f"- **CVSS:** {f.get('cvss_score')} (`{f.get('cvss_vector', '')}`)")
                lines.append(f"- **Impacto:** {f.get('impact', '—')}")
                lines.append(f"- **Esforço:** {f.get('effort', '—')}")
                if f.get("matched_at") or f.get("url"):
                    lines.append(f"- **Matched-at:** {f.get('matched_at') or f.get('url')}")
                if f.get("template_id"):
                    lines.append(f"- **Template:** `{f.get('template_id')}`")
                if f.get("evidence_path"):
                    lines.append(f"- **Pacote de evidência:** `{f.get('evidence_path')}`")
                lines.append(f"- **Reteste:** validar com o mesmo template/CVE após correção.")
                lines.append("")
        else:
            lines.append("*Nenhum achado no gate executivo.*")
            lines.append("")

        human = (gate or {}).get("human_queue") or []
        if human:
            lines.extend(
                [
                    "### Fila humana (revisar antes da entrega)",
                    "",
                    "| Sev | Título | Status | Motivo |",
                    "|-----|--------|--------|--------|",
                ]
            )
            for f in human[:25]:
                reason = str(
                    f.get("discard_reason") or f.get("evidence") or f.get("status") or ""
                ).replace("|", "\\|").replace("\n", " ")[:80]
                lines.append(
                    f"| {str(f.get('severity', '')).upper()} | "
                    f"{str(f.get('title', '')).replace('|', '\\|')[:100]} | "
                    f"{f.get('status')} | {reason} |"
                )
            lines.append("")

        if chains:
            lines.extend(["### Hipóteses de cadeia (A+B)", ""])
            for c in chains:
                lines.append(
                    f"- **[{c.get('severity', '?').upper()}]** {c.get('title')}: {c.get('detail')}"
                )
            lines.append("")
    else:
        vulns = _extract_vulnerabilities(tool_executions)
        if vulns:
            lines.extend(
                ["| Severidade | Detalhe | Origem |", "|------------|---------|--------|"]
            )
            for v in vulns[:50]:
                lines.append(
                    f"| {v['severity']} | {v['detail'].replace('|', '\\|')[:120]} | "
                    f"`{v['source'].replace('|', '\\|')[:60]}` |"
                )
        else:
            lines.append("*Nenhuma vulnerabilidade extraída dos logs.*")
        lines.append("")

    if bucket is not None:
        lines.extend(["---", "", "## 6. Delta de reteste", "", delta_md, ""])

    lines.extend(["---", "", "## 7. Remediações (executivo)", ""])
    if remediations:
        for i, r in enumerate(remediations[:30], 1):
            lines.append(
                f"{i}. **[{str(r.get('severity', '?')).upper()}] {r.get('finding_title')}** — "
                f"{r.get('remediation_title')}: {r.get('action')}"
            )
        lines.append("")
    else:
        lines.append("*Sem remediações — nenhum achado no gate executivo.*")
        lines.append("")

    if bucket is not None:
        lines.extend(
            [
                "---",
                "",
                "## 8. Anexo técnico — FP e descartados",
                "",
            ]
        )
        for label, key in (
            ("Falsos positivos", "false_positive"),
            ("Descartados", "discarded"),
        ):
            items = bucket[key]
            lines.append(f"### {label}")
            lines.append("")
            if items:
                lines.extend(
                    ["| Sev | Título | Motivo |", "|-----|--------|--------|"]
                )
                for f in items[:30]:
                    reason = str(
                        f.get("discard_reason") or f.get("evidence") or ""
                    ).replace("|", "\\|").replace("\n", " ")[:80]
                    lines.append(
                        f"| {str(f.get('severity', '')).upper()} | "
                        f"{str(f.get('title', '')).replace('|', '\\|')[:100]} | {reason} |"
                    )
            else:
                lines.append("*Nenhum.*")
            lines.append("")

    if bucket is not None:
        n_recon, n_art, n_logs, n_disc = 9, 10, 11, 12
    else:
        n_recon, n_art, n_logs, n_disc = 6, 7, 8, 9

    lines.extend(["---", "", f"## {n_recon}. Recon cacheado", ""])
    recon_summaries = list_recon_summaries()
    if recon_summaries:
        lines.extend(
            [
                "| Alvo | Portas | CVEs | Achados | Atualizado |",
                "|------|--------|------|---------|------------|",
            ]
        )
        for r in recon_summaries[:20]:
            lines.append(
                f"| {r.get('target', '')} | {r.get('open_ports_count', 0)} | "
                f"{r.get('cves_count', 0)} | {r.get('vulnerabilities_count', 0)} | "
                f"{r.get('updated_at', '')[:16]} |"
            )
    else:
        lines.append("*Nenhum dado de recon persistido.*")

    lines.extend(["", "---", "", f"## {n_art}. Artefatos", ""])
    artifacts = list_output_files()
    if artifacts:
        lines.append("| Arquivo | Tamanho | Modificado |")
        lines.append("|---------|---------|------------|")
        for f in artifacts[:30]:
            lines.append(
                f"| `{f.get('name', '')}` | {f.get('size', 0) // 1024} KB | "
                f"{f.get('modified_at', '')[:16]} |"
            )
    else:
        lines.append("*Nenhum artefato.*")

    lines.extend(["", "---", "", f"## {n_logs}. Logs", ""])
    for ex in tool_executions:
        log_id = ex.get("log_file_id", "")
        cmd = ex.get("command", "")
        if log_id:
            lines.append(f"- `{cmd}` → log `{log_id}`")
        else:
            lines.append(f"- `{cmd}` → sem log")

    lines.extend(
        [
            "",
            "---",
            "",
            f"## {n_disc}. Declaração / confidencialidade",
            "",
            _DISCLAIMER,
            "",
            f"*{brand} v{APP_VERSION} — revise a fila humana e críticos antes da entrega.*",
            "",
        ]
    )
    return "\n".join(lines)


def generate_report_html(
    history: list[dict],
    tool_executions: list[dict],
    title: str = "Relatório de Pentest",
    surface_target: str | None = None,
    *,
    snapshot_baseline: bool = True,
) -> str:
    md = generate_report(
        history,
        tool_executions,
        title=title,
        surface_target=surface_target,
        snapshot_baseline=snapshot_baseline,
    )
    brand = "Chat IA Kali"
    client = ""
    risk_label = ""
    if surface_target:
        from backend.ai.risk_score import risk_score_for_target
        from backend.config import REPORT_BRAND_NAME
        from backend.executor.surface import load_surface

        surface = load_surface(surface_target) or {}
        brand = html.escape(str(surface.get("brand_name") or REPORT_BRAND_NAME))
        client = html.escape(str(surface.get("client") or ""))
        risk = risk_score_for_target(surface_target)
        risk_label = html.escape(
            f"Risk {risk.get('score', 0)}/100 — {risk.get('label', '')}"
        )

    body_parts: list[str] = []
    for raw in md.split("\n"):
        line = raw.rstrip()
        if line.startswith("# "):
            body_parts.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.startswith("## "):
            body_parts.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif line.startswith("### "):
            body_parts.append(f"<h3>{html.escape(line[4:])}</h3>")
        elif line.startswith("#### "):
            body_parts.append(f"<h4>{html.escape(line[5:])}</h4>")
        elif line.startswith("> "):
            body_parts.append(f"<blockquote>{html.escape(line[2:])}</blockquote>")
        elif line.startswith("|") and "---" not in line:
            cells = [c.strip() for c in line.strip("|").split("|")]
            tds = "".join(f"<td>{html.escape(c)}</td>" for c in cells)
            body_parts.append(f"<tr>{tds}</tr>")
        elif line.startswith("|") and "---" in line:
            continue
        elif line.startswith("- "):
            body_parts.append(f"<li>{_inline_md(line[2:])}</li>")
        elif re.match(r"^\d+\.\s", line):
            body_parts.append(f"<li>{_inline_md(re.sub(r'^\d+\.\s', '', line))}</li>")
        elif line.strip() == "---":
            body_parts.append("<hr/>")
        elif line.strip() == "":
            body_parts.append("")
        else:
            body_parts.append(f"<p>{_inline_md(line)}</p>")

    joined = "\n".join(body_parts)
    joined = re.sub(
        r"(?:<tr>.*?</tr>\n?)+",
        lambda m: "<table>\n" + m.group(0) + "</table>\n",
        joined,
        flags=re.S,
    )
    joined = re.sub(
        r"(?:<li>.*?</li>\n?)+",
        lambda m: "<ul>\n" + m.group(0) + "</ul>\n",
        joined,
        flags=re.S,
    )

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8"/>
<title>{html.escape(title)}</title>
<style>
  @page {{ margin: 18mm 14mm; }}
  body {{ font-family: "Segoe UI", Georgia, serif; max-width: 900px; margin: 0 auto;
         color: #1a1a1a; line-height: 1.5; padding: 1.5rem 1.25rem; }}
  .cover {{ border-bottom: 3px solid #222; padding-bottom: 1.25rem; margin-bottom: 2rem;
            page-break-after: avoid; }}
  .cover .brand {{ font-size: 0.85rem; letter-spacing: .12em; text-transform: uppercase;
                  color: #555; }}
  .cover h1.cover-title {{ font-size: 1.85rem; margin: .5rem 0 .35rem; border: none; }}
  .cover .meta {{ color: #666; font-size: .9rem; }}
  .risk-badge {{ display: inline-block; margin-top: .6rem; padding: .25rem .6rem;
                 background: #222; color: #fff; font-size: .8rem; }}
  h1 {{ font-size: 1.5rem; border-bottom: 2px solid #222; padding-bottom: .35rem; }}
  h2 {{ font-size: 1.2rem; margin-top: 1.75rem; color: #222; page-break-after: avoid; }}
  h3 {{ font-size: 1.05rem; margin-top: 1.1rem; }}
  h4 {{ font-size: .95rem; margin-top: .9rem; }}
  table {{ border-collapse: collapse; width: 100%; font-size: .82rem; margin: .75rem 0;
           page-break-inside: avoid; }}
  td {{ border: 1px solid #ccc; padding: .35rem .5rem; text-align: left; vertical-align: top; }}
  tr:first-child td {{ font-weight: 600; background: #f4f4f4; }}
  blockquote {{ border-left: 3px solid #666; margin: 1rem 0; padding: .25rem 1rem;
               color: #444; background: #fafafa; }}
  code {{ font-family: Consolas, monospace; font-size: .78rem; background: #f0f0f0;
         padding: .1rem .3rem; }}
  ul {{ margin: .4rem 0 .8rem 1.2rem; }}
  .footer {{ margin-top: 2.5rem; font-size: .75rem; color: #777; border-top: 1px solid #ddd;
             padding-top: .75rem; }}
  @media print {{
    body {{ margin: 0; max-width: none; padding: 0; }}
    .risk-badge {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
  }}
</style>
</head>
<body>
<div class="cover">
  <div class="brand">{brand}</div>
  <h1 class="cover-title">{html.escape(title)}</h1>
  <div class="meta">{client or "Relatório de segurança"} · Gerado automaticamente · Imprima para PDF</div>
  {f'<div class="risk-badge">{risk_label}</div>' if risk_label else ''}
</div>
{joined}
<div class="footer">Confidencial · {brand} · Revise fila humana antes da entrega ao cliente.</div>
</body>
</html>
"""


def _inline_md(text: str) -> str:
    s = html.escape(text)
    s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"`(.+?)`", r"<code>\1</code>", s)
    return s
