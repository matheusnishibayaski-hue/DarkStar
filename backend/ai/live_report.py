"""Pré-visualização HTML do relatório da conversa (espelha o PDF)."""

from __future__ import annotations

import html
from typing import Any

from backend.ai.exec_digest import digest_execution
from backend.ai.report_model import assemble_session_report
from backend.deps import APP_VERSION

_STATUS = {
    "confirmed": "Vulnerabilidade confirmada",
    "false_positive": "Falso positivo",
    "discarded": "Descartado",
    "candidate": "Pendente de triagem",
    "inconclusive": "Inconclusivo",
}


def _esc(value: Any) -> str:
    return html.escape(str(value or ""), quote=True)


def _tool_name(ex: dict[str, Any]) -> str:
    tool = str(ex.get("tool") or "").strip()
    if tool:
        return tool
    cmd = str(ex.get("command") or "").strip()
    if not cmd:
        return "comando"
    return cmd.split()[0].split("/")[-1]


def _hbar(label: str, value: int, maxv: int, color: str) -> str:
    maxv = max(1, int(maxv or 1))
    value = max(0, int(value or 0))
    w = max(0, min(220, round(220 * value / maxv)))
    return (
        f"<div class='hbar'><span>{_esc(label)}</span>"
        f"<svg width='220' height='12' aria-hidden='true'>"
        f"<rect width='220' height='12' fill='#e5e7eb'/>"
        f"<rect width='{w}' height='12' fill='{_esc(color)}'/></svg>"
        f"<b>{value}</b></div>"
    )


def _charts_html(model: dict[str, Any]) -> str:
    sev = model.get("severity") or {}
    kinds = model.get("kinds") or {}
    tools = model.get("tools") or {}
    risk = model.get("risk") or {}
    score = max(0, min(100, int(risk.get("score") or 0)))
    risk_color = "#166534" if score < 20 else "#d97706" if score < 45 else "#dc2626"
    sev_rows = [
        ("Crítico", sev.get("critical") or 0, "#7f1d1d"),
        ("Grave", sev.get("high") or 0, "#dc2626"),
        ("Atenção", sev.get("medium") or 0, "#d97706"),
        ("Leve", sev.get("low") or 0, "#2563eb"),
        ("Informação", sev.get("info") or 0, "#6b7280"),
    ]
    sev_max = max((v for _, v, _ in sev_rows), default=1) or 1
    kind_max = max(list(kinds.values()) or [1])
    tool_max = max(list(tools.values()) or [1])
    iso = int(model.get("iso_cov") or 0)
    soc = int(model.get("soc_cov") or 0)
    n_conf = len(model.get("confirmed") or [])
    n_fp = len(model.get("fps") or [])
    n_pend = len(model.get("pending") or [])
    n_disc = len(model.get("discarded") or [])
    status_max = max(n_conf, n_fp, n_pend, n_disc, 1)
    sev_html = "".join(_hbar(a, b, sev_max, c) for a, b, c in sev_rows)
    kind_html = "".join(_hbar(k, int(v), kind_max, "#1e90ff") for k, v in list(kinds.items())[:8]) or "<p class='note'>Sem tipos ainda.</p>"
    tool_html = "".join(_hbar(k, int(v), tool_max, "#111827") for k, v in list(tools.items())[:8]) or "<p class='note'>Nenhuma ferramenta registrada.</p>"
    return f"""
  <div class="charts">
    <div class="chart-box">
      <h3>Risco residual</h3>
      <p class="risk-num" style="color:{risk_color}">{score}<small>/100</small></p>
      <p class="note">{_esc(risk.get("label") or "—")} — só o que você confirmou como problema real.</p>
      <svg width="100%" height="16" viewBox="0 0 220 16" aria-label="risco">
        <rect width="220" height="16" fill="#e5e7eb"/>
        <rect width="{round(2.2 * score)}" height="16" fill="{risk_color}"/>
      </svg>
    </div>
    <div class="chart-box">
      <h3>Gravidade (achados ativos)</h3>
      {sev_html}
    </div>
    <div class="chart-box">
      <h3>Triagem</h3>
      {_hbar("Confirmados", n_conf, status_max, "#166534")}
      {_hbar("Alarme falso", n_fp, status_max, "#d97706")}
      {_hbar("Pendentes", n_pend, status_max, "#2563eb")}
      {_hbar("Descartados", n_disc, status_max, "#9ca3af")}
    </div>
    <div class="chart-box">
      <h3>ISO 27001 / SOC 2 (indicativo)</h3>
      {_hbar("ISO 27001", iso, 100, "#166534")}
      {_hbar("SOC 2", soc, 100, "#1e90ff")}
      <p class="note">Percentual indicativo — não é certificação.</p>
    </div>
    <div class="chart-box">
      <h3>Tipos de achado</h3>
      {kind_html}
    </div>
    <div class="chart-box">
      <h3>Ferramentas usadas</h3>
      {tool_html}
    </div>
  </div>"""


def generate_live_report_html(
    *,
    history: list[dict[str, Any]] | None = None,
    tool_executions: list[dict[str, Any]] | None = None,
    session_id: str = "",
    title: str = "Relatório de Pentest",
) -> str:
    model = assemble_session_report(
        history=history,
        tool_executions=tool_executions,
        session_id=session_id,
        title=title,
    )
    findings = model["findings"]
    executions = model["executions"]
    confirmed = model["confirmed"]
    fps = model["fps"]
    risk = model["risk"]
    target = model["target"]
    alvos = ", ".join(_esc(t) for t in (model["targets"] or [])) or "—"
    risk_html = (
        f"<div class='kpi'><b>{_esc(risk.get('score', 0))}</b>"
        f"<span>risco · {_esc(risk.get('label'))}</span></div>"
    )
    iso_html = _render_iso_soc2(findings, target or "session", model.get("compliance"))
    tests_html = _render_tests(executions)
    findings_html = _render_findings(findings)
    rem_html = _render_remediations(model["remediations"])
    chat_html = _render_chat_notes(model.get("notes") or model["assistant_msgs"])
    charts_html = _charts_html(model)
    empty_banner = (
        "<div class='empty'>Ainda não há testes nesta conversa. "
        "Fale com a Argus ou rode o piloto — esta prévia atualiza sozinha.</div>"
        if model["empty"]
        else ""
    )

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8"/>
<title>{_esc(model["title"])}</title>
<style>
  :root {{ --ink:#111827; --muted:#6b7280; --line:#e5e7eb; --accent:#1e90ff; --paper:#fff; --ok:#166534; --bad:#991b1b; --warn:#92400e; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background:#e8eaed; color:var(--ink); font-family:"Segoe UI", Georgia, serif; }}
  .page {{ max-width:820px; margin:16px auto 32px; background:var(--paper); padding:36px 40px 48px;
           box-shadow:0 8px 28px rgba(0,0,0,.18); min-height:1000px; }}
  .brand {{ font-size:11px; letter-spacing:.16em; text-transform:uppercase; color:var(--accent); font-weight:700; }}
  h1 {{ font-size:26px; margin:8px 0 6px; line-height:1.2; }}
  .meta {{ color:var(--muted); font-size:13px; margin-bottom:14px; }}
  .kpis {{ display:grid; grid-template-columns:repeat(5,1fr); gap:8px; margin:16px 0 18px; }}
  .kpi {{ border:1px solid var(--line); padding:10px 8px; text-align:center; }}
  .kpi b {{ display:block; font-size:20px; }}
  .kpi span {{ font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:.06em; }}
  .charts {{ display:grid; grid-template-columns:1fr 1fr; gap:12px; margin:8px 0 20px; }}
  .chart-box {{ border:1px solid var(--line); padding:10px 12px 12px; background:#fafafa; }}
  .chart-box h3 {{ margin:0 0 8px; font-size:12px; letter-spacing:.06em; text-transform:uppercase; color:var(--muted); }}
  .hbar {{ display:grid; grid-template-columns:92px 1fr 28px; gap:6px; align-items:center; margin:4px 0; font-size:11px; }}
  .hbar span {{ color:var(--muted); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
  .hbar b {{ text-align:right; font-size:11px; }}
  .risk-num {{ font-size:36px; font-weight:700; margin:4px 0 6px; }}
  .risk-num small {{ font-size:14px; color:var(--muted); font-weight:500; }}
  .lead {{ font-size:14px; line-height:1.6; }}
  .barwrap {{ background:#e5e7eb; height:10px; margin:6px 0 14px; }}
  .bar {{ height:10px; background:var(--accent); }}
  .bar.iso {{ background:#166534; }}
  .note {{ font-size:11px; color:var(--muted); }}
  table.comp {{ border-collapse:collapse; width:100%; font-size:11px; margin:8px 0 16px; }}
  table.comp th, table.comp td {{ border:1px solid var(--line); padding:4px 6px; text-align:left; }}
  table.comp th {{ background:#f3f4f6; }}
  h2 {{ font-size:15px; letter-spacing:.08em; text-transform:uppercase; border-bottom:2px solid var(--accent);
        padding-bottom:6px; margin:28px 0 12px; color:var(--accent); }}
  h3 {{ font-size:14px; margin:16px 0 6px; }}
  p, li {{ font-size:13px; line-height:1.55; }}
  .test {{ border:1px solid var(--line); padding:10px 12px; margin:0 0 10px; page-break-inside:avoid; }}
  .test .cmd {{ font-family:Consolas,monospace; font-size:11px; background:#f3f4f6; padding:6px 8px; overflow-x:auto; }}
  .test ul {{ margin:6px 0 8px; padding-left:1.2rem; }}
  .fail-why {{ color:var(--bad); font-size:12px; }}
  .out {{ font-family:Consolas,monospace; font-size:10.5px; white-space:pre-wrap; background:#0f172a; color:#e2e8f0;
          padding:8px 10px; max-height:160px; overflow:auto; margin-top:8px; }}
  details.test-log {{ margin-top:8px; font-size:12px; color:var(--muted); }}
  .ok {{ color:var(--ok); font-weight:700; }}
  .fail {{ color:var(--bad); font-weight:700; }}
  .finding {{ border-left:4px solid var(--accent); padding:8px 12px; margin:0 0 12px; background:#f8fafc; }}
  .finding.alto {{ border-color:#dc2626; }}
  .finding.medio {{ border-color:#d97706; }}
  .finding.baixo {{ border-color:#2563eb; }}
  .finding.info {{ border-color:#6b7280; }}
  .tag {{ display:inline-block; font-size:10px; padding:2px 6px; border:1px solid var(--line); margin-right:6px; }}
  .empty {{ padding:40px 16px; text-align:center; color:var(--muted); }}
  .foot {{ margin-top:36px; font-size:11px; color:var(--muted); border-top:1px solid var(--line); padding-top:10px; }}
  .fix ol {{ margin:0.35rem 0 0.5rem; padding-left:1.2rem; }}
  @media (max-width:640px) {{
    .kpis {{ grid-template-columns:repeat(2,1fr); }}
    .charts {{ grid-template-columns:1fr; }}
  }}
</style>
</head>
<body>
<div class="page">
  <div class="brand">DarkStar · Argus v{_esc(APP_VERSION)}</div>
  <h1>{_esc(model["title"])}</h1>
  <div class="meta">CONFIDENCIAL · {model["now"]} · Alvo(s): {alvos}</div>
  {empty_banner}
  <div class="kpis">
    <div class="kpi"><b>{len(executions)}</b><span>testes</span></div>
    <div class="kpi"><b>{len(findings)}</b><span>achados</span></div>
    <div class="kpi"><b>{len(confirmed)}</b><span>confirmados</span></div>
    <div class="kpi"><b>{len(fps)}</b><span>falsos +</span></div>
    {risk_html}
  </div>
  {charts_html}

  <h2>1. Resumo executivo</h2>
  <p class="lead">{_esc(model.get("executive") or "")}</p>

  <h2>2. Escopo</h2>
  <p>{_esc(model["scope"])}</p>
  <p>Engajamento assistido (reconhecimento → enumeração → varredura → verificação). 
  Testes em container Kali isolado. Sem credenciais autenticadas, salvo se declaradas no chat.</p>

  <h2>3. Testes realizados</h2>
  <p>{model["ok_exec"]} execução(ões) com sucesso · {model["fail_exec"]} falha(s)/bloqueio(s).</p>
  {tests_html}

  <h2>4. O que foi encontrado</h2>
  {findings_html}

  <h2>5. Como corrigir</h2>
  {rem_html}

  <h2>6. Notas da conversa</h2>
  {chat_html}

  <h2>7. Conformidade indicativa ISO 27001 / SOC 2</h2>
  {iso_html}

  <h2>8. Metodologia e limitações</h2>
  <ul>
    <li>Reconhecimento, enumeração, varredura e verificação PoC não destrutiva.</li>
    <li>WAF/CDN podem gerar falsos negativos; ausência de achado não garante segurança.</li>
    <li>CVSS sem NVD é estimado. Gravidade no relatório usa o tipo do achado e a tag do scanner, não só o campo “info” dos logs.</li>
    <li>ISO/SOC 2 aqui é mapeamento por palavras-chave — não substitui auditoria nem certificação.</li>
    <li>Revise pendentes antes da entrega ao cliente. O PDF segue este mesmo modelo.</li>
  </ul>
  <div class="foot">Documento gerado automaticamente a partir desta conversa. Atualiza em tempo real conforme novos testes. DarkStar · Argus v{_esc(APP_VERSION)}.</div>
</div>
</body>
</html>
"""


def _render_iso_soc2(
    findings: list[dict[str, Any]], target: str, report: dict[str, Any] | None = None
) -> str:
    if report is None:
        try:
            from backend.compliance.reporter import generate_compliance_report

            report = generate_compliance_report(
                str(target or "session"), ["ISO27001", "SOC2"], findings=findings
            )
        except Exception:  # noqa: BLE001
            return "<p>Não foi possível mapear controles neste momento.</p>"
    disc = _esc(report.get("disclaimer_pt") or "")
    extra = (
        "Cobertura <b>indicativa</b> por palavras-chave — não substitui certificação "
        "ISO/IEC 27001 nem atestado SOC 2."
    )
    parts = [f"<p class='note'>{disc}</p><p class='note'>{extra}</p>"]
    for fw_id, fw in (report.get("frameworks") or {}).items():
        cov = int(fw.get("indicative_coverage_0_100") or 0)
        name = _esc(fw.get("name") or fw_id)
        bar_cls = "iso" if "ISO" in str(fw_id).upper() else ""
        parts.append(
            f"<h3>{name} — {cov}%</h3>"
            f"<p class='note'>{fw.get('gaps', 0)} gap(s) / {fw.get('controls_total', 0)} controles</p>"
            f"<div class='barwrap'><div class='bar {bar_cls}' style='width:{max(0, min(100, cov))}%'></div></div>"
        )
        rows = ["<table class='comp'><tr><th>Controle</th><th>Crítico</th><th>Gap</th><th>Achados</th></tr>"]
        for c in (fw.get("controls") or [])[:24]:
            rows.append(
                "<tr>"
                f"<td>{_esc(c.get('id'))} {_esc(c.get('name'))}</td>"
                f"<td>{'sim' if c.get('critical') else 'não'}</td>"
                f"<td>{'sim' if c.get('gap') else 'não'}</td>"
                f"<td>{len(c.get('matched_findings') or [])}</td>"
                "</tr>"
            )
        rows.append("</table>")
        parts.append("".join(rows))
    return "".join(parts)


def _render_tests(executions: list[dict[str, Any]]) -> str:
    if not executions:
        return "<p>Nenhum comando executado ainda.</p>"
    parts: list[str] = []
    for i, ex in enumerate(executions[:60], 1):
        d = digest_execution(ex)
        cls = "ok" if d["status"] == "ok" else "fail"
        bullets = "".join(f"<li>{_esc(b)}</li>" for b in d.get("bullets") or [])
        fail = d.get("failure") or ""
        reason = d.get("reason") or ""
        log = d.get("log") or ""
        log_block = (
            f"<details class='test-log'><summary>Log limpo</summary>"
            f"<div class='out'>{_esc(log)}</div></details>"
            if log
            else ""
        )
        parts.append(
            f"<div class='test'><h3>{i}. {_esc(d['tool'])} · "
            f"<span class='{cls}'>{_esc(d['status_label'])}</span></h3>"
            f"<p>{_esc(d.get('headline') or '')}</p>"
            f"{f'<p class=\"fail-why\">{_esc(fail)}</p>' if fail else ''}"
            f"{f'<p class=\"note\">{_esc(reason)}</p>' if reason and reason != fail else ''}"
            f"{f'<ul>{bullets}</ul>' if bullets else ''}"
            f"<div class='cmd'>{_esc(d.get('command') or '—')}</div>"
            f"{log_block}</div>"
        )
    return "".join(parts)


def _sev_class(sev: Any) -> str:
    s = str(sev or "").lower()
    if s in {"critical", "high", "alto"}:
        return "alto"
    if s in {"medium", "medio", "média"}:
        return "medio"
    if s in {"info", "informational"}:
        return "info"
    return "baixo"


def _render_findings(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "<p>Nenhum achado estruturado ainda. Quando nuclei/nmap/nikto (ou a triagem) gerarem itens, eles aparecem aqui.</p>"
    parts: list[str] = []
    for i, f in enumerate(findings[:120], 1):
        status = _STATUS.get(str(f.get("status") or "candidate"), str(f.get("status") or "Pendente"))
        sev_label = str(f.get("severity_label") or f.get("severity") or "info")
        host = f.get("surface_target") or f.get("host") or "—"
        evidence = str(f.get("evidence") or "")[:1600]
        cmd = str(f.get("command") or "")[:500]
        headline = f.get("plain_title") or f.get("title") or "Achado"
        tech = str(f.get("title") or "")
        tech_line = (
            f"<p class='note'>Nome técnico: {_esc(tech)}</p>"
            if tech and tech != headline
            else ""
        )
        what = str(f.get("what_it_is") or "")
        everyday = str(f.get("everyday") or "")
        why = str(f.get("why_it_matters") or "")
        happen = "".join(f"<li>{_esc(x)}</li>" for x in (f.get("could_happen") or [])[:4])
        decide = "".join(f"<li>{_esc(x)}</li>" for x in (f.get("how_to_decide") or [])[:4])
        kind = _esc(f.get("kind_label") or "")
        parts.append(
            f"<div class='finding {_sev_class(f.get('severity'))}'>"
            f"<p><b>{i}. {_esc(headline)}</b></p>"
            f"{tech_line}"
            f"<p><span class='tag'>{_esc(sev_label)}</span><span class='tag'>{_esc(status)}</span>"
            f"{f'<span class=\"tag\">{kind}</span>' if kind else ''}"
            f"<span class='tag'>{_esc(f.get('tool') or '—')}</span>"
            f"<span class='tag'>{_esc(host)}</span></p>"
            f"{f'<p>{_esc(what)}</p>' if what else ''}"
            f"{f'<p><i>{_esc(everyday)}</i></p>' if everyday else ''}"
            f"{f'<p><b>Por que importa:</b> {_esc(why)}</p>' if why else ''}"
            f"{f'<p><b>Se for verdade, pode acontecer:</b></p><ul>{happen}</ul>' if happen else ''}"
            f"{f'<p><b>Como decidir:</b></p><ul>{decide}</ul>' if decide else ''}"
            f"{f'<p><b>Comando:</b> <code>{_esc(cmd)}</code></p>' if cmd else ''}"
            f"{f'<p><b>Evidência:</b> {_esc(evidence)}</p>' if evidence else ''}"
            f"</div>"
        )
    return "".join(parts)


def _render_remediations(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "<p>Sem plano de correção ainda — aparece quando houver achados (além de logs de teste).</p>"
    parts: list[str] = []
    for i, r in enumerate(rows[:60], 1):
        steps = r.get("steps") or []
        steps_html = "".join(f"<li>{_esc(s)}</li>" for s in steps)
        who = _esc(r.get("who") or "")
        why = _esc(r.get("why") or "")
        verify = _esc(r.get("verify") or "")
        sev = _esc(r.get("severity_label") or r.get("severity") or "")
        steps_block = (
            f"<p><b>Passo a passo</b></p><ol>{steps_html}</ol>"
            if steps_html
            else f"<p>{_esc(r.get('action') or '')}</p>"
        )
        parts.append(
            f"<div class='test fix'><h3>{i}. {_esc(r.get('remediation_title') or 'Correção')}</h3>"
            f"<p><b>Achado:</b> {_esc(r.get('finding_title'))} · {_esc(sev)}</p>"
            f"{f'<p><b>Quem faz:</b> {who}</p>' if who else ''}"
            f"{f'<p>{why}</p>' if why else ''}"
            f"{steps_block}"
            f"{f'<p><b>Como saber que corrigiu:</b> {verify}</p>' if verify else ''}"
            f"</div>"
        )
    return "".join(parts)


def _render_chat_notes(assistant_msgs: list[str]) -> str:
    notes = [m.strip() for m in assistant_msgs if m and len(str(m).strip()) > 40]
    if not notes:
        return "<p>A Argus ainda não registrou análise nesta conversa.</p>"
    parts = []
    for n, text in enumerate(notes[-4:], 1):
        parts.append(f"<div class='test'><h3>Nota {n}</h3><p>{_esc(text[:2200])}</p></div>")
    return "".join(parts)
