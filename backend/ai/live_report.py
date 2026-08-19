"""Pré-visualização HTML do relatório da conversa (espelha o PDF do cliente)."""

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
    risk = model["risk"] or {}
    score = int(risk.get("score") or 0)
    label = str(risk.get("label") or "—")
    cards = model.get("client_cards") or []
    alvos = ", ".join(_esc(t) for t in (model["targets"] or [])) or "—"
    cards_html = _render_client_cards(cards)
    ai_prompt = _esc(model.get("ai_prompt") or "")
    empty_banner = (
        "<div class='empty'>Ainda não há testes nesta conversa. "
        "Fale com a Argus ou rode o piloto — esta prévia atualiza sozinha.</div>"
        if model["empty"]
        else ""
    )
    risk_color = (
        "#166534"
        if score < 30
        else "#d97706"
        if score < 50
        else "#c2410c"
        if score < 75
        else "#dc2626"
    )
    simple = model.get("simple_summary") or {}

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8"/>
<title>{_esc(model["title"])}</title>
<style>
  :root {{ --ink:#111827; --muted:#6b7280; --line:#e5e7eb; --accent:#1e90ff; --paper:#fff; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background:#e8eaed; color:var(--ink); font-family:"Segoe UI", system-ui, sans-serif; }}
  .page {{ max-width:760px; margin:16px auto 32px; background:var(--paper); padding:36px 40px 48px;
           box-shadow:0 8px 28px rgba(0,0,0,.14); }}
  .brand {{ font-size:11px; letter-spacing:.16em; text-transform:uppercase; color:var(--accent); font-weight:700; }}
  h1 {{ font-size:24px; margin:8px 0 6px; line-height:1.25; }}
  .meta {{ color:var(--muted); font-size:13px; margin-bottom:18px; }}
  .danger {{ display:grid; grid-template-columns:140px 1fr; gap:0; border:1px solid var(--line);
             margin:0 0 18px; background:#f8fafc; }}
  .danger-score {{ background:#eef6ff; padding:18px 12px; text-align:center; }}
  .danger-score b {{ display:block; font-size:28px; color:{risk_color}; }}
  .danger-score span {{ font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.06em; }}
  .danger-body {{ padding:14px 16px; }}
  .danger-body .level {{ font-size:18px; font-weight:700; margin:0 0 6px; }}
  .danger-body .scale {{ font-size:11px; color:var(--muted); margin:0 0 8px; }}
  .danger-body p {{ margin:0; font-size:14px; line-height:1.5; }}
  .now {{ font-weight:600; margin:0 0 8px; font-size:14px; }}
  .scope {{ font-size:12px; color:var(--muted); margin:0 0 20px; }}
  h2 {{ font-size:13px; letter-spacing:.08em; text-transform:uppercase; border-bottom:2px solid var(--accent);
        padding-bottom:6px; margin:28px 0 14px; color:var(--accent); }}
  .card {{ border:1px solid var(--line); border-left:4px solid var(--accent); padding:14px 16px;
           margin:0 0 14px; background:#fcfcfd; }}
  .card.alto {{ border-left-color:#dc2626; }}
  .card.medio {{ border-left-color:#d97706; }}
  .card.baixo {{ border-left-color:#2563eb; }}
  .card h3 {{ margin:0 0 6px; font-size:15px; }}
  .card .tags {{ margin:0 0 10px; }}
  .tag {{ display:inline-block; font-size:10px; padding:2px 7px; border:1px solid var(--line);
          margin:0 6px 4px 0; background:#fff; }}
  .card p {{ font-size:13px; line-height:1.55; margin:0 0 8px; }}
  .card ol, .card ul {{ margin:4px 0 8px; padding-left:1.2rem; font-size:13px; }}
  .prompt {{ background:#f3f4f6; border:1px solid #d1d5db; padding:12px 14px; font-family:Consolas,monospace;
             font-size:11px; white-space:pre-wrap; line-height:1.45; color:#1f2937; }}
  .note {{ font-size:12px; color:var(--muted); }}
  .empty {{ padding:40px 16px; text-align:center; color:var(--muted); }}
  .foot {{ margin-top:32px; font-size:11px; color:var(--muted); border-top:1px solid var(--line); padding-top:10px; }}
  .simple-box {{ border:1px solid var(--line); padding:14px 16px; margin:12px 0 18px; background:#f8fafc; }}
  .simple-box h2 {{ margin:0 0 8px; font-size:13px; letter-spacing:.06em; text-transform:uppercase;
                    border:none; padding:0; color:var(--muted); }}
  .simple-box .lead {{ margin:0 0 10px; }}
  .simple-box .now {{ margin:0; font-weight:600; }}
  .charts {{ display:grid; grid-template-columns:1fr 1fr; gap:12px; margin:8px 0 20px; }}
  .chart-box {{ border:1px solid var(--line); padding:10px 12px 12px; background:#fafafa; }}
  .chart-box h3 {{ margin:0 0 8px; font-size:12px; letter-spacing:.06em; text-transform:uppercase; color:var(--muted); }}
  .hbar {{ display:grid; grid-template-columns:92px 1fr 28px; gap:6px; align-items:center; margin:4px 0; font-size:11px; }}
  .hbar span {{ color:var(--muted); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
  .hbar b {{ text-align:right; font-size:11px; }}
  .risk-num {{ font-size:36px; font-weight:700; margin:4px 0 6px; }}
  .risk-num small {{ font-size:14px; color:var(--muted); font-weight:500; }}
  @media (max-width:640px) {{ .danger {{ grid-template-columns:1fr; }} .charts {{ grid-template-columns:1fr; }} }}
</style>
</head>
<body>
<div class="page">
  <div class="brand">DarkStar · Argus v{_esc(APP_VERSION)}</div>
  <h1>{_esc(model["title"])}</h1>
  <div class="meta">CONFIDENCIAL · {model["now"]} · Alvo(s): {alvos}</div>
  {empty_banner}
  <div class="danger">
    <div class="danger-score"><b>{score}/100</b><span>nível de perigo</span></div>
    <div class="danger-body">
      <p class="level">{_esc(label)}</p>
      <p class="scale">Baixo · Médio · Médio alto · Alto</p>
      <p>{_esc(simple.get("found") or "")}</p>
    </div>
  </div>
  <p class="now">{_esc(simple.get("now") or "")}</p>
  <p class="scope"><b>Escopo:</b> {_esc(model.get("scope") or "")}</p>

  <h2>Problemas encontrados</h2>
  {cards_html}

  <h2>Prompt para IA (copie e cole)</h2>
  <p class="note">Cole em ChatGPT, Claude ou outra IA para um plano de correção priorizado.</p>
  <pre class="prompt">{ai_prompt}</pre>

  <div class="foot">Prévia = mesmo conteúdo do PDF baixado. Só vulnerabilidades confirmadas. DarkStar · Argus v{_esc(APP_VERSION)}.</div>
</div>
</body>
</html>
"""


def _render_client_cards(cards: list[dict[str, Any]]) -> str:
    if not cards:
        return (
            "<p>Nenhuma vulnerabilidade confirmada neste teste. "
            "Logs de ferramenta e alarmes falsos foram omitidos.</p>"
        )
    parts: list[str] = []
    for i, c in enumerate(cards, 1):
        sev = str(c.get("severity") or "").lower()
        cls = "alto" if sev in {"critical", "high"} else "medio" if sev in {"medium"} else "baixo"
        tags = f"<span class='tag'>{_esc(c.get('severity_label') or '—')}</span>"
        if c.get("kind_label"):
            tags += f"<span class='tag'>{_esc(c['kind_label'])}</span>"
        if c.get("host"):
            tags += f"<span class='tag'>{_esc(c['host'])}</span>"
        what = f"<p><b>O que é:</b> {_esc(c['what'])}</p>" if c.get("what") else ""
        happen = "".join(f"<li>{_esc(x)}</li>" for x in (c.get("could_happen") or [])[:4])
        happen_html = f"<ul>{happen}</ul>" if happen else ""
        steps = "".join(f"<li>{_esc(s)}</li>" for s in (c.get("fix_steps") or [])[:6])
        steps_html = f"<ol>{steps}</ol>" if steps else ""
        action = f"<p>{_esc(c['fix_action'])}</p>" if c.get("fix_action") else ""
        who = f"<p class='note'>Quem faz: {_esc(c['fix_who'])}</p>" if c.get("fix_who") else ""
        verify = (
            f"<p><b>Como saber que corrigiu:</b> {_esc(c['fix_verify'])}</p>"
            if c.get("fix_verify")
            else ""
        )
        parts.append(
            f"<div class='card {cls}'>"
            f"<h3>{i}. {_esc(c.get('title') or 'Problema')}</h3>"
            f"<div class='tags'>{tags}</div>"
            f"{what}"
            f"<p><b>O que pode causar:</b> {_esc(c.get('impact') or '—')}</p>"
            f"{happen_html}"
            f"<p><b>Como corrigir — {_esc(c.get('fix_title') or 'Correção')}</b></p>"
            f"{who}{action}{steps_html}{verify}"
            f"</div>"
        )
    return "".join(parts)


def _simple_summary_html(model: dict[str, Any]) -> str:
    from backend.ai.report_model import build_simple_summary

    s = model.get("simple_summary") or build_simple_summary(model)
    return f"""
  <div class="simple-box">
    <h2>Risco geral</h2>
    <p class="now">{_esc(s.get("risk_line") or "")}</p>
    <p class="note">0–100 com nível: Baixo · Médio · Médio alto · Alto (só confirmados).</p>
    <h2>O que encontramos</h2>
    <p class="lead">{_esc(s.get("found") or "")}</p>
    <h2>O que fazer agora</h2>
    <p class="now">{_esc(s.get("now") or "")}</p>
  </div>"""


def _charts_html(model: dict[str, Any]) -> str:
    """Mantido para testes de cobertura / legado."""
    sev = model.get("severity") or {}
    kinds = model.get("kinds") or {}
    tools = model.get("tools") or {}
    risk = model.get("risk") or {}
    score = max(0, min(100, int(risk.get("score") or 0)))
    risk_color = "#166534" if score < 30 else "#d97706" if score < 50 else "#dc2626"
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
    n_conf = len(model.get("confirmed") or [])
    n_fp = len(model.get("fps") or [])
    n_pend = len(model.get("pending") or [])
    n_disc = len(model.get("discarded") or [])
    status_max = max(n_conf, n_fp, n_pend, n_disc, 1)
    sev_html = "".join(_hbar(a, b, sev_max, c) for a, b, c in sev_rows)
    kind_html = (
        "".join(_hbar(k, int(v), kind_max, "#1e90ff") for k, v in list(kinds.items())[:8])
        or "<p class='note'>Sem tipos ainda.</p>"
    )
    tool_html = (
        "".join(_hbar(k, int(v), tool_max, "#111827") for k, v in list(tools.items())[:8])
        or "<p class='note'>Nenhuma ferramenta registrada.</p>"
    )
    return f"""
  <div class="charts">
    <div class="chart-box">
      <h3>Nível de perigo</h3>
      <p class="risk-num" style="color:{risk_color}">{score}<small>/100</small></p>
      <p class="note">{_esc(risk.get("label") or "—")} — Baixo · Médio · Médio alto · Alto.</p>
    </div>
    <div class="chart-box">
      <h3>Gravidade</h3>
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
      <h3>Tipos / ferramentas</h3>
      {kind_html}
      {tool_html}
    </div>
  </div>"""


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
    parts = [f"<p class='note'>{disc}</p>"]
    for fw_id, fw in (report.get("frameworks") or {}).items():
        cov = int(fw.get("indicative_coverage_0_100") or 0)
        name = _esc(fw.get("name") or fw_id)
        parts.append(f"<h3>{name} — {cov}%</h3>")
    return "".join(parts)


def _render_tests(executions: list[dict[str, Any]]) -> str:
    if not executions:
        return "<p>Nenhum comando executado ainda.</p>"
    parts: list[str] = []
    for i, ex in enumerate(executions[:60], 1):
        d = digest_execution(ex)
        parts.append(
            f"<div class='test'><h3>{i}. {_esc(d['tool'])}</h3>"
            f"<p>{_esc(d.get('headline') or '')}</p></div>"
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
        return "<p>Nenhum problema listado ainda.</p>"
    parts: list[str] = []
    for i, f in enumerate(findings[:120], 1):
        headline = f.get("plain_title") or f.get("title") or "Problema"
        impact = f.get("why_it_matters") or f.get("everyday") or f.get("what_it_is") or "—"
        parts.append(
            f"<div class='finding {_sev_class(f.get('severity'))}'>"
            f"<p><b>{i}. {_esc(headline)}</b></p>"
            f"<p class='impact'><b>Impacto:</b> {_esc(impact)}</p>"
            f"</div>"
        )
    return "".join(parts)


def _render_remediations(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "<p>Sem plano de correção ainda.</p>"
    parts: list[str] = []
    for i, r in enumerate(rows[:60], 1):
        parts.append(
            f"<div class='test fix'><h3>{i}. {_esc(r.get('remediation_title') or 'Correção')}</h3>"
            f"<p>{_esc(r.get('action') or '')}</p></div>"
        )
    return "".join(parts)


def _render_chat_notes(assistant_msgs: list[str]) -> str:
    notes = [m.strip() for m in assistant_msgs if m and len(str(m).strip()) > 40]
    if not notes:
        return "<p>A Argus ainda não registrou análise nesta conversa.</p>"
    return "".join(
        f"<div class='test'><h3>Nota {n}</h3><p>{_esc(text[:2200])}</p></div>"
        for n, text in enumerate(notes[-4:], 1)
    )
