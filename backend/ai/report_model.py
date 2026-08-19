"""Modelo único da prévia HTML e do PDF da conversa."""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from backend.deps import APP_VERSION

_SEV_LABEL = {
    "critical": "Crítico",
    "high": "Grave",
    "medium": "Atenção",
    "low": "Leve",
    "info": "Informação",
}

_KIND_SEV = {
    "xss": "high",
    "sqli": "high",
    "rce": "critical",
    "lfi": "high",
    "ssti": "high",
    "idor": "high",
    "cve": "high",
    "ssl": "medium",
    "hsts": "medium",
    "clickjack": "medium",
    "csp": "medium",
    "nosniff": "low",
    "port": "info",
    "scan_summary": "info",
    "exposure": "medium",
    "wordpress": "medium",
}

_SEV_ALIASES = {
    "alto": "high",
    "grave": "high",
    "crítico": "critical",
    "critico": "critical",
    "médio": "medium",
    "medio": "medium",
    "média": "medium",
    "atenção": "medium",
    "atencao": "medium",
    "baixa": "low",
    "baixo": "low",
    "leve": "low",
    "informational": "info",
    "informação": "info",
    "informacao": "info",
}


def normalize_severity(finding: dict[str, Any]) -> str:
    """Gravidade real: tag [high], tipo do achado, depois o campo do scanner."""
    from backend.ai.fp_explain import detect_finding_kind

    blob = " ".join(
        str(finding.get(k) or "") for k in ("title", "evidence", "command", "cve", "severity")
    )
    tagged = re.search(r"\[(critical|high|medium|low|info)\]", blob, re.I)
    if tagged:
        return tagged.group(1).lower()

    kind = detect_finding_kind(finding)
    inferred = _KIND_SEV.get(kind)

    raw = str(finding.get("severity") or "").strip().lower()
    raw = _SEV_ALIASES.get(raw, raw)
    if raw in {"critical", "high", "medium"}:
        return raw
    if inferred in {"critical", "high", "medium"}:
        return inferred
    if raw in {"low", "info"}:
        return raw
    return inferred or "info"


_KIND_REFS = {
    "xss": ("CWE-79", "A03:2021 Injection"),
    "sqli": ("CWE-89", "A03:2021 Injection"),
    "rce": ("CWE-94", "A03:2021 Injection"),
    "lfi": ("CWE-22", "A01:2021 Broken Access Control"),
    "ssti": ("CWE-1336", "A03:2021 Injection"),
    "idor": ("CWE-639", "A01:2021 Broken Access Control"),
    "cve": ("CWE-1395", "A06:2021 Vulnerable Components"),
    "hsts": ("CWE-319", "A02:2021 Cryptographic Failures"),
    "clickjack": ("CWE-1021", "A05:2021 Security Misconfiguration"),
    "csp": ("CWE-693", "A05:2021 Security Misconfiguration"),
    "nosniff": ("CWE-16", "A05:2021 Security Misconfiguration"),
    "ssl": ("CWE-295", "A02:2021 Cryptographic Failures"),
    "port": ("CWE-200", "A05:2021 Security Misconfiguration"),
    "scan_summary": ("", ""),
    "exposure": ("CWE-200", "A01:2021 Broken Access Control"),
    "wordpress": ("CWE-1104", "A06:2021 Vulnerable Components"),
    "generic": ("", ""),
}

_KIND_LABEL = {
    "xss": "XSS (script na página)",
    "sqli": "SQL injection",
    "rce": "Execução remota",
    "lfi": "Leitura de arquivo",
    "ssti": "Injeção em template",
    "idor": "IDOR / controle de acesso",
    "cve": "Falha conhecida (CVE)",
    "hsts": "HSTS / HTTPS",
    "clickjack": "Clickjacking",
    "csp": "Content-Security-Policy",
    "nosniff": "MIME sniffing",
    "ssl": "TLS / certificado",
    "port": "Porta / serviço",
    "scan_summary": "Log de teste",
    "exposure": "Painel exposto",
    "wordpress": "WordPress",
    "generic": "Outro",
}

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def finding_refs(finding: dict[str, Any]) -> dict[str, str]:
    """CWE / OWASP a partir do kind (ou campos já presentes)."""
    from backend.ai.fp_explain import detect_finding_kind

    kind = str(finding.get("kind") or detect_finding_kind(finding) or "generic")
    mapped_cwe, mapped_owasp = _KIND_REFS.get(kind, ("", ""))
    return {
        "cwe": str(finding.get("cwe") or mapped_cwe),
        "owasp": str(finding.get("owasp") or mapped_owasp),
    }


def enrich_finding(finding: dict[str, Any]) -> dict[str, Any]:
    from backend.ai.fp_explain import _plain_title, detect_finding_kind, explain_false_positive

    row = dict(finding)
    kind = detect_finding_kind(row)
    sev = normalize_severity(row)
    row["kind"] = kind
    row["kind_label"] = _KIND_LABEL.get(kind, kind)
    refs = finding_refs({**row, "kind": kind})
    row["cwe"] = refs["cwe"]
    row["owasp"] = refs["owasp"]
    row["severity"] = sev
    row["severity_label"] = _SEV_LABEL.get(sev, sev)
    row["plain_title"] = _plain_title(row, kind)
    try:
        expl = explain_false_positive(row)
        row["what_it_is"] = expl.get("what_it_is") or ""
        row["everyday"] = expl.get("everyday") or ""
        row["why_it_matters"] = expl.get("why_it_matters") or ""
        row["could_happen"] = list(expl.get("could_happen") or [])
        row["how_to_decide"] = list(expl.get("how_to_decide") or [])
    except Exception:  # noqa: BLE001
        pass
    return row


def _merge_extracted(
    findings: list[dict[str, Any]], executions: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    from backend.ai.report import _extract_vulnerabilities

    out = list(findings)
    seen = {re.sub(r"\s+", " ", str(f.get("title") or "").lower())[:160] for f in out}
    for i, v in enumerate(_extract_vulnerabilities(executions or [])):
        detail = str(v.get("detail") or "Achado").strip()
        key = re.sub(r"\s+", " ", detail.lower())[:160]
        if not key or key in seen:
            continue
        seen.add(key)
        cmd = str(v.get("source") or "")[:500]
        tool = cmd.split()[0].split("/")[-1] if cmd.strip() else ""
        out.append(
            {
                "id": f"extract-live-{i}",
                "title": detail[:200],
                "severity": str(v.get("severity") or "info").lower(),
                "status": "candidate",
                "evidence": detail[:2000],
                "command": cmd,
                "tool": tool,
                "source": "execution_extract",
            }
        )
    return out


def _filter_client_targets(targets: list[str]) -> list[str]:
    """Só hosts/URLs de rede — remove paths de código (process.cwd, *.ts, …)."""
    try:
        from backend.executor.recon_db import is_recon_target, normalize_target
    except Exception:  # noqa: BLE001
        return [str(t).strip() for t in targets if str(t).strip()][:20]
    out: list[str] = []
    seen: set[str] = set()
    for raw in targets:
        t = str(raw or "").strip()
        if not t or not is_recon_target(t):
            continue
        key = normalize_target(t)
        if key in seen:
            continue
        seen.add(key)
        out.append(t)
    return out[:20]


_SCOPE_NOISE = re.compile(
    r"\[PROJECT INTEL[\s\S]*?(?=\n\n|\Z)|"
    r"\[Pentest white-box[^\]]*\]|"
    r"Analise o mapa e os arquivos[\s\S]{0,800}?Regras:|"
    r"Missão:\s*pentest white-box[\s\S]{0,400}?Regras:",
    re.I,
)


def _clean_scope(user_msgs: list[str]) -> str:
    """Escopo curto em português — sem prompt interno / mapa de projeto."""
    chunks: list[str] = []
    for m in user_msgs:
        text = str(m or "").strip()
        if not text:
            continue
        text = _SCOPE_NOISE.sub(" ", text)
        text = re.sub(r"\s+", " ", text).strip()
        # Pula blocos que ainda são instrução de sistema
        low = text.lower()
        if low.startswith("analise o mapa") or "entregue somente o relatório" in low:
            continue
        if len(text) < 12:
            continue
        chunks.append(text[:400])
        if sum(len(c) for c in chunks) >= 500:
            break
    if not chunks:
        return "Teste autorizado nesta conversa — alvos derivados das execuções."
    return " ".join(chunks)[:700]


def is_reportable_finding(finding: dict[str, Any]) -> bool:
    """Itens que o cliente deve ver no corpo — só erro real (confirmado)."""
    if finding.get("kind") == "scan_summary":
        return False
    return str(finding.get("status") or "") == "confirmed"


def build_client_cards(
    confirmed: list[dict[str, Any]], remediations: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Cartões cliente: erro + o que causa + como corrigir."""
    by_id = {str(r.get("finding_id") or ""): r for r in remediations if r.get("finding_id")}
    by_title = {
        re.sub(r"\s+", " ", str(r.get("finding_title") or "").lower())[:120]: r
        for r in remediations
    }
    cards: list[dict[str, Any]] = []
    for f in confirmed:
        title = str(f.get("plain_title") or f.get("title") or "Problema de segurança")
        title_key = re.sub(r"\s+", " ", title.lower())[:120]
        rem = by_id.get(str(f.get("id") or "")) or by_title.get(title_key) or {}
        happen = [str(x).strip() for x in (f.get("could_happen") or []) if str(x).strip()]
        impact = (
            str(f.get("why_it_matters") or "").strip()
            or ("; ".join(happen[:3]) if happen else "")
            or str(f.get("everyday") or "").strip()
            or str(f.get("what_it_is") or "").strip()
            or "Pode expor dados ou permitir abuso do sistema."
        )
        steps = [str(s).strip() for s in (rem.get("steps") or []) if str(s).strip()]
        fix_title = str(rem.get("remediation_title") or "").strip()
        fix_action = str(rem.get("action") or "").strip()
        if not fix_title and not fix_action and not steps:
            fix_title = "Corrigir conforme a evidência deste achado"
            fix_action = (
                "Reproduza o problema no ambiente autorizado, corrija o controle "
                "no código/config e valide de novo o mesmo teste."
            )
        cards.append(
            {
                "title": title,
                "tech_title": str(f.get("title") or ""),
                "severity": str(f.get("severity") or "info"),
                "severity_label": str(f.get("severity_label") or f.get("severity") or "—"),
                "kind_label": str(f.get("kind_label") or f.get("kind") or ""),
                "host": str(f.get("surface_target") or f.get("host") or ""),
                "what": str(f.get("what_it_is") or f.get("everyday") or "").strip(),
                "impact": impact,
                "could_happen": happen[:4],
                "fix_title": fix_title,
                "fix_action": fix_action,
                "fix_steps": steps[:6],
                "fix_verify": str(rem.get("verify") or "").strip(),
                "fix_who": str(rem.get("who") or "").strip(),
            }
        )
    return cards


def build_client_ai_prompt(model: dict[str, Any]) -> str:
    """Prompt curto para o cliente colar em uma IA e obter plano de correção."""
    alvos = ", ".join(str(t) for t in (model.get("targets") or [])[:8]) or "alvo do teste"
    risk = model.get("risk") or {}
    score = int(risk.get("score") or 0)
    label = str(risk.get("label") or "—")
    cards = model.get("client_cards") or []
    lines = [
        "Você é um especialista em segurança de aplicações.",
        "Com base neste relatório de pentest autorizado, explique os erros "
        "em português claro e proponha um plano de correção priorizado "
        "para a equipe de desenvolvimento (passo a passo, sem jargão desnecessário).",
        "",
        f"Alvo(s): {alvos}",
        f"Nível de perigo: {score}/100 ({label}) — escala: Baixo, Médio, Médio alto, Alto.",
        "",
    ]
    if not cards:
        lines.append("Não há vulnerabilidades confirmadas neste relatório.")
        lines.append("Sugira apenas boas práticas gerais de endurecimento, se fizer sentido.")
        return "\n".join(lines)

    lines.append(f"Vulnerabilidades confirmadas ({len(cards)}):")
    for i, c in enumerate(cards[:20], 1):
        lines.append(
            f"{i}. {c.get('title')} — Gravidade: {c.get('severity_label') or '—'}"
        )
        if c.get("host"):
            lines.append(f"   Onde: {c['host']}")
        if c.get("impact"):
            lines.append(f"   O que pode causar: {c['impact']}")
        fix = c.get("fix_title") or c.get("fix_action") or ""
        if fix:
            lines.append(f"   Correção sugerida: {fix}")
        for s in (c.get("fix_steps") or [])[:4]:
            lines.append(f"   - {s}")
        lines.append("")
    lines.append(
        "Responda com: (1) resumo executivo de 5 linhas, "
        "(2) lista priorizada do que corrigir primeiro, "
        "(3) passos técnicos por item, "
        "(4) como validar que cada correção funcionou."
    )
    return "\n".join(lines)


def build_simple_summary(model: dict[str, Any]) -> dict[str, str]:
    """Três frases claras — compartilhado por prévia HTML e PDF."""
    risk = model.get("risk") or {}
    score = int(risk.get("score") or 0)
    label = str(risk.get("label") or "não calculado")
    confirmed = model.get("confirmed") or []
    remediations = model.get("remediations") or []
    cards = model.get("client_cards") or []
    if model.get("empty"):
        return {
            "risk_line": f"{score}/100 — {label}",
            "found": "Ainda não rodamos testes nesta conversa.",
            "now": "Peça à Argus um reconhecimento ou inicie o piloto automático.",
        }
    n_c = len(confirmed)
    if n_c == 0:
        found = (
            "Não encontramos vulnerabilidades confirmadas neste teste. "
            f"Nível de perigo: {score}/100 ({label})."
        )
        now = "Mantenha as boas práticas e reavalie após mudanças no sistema."
    else:
        found = (
            f"Encontramos {n_c} vulnerabilidade(s) confirmada(s). "
            f"Nível de perigo: {score}/100 ({label})."
        )
        if cards:
            now = f"Prioridade: {cards[0].get('fix_title') or cards[0].get('title')}."
            if n_c > 1:
                now += f" Há mais {n_c - 1} item(ns) na lista abaixo."
        elif remediations:
            now = f"Comece por: {remediations[0].get('remediation_title') or 'correção'}."
            if len(remediations) > 1:
                now += f" Há mais {len(remediations) - 1} correção(ões) na lista."
        else:
            now = "Corrija os itens abaixo, começando pelos de maior gravidade."
    return {
        "risk_line": f"{score}/100 — {label}",
        "found": found,
        "now": now,
    }


def assemble_session_report(
    *,
    history: list[dict[str, Any]] | None = None,
    tool_executions: list[dict[str, Any]] | None = None,
    session_id: str = "",
    title: str = "Relatório de Pentest",
) -> dict[str, Any]:
    history = list(history or [])
    executions = list(tool_executions or [])
    findings: list[dict[str, Any]] = []
    targets: list[str] = []

    if session_id and not history:
        try:
            from backend.database.chat_store import get_chat_session

            chat = get_chat_session(session_id) or {}
            history = [
                {"role": m.get("role"), "content": m.get("content") or ""}
                for m in (chat.get("messages") or [])
                if isinstance(m, dict)
            ]
        except Exception:  # noqa: BLE001
            history = []

    if session_id:
        try:
            from backend.executor.session_intel import (
                aggregate_session_findings,
                collect_session_tool_executions,
                load_session,
            )

            meta = load_session(session_id) or {}
            findings = list(aggregate_session_findings(session_id) or [])
            targets = list(meta.get("targets") or [])
            if not executions:
                executions = collect_session_tool_executions(session_id) or []
        except Exception:  # noqa: BLE001
            pass

    findings = _merge_extracted(findings, executions)
    findings = [enrich_finding(f) for f in findings]
    findings.sort(
        key=lambda f: (
            0
            if f.get("status") == "confirmed"
            else 1
            if str(f.get("status") or "") in {"candidate", "inconclusive", ""}
            else 2,
            _SEV_ORDER.get(str(f.get("severity") or "info"), 9),
        )
    )

    user_msgs = [m.get("content") or "" for m in history if m.get("role") == "user"]
    assistant_msgs = [m.get("content") or "" for m in history if m.get("role") == "assistant"]
    targets = _filter_client_targets(targets)
    target = ""
    if targets:
        target = str(targets[0])
    if not target:
        texts = "\n".join(
            [str(m.get("content") or "") for m in history]
            + [str(e.get("command") or "") for e in executions]
        )
        url = re.search(r"https?://([a-z0-9][-a-z0-9.]+[a-z0-9])", texts, re.I)
        host = re.search(
            r"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\.[a-z]{2,})\b",
            texts,
            re.I,
        )
        candidate = (url.group(1) if url else host.group(1) if host else "").lower()
        filtered = _filter_client_targets([candidate] if candidate else [])
        target = filtered[0] if filtered else ""

    confirmed = [f for f in findings if f.get("status") == "confirmed"]
    fps = [
        f
        for f in findings
        if f.get("status") == "false_positive" and f.get("kind") not in {"scan_summary"}
    ]
    pending = [
        f
        for f in findings
        if str(f.get("status") or "candidate") in {"candidate", "inconclusive", ""}
        and f.get("kind") not in {"scan_summary"}
    ]
    discarded = [f for f in findings if f.get("status") == "discarded"]
    # Corpo do relatório para cliente: só vulnerabilidades confirmadas
    report_findings = [f for f in findings if is_reportable_finding(f)]
    report_findings.sort(
        key=lambda f: _SEV_ORDER.get(str(f.get("severity") or "info"), 9)
    )

    rem_src = list(report_findings)
    remediations: list[dict[str, Any]] = []
    try:
        from backend.ai.remediation import remediations_for_findings

        remediations = remediations_for_findings(rem_src)
    except Exception:  # noqa: BLE001
        remediations = []

    client_cards = build_client_cards(report_findings, remediations)

    risk = {"score": 0, "label": "—"}
    try:
        from backend.ai.fp_explain import residual_risk_score

        risk = residual_risk_score(findings)
    except Exception:  # noqa: BLE001
        pass

    ok_exec = sum(1 for e in executions if e.get("success"))
    fail_exec = len(executions) - ok_exec

    from backend.ai.fp_explain import severity_counts

    # Gráficos de gravidade: só itens reportáveis (não recibos descartados)
    sev_all = severity_counts(report_findings)
    sev_conf = severity_counts(confirmed)
    kinds = Counter()
    for f in report_findings:
        if f.get("status") in {"false_positive"}:
            continue
        kinds[str(f.get("kind_label") or f.get("kind") or "Outro")] += 1
    tools = Counter()
    for ex in executions:
        t = str(ex.get("tool") or "").strip()
        if not t:
            cmd = str(ex.get("command") or "").strip()
            t = cmd.split()[0].split("/")[-1] if cmd else ""
        if t:
            tools[t.lower()] += 1

    compliance = None
    try:
        from backend.compliance.reporter import generate_compliance_report

        compliance = generate_compliance_report(
            str(target or "session"), ["ISO27001", "SOC2"], findings=report_findings
        )
    except Exception:  # noqa: BLE001
        compliance = None

    iso_cov = 0
    soc_cov = 0
    if compliance:
        fws = compliance.get("frameworks") or {}
        iso_cov = int((fws.get("ISO27001") or {}).get("indicative_coverage_0_100") or 0)
        soc_cov = int((fws.get("SOC2") or {}).get("indicative_coverage_0_100") or 0)

    top_fixes = [
        str(r.get("remediation_title") or "")
        for r in remediations[:5]
        if r.get("remediation_title")
    ]
    exec_summary = _executive_paragraph(
        targets=targets or ([target] if target else []),
        n_tests=len(executions),
        n_ok=ok_exec,
        n_fail=fail_exec,
        n_findings=len(report_findings),
        n_confirmed=len(confirmed),
        n_fp=len(fps),
        n_pending=len(pending),
        n_discarded=len(discarded),
        risk=risk,
        top_fixes=top_fixes,
        sev_conf=sev_conf,
    )
    scope = _clean_scope(user_msgs)
    notes = [m.strip() for m in assistant_msgs if m and len(str(m).strip()) > 40]

    model = {
        "title": title,
        "version": APP_VERSION,
        "now": datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC"),
        "target": target,
        "targets": targets or ([target] if target else []),
        "scope": scope,
        "executive": exec_summary,
        "executions": executions,
        "findings": findings,
        "report_findings": report_findings,
        "client_cards": client_cards,
        "confirmed": confirmed,
        "fps": fps,
        "pending": pending,
        "discarded": discarded,
        "remediations": remediations,
        "assistant_msgs": assistant_msgs,
        "notes": notes[-4:],
        "ok_exec": ok_exec,
        "fail_exec": fail_exec,
        "risk": risk,
        "severity": sev_all,
        "severity_confirmed": sev_conf,
        "kinds": dict(kinds.most_common(10)),
        "tools": dict(tools.most_common(12)),
        "compliance": compliance,
        "iso_cov": iso_cov,
        "soc_cov": soc_cov,
        "empty": not executions and not findings and len(user_msgs) < 1,
    }
    model["simple_summary"] = build_simple_summary(model)
    model["ai_prompt"] = build_client_ai_prompt(model)
    return model


def _executive_paragraph(
    *,
    targets: list[str],
    n_tests: int,
    n_ok: int,
    n_fail: int,
    n_findings: int,
    n_confirmed: int,
    n_fp: int,
    n_pending: int,
    n_discarded: int,
    risk: dict[str, Any],
    top_fixes: list[str],
    sev_conf: dict[str, int],
) -> str:
    alvos = ", ".join(targets[:6]) or "alvo(s) desta conversa"
    score = int(risk.get("score") or 0)
    label = risk.get("label") or "—"
    grave = int(sev_conf.get("critical") or 0) + int(sev_conf.get("high") or 0)
    parts = [
        f"Teste autorizado em {alvos}.",
        f"Rodamos {n_tests} comando(s) ({n_ok} ok, {n_fail} falha/bloqueio).",
        f"Problemas confirmados: {n_confirmed}.",
        f"Nível de perigo: {score}/100 ({label}) — Baixo · Médio · Médio alto · Alto.",
    ]
    if n_discarded:
        parts.append(
            f"{n_discarded} registro(s) de ferramenta foram omitidos (não são vulnerabilidades)."
        )
    if grave:
        parts.append(
            f"{grave} item(ns) em gravidade crítica ou grave — prioridade de correção."
        )
    if top_fixes:
        parts.append("Comece por: " + "; ".join(top_fixes) + ".")
    return " ".join(parts)
