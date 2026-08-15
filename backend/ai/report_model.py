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
        target = (url.group(1) if url else host.group(1) if host else "").lower()

    confirmed = [f for f in findings if f.get("status") == "confirmed"]
    fps = [f for f in findings if f.get("status") == "false_positive"]
    pending = [
        f
        for f in findings
        if str(f.get("status") or "candidate") in {"candidate", "inconclusive", ""}
    ]

    rem_src = [
        f
        for f in findings
        if f.get("status") not in {"discarded", "false_positive"}
        and f.get("kind") not in {"scan_summary"}
    ]
    remediations: list[dict[str, Any]] = []
    try:
        from backend.ai.remediation import remediations_for_findings

        remediations = remediations_for_findings(rem_src)
    except Exception:  # noqa: BLE001
        remediations = []

    risk = {"score": 0, "label": "—"}
    try:
        from backend.ai.fp_explain import residual_risk_score

        risk = residual_risk_score(findings)
    except Exception:  # noqa: BLE001
        pass

    ok_exec = sum(1 for e in executions if e.get("success"))
    fail_exec = len(executions) - ok_exec
    discarded = [f for f in findings if f.get("status") == "discarded"]

    from backend.ai.fp_explain import severity_counts

    sev_all = severity_counts(findings)
    sev_conf = severity_counts(confirmed)
    kinds = Counter()
    for f in findings:
        if f.get("status") in {"false_positive", "discarded"}:
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
            str(target or "session"), ["ISO27001", "SOC2"], findings=findings
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
        n_findings=len(findings),
        n_confirmed=len(confirmed),
        n_fp=len(fps),
        n_pending=len(pending),
        risk=risk,
        top_fixes=top_fixes,
        sev_conf=sev_conf,
    )
    scope_bits = [str(m).strip() for m in user_msgs if str(m).strip()]
    scope = (
        " ".join(scope_bits)[:1200]
        if scope_bits
        else ("Não declarado no chat — derivado das execuções desta conversa.")
    )
    notes = [m.strip() for m in assistant_msgs if m and len(str(m).strip()) > 40]

    return {
        "title": title,
        "version": APP_VERSION,
        "now": datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC"),
        "target": target,
        "targets": targets or ([target] if target else []),
        "scope": scope,
        "executive": exec_summary,
        "executions": executions,
        "findings": findings,
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
    risk: dict[str, Any],
    top_fixes: list[str],
    sev_conf: dict[str, int],
) -> str:
    alvos = ", ".join(targets[:6]) or "alvo(s) desta conversa"
    grave = int(sev_conf.get("critical") or 0) + int(sev_conf.get("high") or 0)
    parts = [
        f"Este documento registra um teste autorizado contra {alvos}.",
        f"Foram executados {n_tests} comando(s) ({n_ok} com sucesso, {n_fail} com falha ou bloqueio).",
        f"A triagem humana classificou {n_confirmed} item(ns) como problema real, "
        f"{n_fp} como alarme falso e {n_pending} ainda pendente(s), num total de {n_findings} achado(s).",
        f"O risco residual (só o que foi confirmado) está em "
        f"{risk.get('label') or '—'} ({int(risk.get('score') or 0)}/100).",
    ]
    if grave:
        parts.append(
            f"Há {grave} confirmado(s) em gravidade crítica ou grave — trate como prioridade de correção."
        )
    if top_fixes:
        parts.append("Primeiras correções sugeridas: " + "; ".join(top_fixes) + ".")
    parts.append(
        "O corpo do relatório prioriza o que foi validado. Falsos positivos e incertezas "
        "permanecem rastreáveis para não sumir evidência."
    )
    return " ".join(parts)
