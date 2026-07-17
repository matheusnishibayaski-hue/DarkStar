"""
Pipeline de verificação assertiva de findings.

Fluxo:
  candidate → (PoC) → confirmed | false_positive | inconclusive
  inconclusive → (re-PoC) → confirmed | false_positive | discarded

Política do relatório: nada fica como "talvez" ao final — só confirmed,
false_positive ou discarded (não reproduzível após 2 tentativas).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from backend.executor.result import ExecutionResult
from backend.executor.surface import load_surface, save_surface

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

# Tipos mais fáceis de verificar primeiro (após severidade)
_TYPE_PRIORITY = {
    "header": 0,
    "cve": 1,
    "ssl": 2,
    "port_info": 3,
    "web_vuln": 4,
    "xss": 5,
    "sqli": 5,
    "generic": 6,
}

_CONFIRM_HINTS = re.compile(
    r"(vulnerable|confirmed|\[critical\]|\[high\]|CVE-\d{4}-\d+|open\s+\w+|SSL\s+certificate|"
    r"missing\s+header|x-frame-options|strict-transport|content-security-policy|"
    r"reflected|inject|unauthenticated|exposed)",
    re.IGNORECASE,
)
_NEGATE_HINTS = re.compile(
    r"(not\s+vulnerable|false\s*positive|no\s+issues?|0\s+findings?|"
    r"template.*not\s+matched|nothing\s+found|clean|safe)",
    re.IGNORECASE,
)
_WAF_HINTS = re.compile(
    r"(cloudflare|akamai|sucuri|incapsula|imperva|aws.?waf|mod_security|"
    r"access\s*denied|attention\s*required|captcha|challenge|"
    r"just\s*a\s*(moment|second)|cf-ray|403\s*forbidden|"
    r"request\s*blocked|security\s*check)",
    re.IGNORECASE,
)

ExecuteFn = Callable[[str, str], ExecutionResult]


@dataclass
class VerifyOutcome:
    finding_id: str
    title: str
    status: str
    confidence: str
    reason: str
    verify_command: str = ""
    pass_number: int = 1


@dataclass
class VerifyPipelineResult:
    outcomes: list[VerifyOutcome] = field(default_factory=list)
    confirmed: int = 0
    false_positive: int = 0
    discarded: int = 0
    verify_commands_run: int = 0


def classify_finding_type(finding: dict[str, Any]) -> str:
    if finding.get("finding_type"):
        return str(finding["finding_type"])
    title = str(finding.get("title") or "").lower()
    tool = str(finding.get("tool") or "").lower()
    tid = str(finding.get("template_id") or "").lower()
    if finding.get("cve") or title.startswith("cve-") or "cve-" in title:
        return "cve"
    if any(k in title for k in ("xss", "cross-site scripting")) or "xss" in tid:
        return "xss"
    if "sql" in title or "injection" in title or "sqli" in tid:
        return "sqli"
    if any(
        k in title or k in tid
        for k in (
            "hsts",
            "x-frame",
            "csp",
            "content-security",
            "strict-transport",
            "x-content-type",
            "missing-header",
            "missing header",
            "security header",
        )
    ):
        return "header"
    if any(k in title for k in ("ssl", "tls", "certificate", "heartbleed", "weak cipher")):
        return "ssl"
    if tool in {"nmap", "naabu", "masscan"} and re.search(r"\d+/tcp", title):
        return "port_info"
    if tool in {"nuclei", "nikto", "wpscan"}:
        return "web_vuln"
    return "generic"


def _base_url(target: str, urls: list[str], finding: dict[str, Any] | None = None) -> str:
    if finding:
        for key in ("url", "matched_at"):
            u = str(finding.get(key) or "").strip()
            if u.startswith("http"):
                return u.rstrip("/")
    for u in urls:
        if target.split(".")[0] in u or target in u:
            return u.rstrip("/")
    if urls:
        return urls[0].rstrip("/")
    return f"https://{target}"


def _service_version_hint(ports: list[dict], target: str) -> str:
    """Concatena serviços conhecidos do surface para correlação CVE."""
    parts = []
    for p in ports or []:
        svc = p.get("service") or ""
        port = p.get("port") or ""
        if svc:
            parts.append(f"{port}/{svc}")
    return " ".join(parts[:20]).lower()


def build_verify_command(
    finding: dict[str, Any],
    target: str,
    *,
    urls: list[str] | None = None,
    ports: list[dict] | None = None,
    pass_number: int = 1,
) -> str | None:
    """Monta comando de PoC mínimo e não destrutivo (preferindo template-id/CVE/JSON)."""
    ftype = classify_finding_type(finding)
    title = str(finding.get("title") or "")
    urls = urls or []
    ports = ports or []
    base = _base_url(target, urls, finding)
    cve = str(finding.get("cve") or "")
    if not cve:
        cve_match = re.search(r"CVE-\d{4}-\d+", title, re.I)
        cve = cve_match.group(0).upper() if cve_match else ""
    tid = str(finding.get("template_id") or "").strip()
    curl_stored = str(finding.get("curl_command") or "").strip()

    # Pass 3 (WAF): UA alternativo + delay leve
    if pass_number >= 3:
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        if tid:
            return (
                f"nuclei -u {base} -id {tid} -silent -timeout 15 "
                f"-H 'User-Agent: {ua}' -jsonl"
            )
        return f"curl -sI -m 20 -A '{ua}' {base}"

    if ftype == "header":
        if pass_number == 1:
            return f"curl -sI -m 15 {base}"
        return f"httpx -u {base} -title -tech-detect -status-code -silent"

    if ftype == "ssl":
        host = target
        if pass_number == 1:
            return f"sslscan --no-colour {host}"
        return f"nmap -Pn -p 443 --script ssl-cert,ssl-enum-ciphers {host}"

    if ftype == "cve" and (cve or tid):
        nid = (tid or cve).lower()
        if pass_number == 1:
            return f"nuclei -u {base} -id {nid} -silent -timeout 10 -jsonl"
        port_list = ",".join(
            sorted({str(p.get("port")) for p in ports if p.get("port")} or {"80", "443"})
        )[:40]
        return f"nmap -Pn -sV --script vulners -p {port_list or '80,443'} {target}"

    if ftype in {"web_vuln", "xss", "sqli", "generic"}:
        # Prefer curl-command do Nuclei JSON na 2ª pass (reprodução exacta)
        if pass_number == 2 and curl_stored and curl_stored.startswith("curl"):
            # Sanitiza: só curl GET/HEAD não destrutivo
            if not re.search(r"\s(-d|--data|PUT|DELETE|PATCH)\b", curl_stored, re.I):
                return curl_stored[:400]
        if tid and pass_number == 1:
            return f"nuclei -u {base} -id {tid} -silent -timeout 10 -jsonl"
        if tid and pass_number == 2:
            return f"nuclei -u {base} -id {tid} -silent -timeout 15 -jsonl"
        if pass_number == 1:
            return (
                f"nuclei -u {base} -severity critical,high,medium "
                f"-silent -timeout 10 -jsonl"
            )
        return f"curl -sI -m 15 {base}"

    if ftype == "port_info":
        port_m = re.search(r"(\d+)/tcp", title)
        port = finding.get("port") or (port_m.group(1) if port_m else "80")
        return f"nmap -Pn -p {port} -sV {target}"

    return f"curl -sI -m 15 {base}"


def score_verification(
    finding: dict[str, Any],
    result: ExecutionResult,
    *,
    pass_number: int = 1,
    surface_context: dict[str, Any] | None = None,
) -> tuple[str, str, str]:
    """
    Retorna (status, confidence, reason).
    status: confirmed | false_positive | inconclusive | discarded
    """
    title = str(finding.get("title") or "")
    sev = str(finding.get("severity") or "unknown").lower()
    output = f"{result.stdout or ''}\n{result.stderr or ''}"
    output_l = output.lower()
    needle = title.lower()[:60]
    sources = int(finding.get("sources") or 1)
    tid = str(finding.get("template_id") or "").lower()

    if result.blocked:
        return "inconclusive", "low", f"Verificação bloqueada: {result.stderr[:120]}"

    # WAF/CDN: não marcar FP — passa 1→2→3, depois fila humana
    if _WAF_HINTS.search(output):
        if pass_number >= 3:
            return (
                "inconclusive",
                "low",
                "WAF/CDN bloqueou PoC após 3 tentativas — revisão humana (waf_blocked).",
            )
        if pass_number == 2:
            return (
                "inconclusive",
                "low",
                "Possível WAF/CDN na 2ª verificação — tentar pass 3 com UA alternativo.",
            )
        return (
            "inconclusive",
            "low",
            "Possível WAF/CDN na 1ª verificação — reagendar re-PoC.",
        )

    if not result.success and not (result.stdout or "").strip():
        if pass_number >= 2:
            return (
                "false_positive",
                "medium",
                "PoC falhou nas 2 tentativas sem evidência reproduzível.",
            )
        return "inconclusive", "low", f"PoC falhou (exit {result.exit_code})."

    confirm = bool(_CONFIRM_HINTS.search(output))
    negate = bool(_NEGATE_HINTS.search(output))
    title_hit = bool(needle) and needle[:40] in output_l
    tid_hit = bool(tid) and tid in output_l
    cve_hit = False
    cve_m = re.search(r"CVE-\d{4}-\d+", title, re.I)
    cve = str(finding.get("cve") or (cve_m.group(0).upper() if cve_m else ""))
    if cve:
        cve_hit = cve.lower() in output_l

    ftype = classify_finding_type(finding)

    # Headers: presença/ausência no curl -I
    if ftype == "header" and result.success:
        header_keys = {
            "hsts": "strict-transport-security",
            "strict-transport": "strict-transport-security",
            "x-frame": "x-frame-options",
            "csp": "content-security-policy",
            "content-security": "content-security-policy",
            "x-content-type": "x-content-type-options",
            "missing-header:strict-transport": "strict-transport-security",
            "missing-header:x-frame": "x-frame-options",
        }
        title_l = (title + " " + tid).lower()
        for key, hdr in header_keys.items():
            if key in title_l:
                present = hdr in output_l
                if "missing" in title_l or "absent" in title_l:
                    if not present:
                        return "confirmed", "high", f"Header {hdr} ausente na resposta."
                    return "false_positive", "high", f"Header {hdr} está presente."
                if present:
                    return "confirmed", "medium", f"Header {hdr} observado."
                return "false_positive", "medium", f"Header {hdr} não encontrado."

    if ftype == "port_info":
        port_m = re.search(r"(\d+)/tcp", title)
        port = str(finding.get("port") or (port_m.group(1) if port_m else ""))
        if port and f"{port}/tcp" in output_l and "open" in output_l:
            conf = "high" if sources >= 2 else "high"
            return "confirmed", conf, "Porta confirmada aberta no re-scan."
        if pass_number >= 2:
            return "false_positive", "medium", "Porta não confirmada aberta."
        return "inconclusive", "low", "Re-scan de porta sem confirmação clara."

    # CVE + versão do serviço no surface
    if ftype == "cve" and cve_hit and result.success:
        from backend.ai.cvss import correlate_cve_version

        ports = list((surface_context or {}).get("ports") or [])
        corr = correlate_cve_version(finding, ports=ports, nmap_output=output)
        if confirm or tid_hit:
            conf = "high" if (sources >= 2 or not corr.get("weak")) else "medium"
            return "confirmed", conf, f"PoC reproduziu {cve}. {corr.get('reason', '')}"
        if corr.get("matched") and not corr.get("weak"):
            return "confirmed", "medium", f"{cve}: {corr.get('reason')}"
        if corr.get("matched") and corr.get("weak"):
            # Correlação fraca sozinha → não high no executivo
            return (
                "confirmed",
                "low",
                f"{cve} citado com correlação fraca de versão — revisar.",
            )
        svc_hint = _service_version_hint(ports, "")
        if svc_hint and any(tok in svc_hint for tok in ("http", "https", "ssl", "ssh")):
            return "confirmed", "low", f"{cve} citado; serviço no surface sem versão clara."

    # Template-id específico bateu
    if tid_hit and result.success and not negate:
        conf = "high" if (confirm or sources >= 2) else "medium"
        return "confirmed", conf, f"Template {tid} reproduzido no PoC."

    if (title_hit or cve_hit) and confirm and not negate:
        conf = "high" if sources >= 2 else "high"
        return "confirmed", conf, "PoC reproduziu o achado no output."
    if (title_hit or cve_hit) and result.success and not negate:
        conf = "medium" if sources < 2 else "high"
        return "confirmed", conf, "Achado citado novamente em verificação bem-sucedida."
    if negate and not title_hit and not cve_hit and not tid_hit:
        return "false_positive", "high", "Verificação indicou ausência do problema."
    if result.success and not title_hit and not cve_hit and not tid_hit and not confirm:
        if sev in {"info", "low"} or pass_number >= 2:
            return (
                "false_positive",
                "medium",
                "Verificação concluída sem reproduzir o achado.",
            )
        return "inconclusive", "low", "Sem evidência clara na 1ª verificação."

    if pass_number >= 2:
        return (
            "discarded",
            "medium",
            "Não reproduzível após 2 verificações — descartado do relatório executivo.",
        )

    return "inconclusive", "low", "Resultado ambíguo — reagendar re-verificação."


def _sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Prioriza: severidade → tipo verificável → multi-fonte → título."""

    def key(f: dict[str, Any]) -> tuple:
        sev = SEVERITY_ORDER.get(str(f.get("severity") or "unknown").lower(), 9)
        ftype = classify_finding_type(f)
        tpri = _TYPE_PRIORITY.get(ftype, 9)
        # Preferir já tipados (template/cve) e multi-fonte
        has_id = 0 if (f.get("template_id") or f.get("cve")) else 1
        sources = -int(f.get("sources") or 1)
        return (sev, tpri, has_id, sources, str(f.get("title") or ""))

    return sorted(findings, key=key)


def _apply_status(
    target: str,
    finding_id: str,
    status: str,
    *,
    evidence: str,
    confidence: str,
    verify_command: str,
    pass_number: int,
) -> dict[str, Any] | None:
    data = load_surface(target)
    if not data:
        return None
    for finding in data.get("findings") or []:
        if finding.get("id") != finding_id:
            continue
        finding["status"] = status
        finding["evidence"] = (evidence or finding.get("evidence") or "")[:1000]
        finding["confidence"] = confidence
        finding["verify_command"] = verify_command[:300]
        finding["verify_passes"] = int(finding.get("verify_passes") or 0) + 1
        finding["verify_pass_last"] = pass_number
        finding["finding_type"] = classify_finding_type(finding)
        from datetime import datetime, timezone

        finding["verified_at"] = datetime.now(timezone.utc).isoformat()
        if status == "discarded":
            finding["discard_reason"] = evidence[:300]
        if "waf" in (evidence or "").lower() or "cdn" in (evidence or "").lower():
            finding["needs_human_review"] = True
            finding["waf_blocked"] = True
        try:
            from backend.ai.cvss import enrich_finding

            enrich_finding(finding)
        except (ImportError, TypeError, ValueError, KeyError):
            pass
        save_surface(target, data)
        return finding
    return None


def _executive_eligible(f: dict[str, Any]) -> bool:
    """
    Gate rígido: confirmed + (high conf) OU (medium + multi-fonte/template/PoC tipado).
    """
    if f.get("status") != "confirmed":
        return False
    conf = str(f.get("confidence") or "low").lower()
    if conf == "low":
        return False
    if conf == "high":
        return True
    # medium: exige segunda fonte OU template-id OU curl_command do nuclei
    sources = int(f.get("sources") or 1)
    has_id = bool(f.get("template_id") or f.get("cve"))
    has_poc = bool(f.get("verify_command") or f.get("curl_command"))
    return sources >= 2 or (has_id and has_poc)


def confidence_gate_buckets(target: str) -> dict[str, list[dict[str, Any]]]:
    """
    Separa o que vai direto ao executivo vs fila humana.
    - executive: confirmed com gate rígido
    - human_queue: inconclusivo / WAF / confirmed fraco
    - archive: FP + discarded
    """
    data = load_surface(target) or {}
    findings = list(data.get("findings") or [])
    executive: list[dict[str, Any]] = []
    human_queue: list[dict[str, Any]] = []
    archive: list[dict[str, Any]] = []
    for f in findings:
        st = f.get("status")
        if st == "confirmed" and _executive_eligible(f):
            executive.append(f)
        elif st == "confirmed":
            human_queue.append(f)
        elif st == "inconclusive" or f.get("needs_human_review") or f.get("waf_blocked"):
            human_queue.append(f)
        elif st in {"false_positive", "discarded"}:
            archive.append(f)
        elif st == "candidate":
            human_queue.append(f)
    return {
        "executive": executive,
        "human_queue": human_queue,
        "archive": archive,
    }


def run_verification_pipeline(
    target: str,
    *,
    execute: ExecuteFn | None = None,
    max_findings: int | None = None,
    emit: Callable[[str, dict], None] | None = None,
    mission_id: str | None = None,
) -> VerifyPipelineResult:
    """
    Verifica candidatos/inconclusivos com PoC e fecha o estado para relatório assertivo.
    Prioriza high/critical e tipos verificáveis; processa em lotes até o teto.
    """
    from backend.config import VERIFY_MAX_FINDINGS
    from backend.executor.kali import execute_in_kali
    from backend.security.missions import get_mission_registry

    if max_findings is None:
        max_findings = VERIFY_MAX_FINDINGS

    def _default_execute(command: str, reason: str) -> ExecutionResult:
        return execute_in_kali(command, reason, mission_id=mission_id)

    exec_fn = execute or _default_execute
    result = VerifyPipelineResult()
    data = load_surface(target)
    if not data:
        return result

    urls = list(data.get("urls") or [])
    ports = list(data.get("ports") or [])
    surface_ctx = {"ports": ports, "urls": urls, "services": data.get("services") or []}

    pending = [
        f
        for f in (data.get("findings") or [])
        if f.get("status") in {"candidate", "inconclusive"}
    ]
    pending = _sort_findings(pending)

    # Garante que todos high/critical entram antes do teto (até max)
    critical_high = [
        f
        for f in pending
        if str(f.get("severity") or "").lower() in {"critical", "high"}
    ]
    others = [
        f
        for f in pending
        if str(f.get("severity") or "").lower() not in {"critical", "high"}
    ]
    # Expand teto se há mais critical/high que o limite
    effective_max = max(max_findings, len(critical_high))
    effective_max = min(effective_max, 80)  # hard cap segurança
    selected = (critical_high + others)[:effective_max]

    def _verify_one(finding: dict[str, Any], pass_number: int) -> VerifyOutcome:
        fid = str(finding.get("id") or "")
        title = str(finding.get("title") or "")
        cmd = build_verify_command(
            finding, target, urls=urls, ports=ports, pass_number=pass_number
        )
        if not cmd:
            _apply_status(
                target,
                fid,
                "discarded",
                evidence="Sem comando de PoC seguro aplicável.",
                confidence="low",
                verify_command="",
                pass_number=pass_number,
            )
            return VerifyOutcome(
                fid, title, "discarded", "low", "Sem PoC aplicável.", "", pass_number
            )

        if emit:
            emit(
                "verify_start",
                {
                    "finding_id": fid,
                    "title": title[:120],
                    "command": cmd,
                    "pass": pass_number,
                },
            )

        if mission_id and get_mission_registry().is_cancelled(mission_id):
            return VerifyOutcome(
                fid, title, "inconclusive", "low", "Missão cancelada.", cmd, pass_number
            )

        exec_result = exec_fn(cmd, f"Verificação PoC pass {pass_number}: {title[:80]}")
        result.verify_commands_run += 1
        status, confidence, reason = score_verification(
            finding,
            exec_result,
            pass_number=pass_number,
            surface_context=surface_ctx,
        )
        evidence = (
            f"{reason}\n---\n{(exec_result.stdout or exec_result.stderr or '')[:600]}"
        )
        _apply_status(
            target,
            fid,
            status,
            evidence=evidence,
            confidence=confidence,
            verify_command=cmd,
            pass_number=pass_number,
        )
        # Pacote de evidência em disco
        try:
            from backend.ai.evidence import write_finding_evidence

            data_now = load_surface(target) or {}
            finding_now = next(
                (x for x in (data_now.get("findings") or []) if x.get("id") == fid),
                finding,
            )
            write_finding_evidence(
                target,
                finding_now,
                command=cmd,
                stdout=exec_result.stdout or "",
                stderr=exec_result.stderr or "",
                reason=reason,
                pass_number=pass_number,
            )
        except (OSError, TypeError, ValueError, KeyError):
            pass
        if emit:
            emit(
                "verify_done",
                {
                    "finding_id": fid,
                    "title": title[:120],
                    "status": status,
                    "confidence": confidence,
                    "pass": pass_number,
                },
            )
        return VerifyOutcome(fid, title, status, confidence, reason, cmd, pass_number)

    need_reverify: list[str] = []
    for finding in selected:
        outcome = _verify_one(finding, 1)
        result.outcomes.append(outcome)
        if outcome.status == "inconclusive":
            need_reverify.append(outcome.finding_id)

    if need_reverify:
        data = load_surface(target) or data
        by_id = {f.get("id"): f for f in (data.get("findings") or [])}
        for fid in need_reverify:
            finding = by_id.get(fid)
            if not finding or finding.get("status") != "inconclusive":
                continue
            outcome = _verify_one(finding, 2)
            result.outcomes.append(outcome)

    # Pass 3 — só WAF / ainda inconclusivo após 2
    data = load_surface(target) or {}
    need_p3 = [
        f
        for f in (data.get("findings") or [])
        if f.get("status") == "inconclusive"
        and (
            f.get("waf_blocked")
            or "waf" in str(f.get("evidence") or "").lower()
            or "cdn" in str(f.get("evidence") or "").lower()
            or int(f.get("verify_pass_last") or 0) >= 2
        )
    ]
    for finding in need_p3[:20]:
        outcome = _verify_one(finding, 3)
        result.outcomes.append(outcome)

    # Fechamento assertivo — exceto fila WAF/humana
    data = load_surface(target) or {}
    for finding in list(data.get("findings") or []):
        st = finding.get("status")
        if st == "inconclusive" and (
            finding.get("needs_human_review") or finding.get("waf_blocked")
        ):
            continue  # fica na fila humana
        if st in {"candidate", "inconclusive"}:
            fid = str(finding.get("id") or "")
            # candidatos fora do teto (não selecionados) → discarded com motivo claro
            was_selected = any(o.finding_id == fid for o in result.outcomes)
            evidence = (
                "Não verificado ou ainda ambíguo após pipeline — excluído do executivo."
                if was_selected
                else "Fora do lote de verificação (prioridade menor) — excluído do executivo; re-rode verify."
            )
            _apply_status(
                target,
                fid,
                "discarded",
                evidence=evidence,
                confidence="low",
                verify_command=str(finding.get("verify_command") or ""),
                pass_number=int(finding.get("verify_pass_last") or 0),
            )
            result.outcomes.append(
                VerifyOutcome(
                    fid,
                    str(finding.get("title") or ""),
                    "discarded",
                    "low",
                    "Fechamento assertivo do pipeline.",
                    "",
                    2,
                )
            )

    data = load_surface(target) or {}
    for f in data.get("findings") or []:
        st = f.get("status")
        if st == "confirmed":
            result.confirmed += 1
        elif st == "false_positive":
            result.false_positive += 1
        elif st == "discarded":
            result.discarded += 1

    if emit:
        emit(
            "verify_summary",
            {
                "target": target,
                "confirmed": result.confirmed,
                "false_positive": result.false_positive,
                "discarded": result.discarded,
                "verify_commands_run": result.verify_commands_run,
            },
        )

    return result
