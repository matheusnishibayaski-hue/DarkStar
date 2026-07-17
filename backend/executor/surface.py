"""Attack Surface Graph — memória estruturada por alvo/engajamento."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.config import BASE_DIR, RECON_DIR
from backend.executor.recon_db import extract_targets, is_recon_target, normalize_target

SURFACE_DIR = BASE_DIR / "backend" / "surface"
SURFACE_DIR.mkdir(parents=True, exist_ok=True)

_PORT_LINE_RE = re.compile(
    r"(?P<port>\d{1,5})/tcp[ \t]+open"
    r"(?:[ \t]+(?P<service>[\w\-]+))?"
    r"(?:[ \t]+(?P<product>[A-Za-z][\w.\-]*))?"
    r"(?:[ \t]+(?P<version>\d[\w.\-]*))?",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_HOST_HINT_RE = re.compile(
    r"(?:\[?([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+)\]?)",
)
_SEV_RE = re.compile(
    r"\[(?P<sev>critical|high|medium|low|info|unknown)\]\s*(?P<title>.+)",
    re.IGNORECASE,
)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
# Nuclei: [critical] [template-id] Title  OR  [http] [critical] template-id
_NUCLEI_TPL_RE = re.compile(
    r"\[(?:critical|high|medium|low|info)\]\s*\[(?P<tid>[a-zA-Z0-9][\w.\-:]+)\]\s*(?P<title>.+)",
    re.IGNORECASE,
)
_NUCLEI_ID_INLINE = re.compile(
    r"\[(?P<tid>[a-z0-9][\w.\-]{2,80})\]",
    re.IGNORECASE,
)
_WAF_HINT_RE = re.compile(
    r"(cloudflare|akamai|sucuri|incapsula|imperva|aws.?waf|mod_security|"
    r"access\s*denied|attention\s*required|captcha|challenge|"
    r"just\s*a\s*(moment|second)|cf-ray)",
    re.IGNORECASE,
)
# nmap http-cookie-flags: cookie sem HttpOnly
_HTTPONLY_RE = re.compile(
    r"(?P<cookie>[A-Za-z_][\w\-]{2,64}):\s*(?:\n\|[_\s]*)?httponly flag not set",
    re.IGNORECASE,
)
_NIKTO_LINE_RE = re.compile(r"^\+\s+(?P<title>.+)$", re.MULTILINE)
_XFRAME_RE = re.compile(
    r"x-frame-options\s+header\s+is\s+not\s+present",
    re.IGNORECASE,
)
_HSTS_MISSING_RE = re.compile(
    r"(?:strict-transport-security|hsts).{0,40}(?:not\s+(?:set|present)|missing)",
    re.IGNORECASE,
)
_SERVER_BANNER_RE = re.compile(
    r"_?http-server-header:\s*(?P<header>[^\n|]+)",
    re.IGNORECASE,
)
_DIR_HIT_RE = re.compile(
    r"(?:^|\n)\s*(?P<path>/\S+)\s+\(Status:\s*(?P<code>200|301|302|403)\)",
    re.IGNORECASE,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _path_for(target: str) -> Path:
    return SURFACE_DIR / f"{normalize_target(target)}.json"


def empty_surface(
    target: str,
    *,
    objective: str = "",
    risk_profile: str = "safe-active",
    mission_id: str = "",
    client: str = "",
    scope_notes: str = "",
    brand_name: str = "",
    label: str = "",
) -> dict[str, Any]:
    return {
        "target": normalize_target(target),
        "objective": objective,
        "mission_id": mission_id,
        "risk_profile": risk_profile,
        "client": client,
        "scope_notes": scope_notes,
        "brand_name": brand_name or "Chat IA Kali",
        "label": label,
        "phase": "recon",
        "phases_completed": [],
        "hosts": [normalize_target(target)],
        "ports": [],
        "urls": [],
        "services": [],
        "findings": [],
        "hypotheses": [],
        "tools_run": [],
        "commands_run": 0,
        "baseline_findings": [],
        "baseline_at": None,
        "updated_at": _now(),
        "created_at": _now(),
    }


def load_surface(target: str) -> dict[str, Any]:
    path = _path_for(target)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def save_surface(target: str, data: dict[str, Any]) -> dict[str, Any]:
    path = _path_for(target)
    data = dict(data)
    data["target"] = normalize_target(target)
    data["updated_at"] = _now()
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return data


def get_or_create_surface(
    target: str,
    *,
    objective: str = "",
    risk_profile: str = "safe-active",
    mission_id: str = "",
    client: str = "",
    scope_notes: str = "",
    brand_name: str = "",
) -> dict[str, Any]:
    existing = load_surface(target)
    if existing:
        if objective:
            existing["objective"] = objective
        if mission_id:
            existing["mission_id"] = mission_id
        if risk_profile:
            existing["risk_profile"] = risk_profile
        if client:
            existing["client"] = client
        if scope_notes:
            existing["scope_notes"] = scope_notes
        if brand_name:
            existing["brand_name"] = brand_name
        return save_surface(target, existing)
    return save_surface(
        target,
        empty_surface(
            target,
            objective=objective,
            risk_profile=risk_profile,
            mission_id=mission_id,
            client=client,
            scope_notes=scope_notes,
            brand_name=brand_name,
        ),
    )


def _unique_append(items: list[Any], value: Any, key_fn=None) -> None:
    if key_fn is None:
        if value not in items:
            items.append(value)
        return
    keys = {key_fn(i) for i in items}
    k = key_fn(value)
    if k not in keys:
        items.append(value)


def _normalize_title(title: str) -> str:
    t = re.sub(r"\s+", " ", (title or "").strip().lower())
    t = re.sub(r"^\[(?:critical|high|medium|low|info|unknown)\]\s*", "", t)
    return t[:160]


def _extract_cve(text: str) -> str:
    m = _CVE_RE.search(text or "")
    return m.group(0).upper() if m else ""


def _extract_template_id(title: str, tool: str) -> str:
    """Extrai template-id Nuclei / identificador estável do achado."""
    t = title or ""
    m = _NUCLEI_TPL_RE.search(f"[info] {t}" if not t.startswith("[") else t)
    if m:
        tid = m.group("tid")
        if not re.match(r"^(critical|high|medium|low|info)$", tid, re.I):
            return tid.lower()
    # missing-header:hsts style
    m2 = re.search(r"(missing[-_]header[:\-][\w\-]+)", t, re.I)
    if m2:
        return m2.group(1).lower()
    cve = _extract_cve(t)
    if cve:
        return cve.lower()
    if (tool or "").lower() == "nuclei":
        for m3 in _NUCLEI_ID_INLINE.finditer(t):
            tid = m3.group("tid")
            if re.match(r"^(critical|high|medium|low|info|http|dns|tcp|ssl)$", tid, re.I):
                continue
            if len(tid) >= 4:
                return tid.lower()
    return ""


def _canonical_finding_key(
    *,
    title: str,
    severity: str,
    tool: str,
    cve: str = "",
    template_id: str = "",
    host: str = "",
    port: str = "",
) -> str:
    """Chave de correlação: CVE > template-id > host:port:title."""
    if cve:
        return f"cve:{cve.upper()}"
    if template_id:
        return f"tpl:{template_id.lower()}"
    port_m = re.search(r"(\d{1,5})/tcp", title or "")
    p = port or (port_m.group(1) if port_m else "")
    norm = _normalize_title(title)
    # remove tool-specific noise for fuzzy merge
    norm = re.sub(r"\b(nikto|nuclei|nmap|wpscan)\b", "", norm).strip()
    if p:
        return f"svc:{host or ''}:{p}:{norm[:80]}"
    return f"title:{norm[:100]}"


def _finding_id_from_key(key: str) -> str:
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]


def _merge_finding(existing: dict[str, Any], incoming: dict[str, Any]) -> None:
    """Mescla evidências/ferramentas no achado canônico."""
    tools = list(existing.get("tools") or [])
    t = incoming.get("tool")
    if t and t not in tools:
        tools.append(t)
    if existing.get("tool") and existing["tool"] not in tools:
        tools.insert(0, existing["tool"])
    existing["tools"] = tools[:8]
    # Eleva severidade se incoming for mais grave
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    old_s = str(existing.get("severity") or "unknown").lower()
    new_s = str(incoming.get("severity") or "unknown").lower()
    if order.get(new_s, 9) < order.get(old_s, 9):
        existing["severity"] = new_s
    ev = str(incoming.get("evidence") or "")
    if ev and ev not in str(existing.get("evidence") or ""):
        existing["evidence"] = (str(existing.get("evidence") or "") + "\n" + ev)[:1000]
    if incoming.get("template_id") and not existing.get("template_id"):
        existing["template_id"] = incoming["template_id"]
    if incoming.get("cve") and not existing.get("cve"):
        existing["cve"] = incoming["cve"]
    if incoming.get("url") and not existing.get("url"):
        existing["url"] = incoming["url"]
    if incoming.get("matched_at") and not existing.get("matched_at"):
        existing["matched_at"] = incoming["matched_at"]
    if incoming.get("curl_command") and not existing.get("curl_command"):
        existing["curl_command"] = incoming["curl_command"]
    if incoming.get("matcher_name") and not existing.get("matcher_name"):
        existing["matcher_name"] = incoming["matcher_name"]
    if incoming.get("cvss_score") is not None and existing.get("cvss_score") is None:
        existing["cvss_score"] = incoming["cvss_score"]
    if incoming.get("version") and not existing.get("version"):
        existing["version"] = incoming["version"]
    existing["sources"] = int(existing.get("sources") or 1) + 1
    # Mais fontes → confiança heurística maior no candidato
    if existing["sources"] >= 2 and existing.get("status") == "candidate":
        existing["confidence"] = "medium"


def _upsert_finding(
    data: dict[str, Any],
    finding: dict[str, Any],
    *,
    chat_session_id: str = "",
) -> None:
    if chat_session_id:
        finding = {**finding, "chat_session_id": chat_session_id}
    key = finding.get("canonical_key") or _canonical_finding_key(
        title=str(finding.get("title") or ""),
        severity=str(finding.get("severity") or "unknown"),
        tool=str(finding.get("tool") or ""),
        cve=str(finding.get("cve") or ""),
        template_id=str(finding.get("template_id") or ""),
        host=str(finding.get("host") or data.get("target") or ""),
    )
    finding["canonical_key"] = key
    finding["id"] = finding.get("id") or _finding_id_from_key(key)
    for existing in data.get("findings") or []:
        if existing.get("canonical_key") == key or existing.get("id") == finding["id"]:
            _merge_finding(existing, finding)
            return
        # Correlação secundária: mesmo CVE
        if finding.get("cve") and existing.get("cve") == finding["cve"]:
            _merge_finding(existing, finding)
            return
        if (
            finding.get("template_id")
            and existing.get("template_id") == finding["template_id"]
        ):
            _merge_finding(existing, finding)
            return
    finding.setdefault("tools", [finding["tool"]] if finding.get("tool") else [])
    finding.setdefault("sources", 1)
    finding.setdefault("confidence", "low")
    try:
        from backend.ai.cvss import enrich_finding

        enrich_finding(finding)
    except (ImportError, TypeError, ValueError, KeyError):
        pass
    data["findings"].append(finding)


def surface_summary(data: dict[str, Any]) -> dict[str, Any]:
    findings = data.get("findings") or []
    return {
        "target": data.get("target"),
        "label": data.get("label") or "",
        "client": data.get("client") or "",
        "phase": data.get("phase"),
        "risk_profile": data.get("risk_profile"),
        "hosts_count": len(data.get("hosts") or []),
        "ports_count": len(data.get("ports") or []),
        "urls_count": len(data.get("urls") or []),
        "findings_total": len(findings),
        "findings_confirmed": sum(1 for f in findings if f.get("status") == "confirmed"),
        "findings_candidates": sum(1 for f in findings if f.get("status") == "candidate"),
        "findings_inconclusive": sum(
            1 for f in findings if f.get("status") == "inconclusive"
        ),
        "findings_false_positive": sum(
            1 for f in findings if f.get("status") == "false_positive"
        ),
        "findings_discarded": sum(1 for f in findings if f.get("status") == "discarded"),
        "tools_run": list(data.get("tools_run") or []),
        "commands_run": data.get("commands_run", 0),
        "updated_at": data.get("updated_at"),
    }


def build_surface_context(target: str, *, max_findings: int = 12) -> str:
    data = load_surface(target)
    if not data:
        return ""
    compact = {
        "phase": data.get("phase"),
        "risk_profile": data.get("risk_profile"),
        "hosts": (data.get("hosts") or [])[:30],
        "ports": (data.get("ports") or [])[:40],
        "urls": (data.get("urls") or [])[:30],
        "services": (data.get("services") or [])[:30],
        "findings": (data.get("findings") or [])[:max_findings],
        "hypotheses": (data.get("hypotheses") or [])[:10],
        "tools_run": data.get("tools_run") or [],
        "summary": surface_summary(data),
    }
    return (
        f"[ATTACK SURFACE GRAPH — {data.get('target')}]:\n"
        f"{json.dumps(compact, ensure_ascii=False, indent=2)}"
    )


def update_surface_from_execution(
    target: str,
    *,
    command: str,
    tool: str,
    stdout: str,
    stderr: str,
    success: bool,
    blocked: bool,
    exit_code: int = 0,
    chat_session_id: str | None = None,
) -> dict[str, Any]:
    """Atualiza o grafo a partir de uma execução (sucesso ou falha parcial)."""
    data = get_or_create_surface(target)
    if chat_session_id:
        from backend.executor.session_intel import touch_session

        touch_session(chat_session_id, target)
    session_tag = chat_session_id or ""

    def _add_finding(payload: dict[str, Any]) -> None:
        _upsert_finding(data, payload, chat_session_id=session_tag)

    output = "\n".join(filter(None, [stdout or "", stderr or ""]))
    tool_name = (tool or (command.split() or [""])[0]).split("/")[-1]
    if tool_name and tool_name not in data["tools_run"]:
        data["tools_run"].append(tool_name)
    data["commands_run"] = int(data.get("commands_run") or 0) + 1

    # Hosts do comando + output
    for host in extract_targets(command, output):
        if is_recon_target(host):
            _unique_append(data["hosts"], normalize_target(host))

    for match in _PORT_LINE_RE.finditer(output):
        port = match.group("port")
        service = (match.group("service") or "").lower()
        product = (match.groupdict().get("product") or "").lower()
        version = (match.groupdict().get("version") or "").lower()
        entry = {"host": normalize_target(target), "port": port, "proto": "tcp"}
        if service:
            entry["service"] = service
        if product:
            entry["product"] = product
        if version:
            entry["version"] = version
        if service:
            svc_entry: dict[str, Any] = {
                "host": entry["host"],
                "port": port,
                "name": service,
            }
            if product:
                svc_entry["product"] = product
            if version:
                svc_entry["version"] = version
            _unique_append(
                data["services"],
                svc_entry,
                key_fn=lambda x: (x.get("host"), x.get("port"), x.get("name")),
            )
        _unique_append(
            data["ports"],
            entry,
            key_fn=lambda x: (x.get("host"), x.get("port"), x.get("proto")),
        )

    for url in _URL_RE.findall(output):
        clean = url.rstrip(").,;]")
        if len(clean) <= 500:
            _unique_append(data["urls"], clean)

    # Nuclei JSON/JSONL (preferencial — template-id, matched-at, curl-command)
    if tool_name == "nuclei" or "nuclei" in (command or "").lower():
        from backend.ai.nuclei_json import events_to_finding_patches, parse_nuclei_json_lines

        for patch in events_to_finding_patches(
            parse_nuclei_json_lines(output), tool=tool_name, command=command
        ):
            patch["host"] = normalize_target(target)
            patch["created_at"] = _now()
            patch["verified_at"] = None
            _add_finding(patch)

    # URLs próximas a linhas de finding (matched-at)
    line_urls = _URL_RE.findall(output)

    # Achados candidatos (Nuclei tipado + severidade genérica)
    seen_lines: set[str] = set()
    for match in _NUCLEI_TPL_RE.finditer(output):
        sev_m = re.search(
            r"\[(critical|high|medium|low|info)\]", match.group(0), re.I
        )
        sev = (sev_m.group(1) if sev_m else "unknown").lower()
        tid = match.group("tid").lower()
        title = match.group("title").strip()[:240]
        if not title or match.group(0) in seen_lines:
            continue
        seen_lines.add(match.group(0))
        cve = _extract_cve(title) or (_extract_cve(tid) if tid.startswith("cve-") else "")
        url_hit = line_urls[0] if line_urls else ""
        _add_finding(
            {
                "title": title if not tid.startswith("cve-") else (cve or title),
                "severity": sev,
                "status": "candidate",
                "evidence": match.group(0)[:500],
                "tool": tool_name,
                "command": command[:300],
                "template_id": tid,
                "cve": cve,
                "url": url_hit[:500] if url_hit else "",
                "matched_at": url_hit[:500] if url_hit else "",
                "host": normalize_target(target),
                "created_at": _now(),
                "verified_at": None,
            },
        )

    for match in _SEV_RE.finditer(output):
        line = match.group(0).strip()
        if line in seen_lines:
            continue
        # Já coberto pelo parser tipado Nuclei
        if _NUCLEI_TPL_RE.search(line):
            continue
        seen_lines.add(line)
        sev = match.group("sev").lower()
        title = match.group("title").strip()[:240]
        if not title:
            continue
        cve = _extract_cve(title)
        tid = _extract_template_id(title, tool_name)
        _add_finding(
            {
                "title": title,
                "severity": sev,
                "status": "candidate",
                "evidence": title[:500],
                "tool": tool_name,
                "command": command[:300],
                "template_id": tid,
                "cve": cve,
                "host": normalize_target(target),
                "created_at": _now(),
                "verified_at": None,
            },
        )

    for cve in dict.fromkeys(m.upper() for m in _CVE_RE.findall(output)):
        _add_finding(
            {
                "title": cve,
                "severity": "unknown",
                "status": "candidate",
                "evidence": cve,
                "tool": tool_name,
                "command": command[:300],
                "template_id": cve.lower(),
                "cve": cve,
                "host": normalize_target(target),
                "created_at": _now(),
                "verified_at": None,
            },
        )

    _extract_tool_specific_findings(
        data,
        target=target,
        tool_name=tool_name,
        command=command,
        output=output,
        chat_session_id=session_tag,
    )

    # Hipótese leve quando comando falhou / WAF
    if _WAF_HINT_RE.search(output):
        _unique_append(
            data["hypotheses"],
            "Possível WAF/CDN detectado no output — PoCs podem retornar inconclusivo.",
        )
    if not success and not blocked and output:
        hint = f"Comando '{tool_name}' falhou (exit {exit_code}) — investigar bloqueio/WAF/args."
        _unique_append(data["hypotheses"], hint)

    # Cap listas + limpa hosts lixo (css/js de HTML)
    data["hosts"] = [
        h for h in (data.get("hosts") or []) if is_recon_target(str(h))
    ][:100]
    data["findings"] = (data.get("findings") or [])[:100]
    data["ports"] = (data.get("ports") or [])[:200]
    data["urls"] = (data.get("urls") or [])[:200]
    data["hypotheses"] = (data.get("hypotheses") or [])[:30]

    saved = save_surface(target, data)
    try:
        from backend.executor.recon_db import sync_recon_counts_from_surface

        sync_recon_counts_from_surface(target, saved)
    except Exception:
        pass
    return saved


def _extract_tool_specific_findings(
    data: dict[str, Any],
    *,
    target: str,
    tool_name: str,
    command: str,
    output: str,
    chat_session_id: str = "",
) -> None:
    """Extrai achados de nmap/nikto/gobuster que não usam formato [sev] Nuclei."""
    host = normalize_target(target)
    tool = (tool_name or "").lower()
    cmd = (command or "").lower()

    def _add(payload: dict[str, Any]) -> None:
        _upsert_finding(data, payload, chat_session_id=chat_session_id)

    # --- nmap: cookie HttpOnly / banners ---
    if tool == "nmap" or "nmap" in cmd or "httponly flag not set" in output.lower():
        for match in _HTTPONLY_RE.finditer(output):
            cookie = match.group("cookie")
            title = f"Cookie sem flag HttpOnly: {cookie}"
            _add(
                {
                    "title": title,
                    "severity": "medium",
                    "status": "candidate",
                    "evidence": match.group(0)[:500],
                    "tool": tool or "nmap",
                    "command": command[:300],
                    "template_id": f"cookie-httponly:{cookie.lower()}",
                    "finding_type": "header",
                    "host": host,
                    "created_at": _now(),
                    "verified_at": None,
                },
            )
        for match in _SERVER_BANNER_RE.finditer(output):
            header = match.group("header").strip()
            if not header or len(header) > 120:
                continue
            # Só registra banners de stacks conhecidas (evita ruído)
            if not re.search(
                r"(iis|apache|nginx|microsoft-httpapi|tomcat|jetty|express)",
                header,
                re.I,
            ):
                continue
            _add(
                {
                    "title": f"Server banner exposto: {header}",
                    "severity": "info",
                    "status": "candidate",
                    "evidence": match.group(0)[:500],
                    "tool": tool or "nmap",
                    "command": command[:300],
                    "template_id": f"server-banner:{header.lower()[:60]}",
                    "finding_type": "info_disclosure",
                    "host": host,
                    "created_at": _now(),
                    "verified_at": None,
                },
            )

    # --- nikto ---
    if tool == "nikto" or "nikto" in cmd or _NIKTO_LINE_RE.search(output):
        for match in _NIKTO_LINE_RE.finditer(output):
            title = match.group("title").strip()[:240]
            if not title or title.lower().startswith("target ip:"):
                continue
            # Ignora linhas de metadados
            if re.match(r"^(start|end)\s+time", title, re.I):
                continue
            sev = "low"
            if _XFRAME_RE.search(title) or "x-frame-options" in title.lower():
                sev = "medium"
                title = "Header X-Frame-Options ausente"
            elif _HSTS_MISSING_RE.search(title):
                sev = "medium"
                title = "Header Strict-Transport-Security ausente"
            elif re.search(r"osvdb|cve-|vulnerable|outdated|xss|sql", title, re.I):
                sev = "medium"
            _add(
                {
                    "title": title,
                    "severity": sev,
                    "status": "candidate",
                    "evidence": match.group(0)[:500],
                    "tool": tool or "nikto",
                    "command": command[:300],
                    "template_id": f"nikto:{_normalize_title(title)[:60]}",
                    "finding_type": "misconfig",
                    "host": host,
                    "created_at": _now(),
                    "verified_at": None,
                },
            )

    # Headers ausentes mencionados em qualquer output
    if _XFRAME_RE.search(output) and tool not in {"nikto"}:
        _add(
            {
                "title": "Header X-Frame-Options ausente",
                "severity": "medium",
                "status": "candidate",
                "evidence": "X-Frame-Options header is not present",
                "tool": tool or "scan",
                "command": command[:300],
                "template_id": "missing-header:x-frame-options",
                "finding_type": "header",
                "host": host,
                "created_at": _now(),
                "verified_at": None,
            },
        )

    # --- gobuster / dirb: paths interessantes ---
    if tool in {"gobuster", "dirb", "ffuf", "feroxbuster"} or any(
        x in cmd for x in ("gobuster", "dirb", "ffuf", "feroxbuster")
    ):
        interesting = ("admin", "login", "backup", "config", "upload", "api", "debug", ".git", "phpmyadmin")
        for match in _DIR_HIT_RE.finditer(output):
            path = match.group("path")
            code = match.group("code")
            if not any(k in path.lower() for k in interesting):
                continue
            _add(
                {
                    "title": f"Caminho exposto ({code}): {path}",
                    "severity": "low" if code != "200" else "medium",
                    "status": "candidate",
                    "evidence": match.group(0).strip()[:500],
                    "tool": tool or "gobuster",
                    "command": command[:300],
                    "template_id": f"path:{path.lower()[:80]}",
                    "finding_type": "exposure",
                    "url": path,
                    "host": host,
                    "created_at": _now(),
                    "verified_at": None,
                },
            )


def repair_surface_from_stored_output(target: str) -> dict[str, Any]:
    """Reprocessa blobs de recon/logs quando surface existe sem findings (ex.: nmap antigo)."""
    data = load_surface(target)
    if data.get("findings"):
        # Ainda limpa hosts poluídos
        cleaned = [h for h in (data.get("hosts") or []) if is_recon_target(str(h))]
        if cleaned != (data.get("hosts") or []):
            data["hosts"] = cleaned[:100]
            return save_surface(target, data)
        return data

    from backend.executor.recon_db import get_recon_data

    recon = get_recon_data(target)
    blob_parts: list[str] = []
    if recon:
        ports = recon.get("open_ports") or []
        # Blob corrompido (scripts colados) ainda contém httponly / banners
        for p in ports:
            if isinstance(p, str) and len(p) > 40:
                blob_parts.append(p)
        for key in ("raw_output", "nikto", "nmap", "last_output"):
            if recon.get(key):
                blob_parts.append(str(recon[key]))

    blob = "\n".join(blob_parts)
    if not blob.strip():
        return data or {}

    tool_guess = str((recon or {}).get("last_tool") or "nmap")
    return update_surface_from_execution(
        target,
        command=f"{tool_guess} (backfill from recon cache)",
        tool=tool_guess,
        stdout=blob,
        stderr="",
        success=True,
        blocked=False,
    )


VALID_FINDING_STATUSES = frozenset(
    {"candidate", "inconclusive", "confirmed", "false_positive", "discarded"}
)


def mark_finding_status(
    target: str,
    finding_id: str,
    status: str,
    *,
    evidence: str = "",
) -> dict[str, Any] | None:
    if status not in VALID_FINDING_STATUSES:
        raise ValueError("status inválido")
    data = load_surface(target)
    if not data:
        return None
    for finding in data.get("findings") or []:
        if finding.get("id") == finding_id:
            finding["status"] = status
            if evidence:
                finding["evidence"] = evidence[:1000]
            if status in {"confirmed", "false_positive", "discarded", "inconclusive"}:
                finding["verified_at"] = _now()
            if status == "discarded" and evidence:
                finding["discard_reason"] = evidence[:300]
            save_surface(target, data)
            return finding
    return None


def list_surface_summaries() -> list[dict[str, Any]]:
    if not SURFACE_DIR.is_dir():
        return []
    items: list[dict[str, Any]] = []
    for path in SURFACE_DIR.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if isinstance(data, dict):
            items.append(surface_summary(data))
    items.sort(key=lambda x: str(x.get("updated_at") or ""), reverse=True)
    return items


def sync_surface_dir_alias() -> Path:
    """Garante pasta surface; RECON_DIR permanece independente."""
    SURFACE_DIR.mkdir(parents=True, exist_ok=True)
    RECON_DIR.mkdir(parents=True, exist_ok=True)
    return SURFACE_DIR
