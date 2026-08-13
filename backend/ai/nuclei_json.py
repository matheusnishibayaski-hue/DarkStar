"""Parser de saída Nuclei JSON/JSONL → findings tipados."""

from __future__ import annotations

import json
import re
from typing import Any

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)


def parse_nuclei_json_lines(output: str) -> list[dict[str, Any]]:
    """
    Extrai eventos Nuclei de stdout (uma linha JSON por finding, ou array).
    Campos úteis: template-id, matched-at, curl-command, info.severity, matcher-name.
    """
    if not output or not output.strip():
        return []
    events: list[dict[str, Any]] = []
    text = output.strip()
    # Array JSON completo
    if text.startswith("["):
        try:
            arr = json.loads(text)
            if isinstance(arr, list):
                for item in arr:
                    if isinstance(item, dict):
                        ev = _normalize_event(item)
                        if ev:
                            events.append(ev)
                return events
        except json.JSONDecodeError:
            pass

    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] not in "{[":
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    ev = _normalize_event(item)
                    if ev:
                        events.append(ev)
        elif isinstance(obj, dict):
            ev = _normalize_event(obj)
            if ev:
                events.append(ev)
    return events


def _normalize_event(obj: dict[str, Any]) -> dict[str, Any] | None:
    info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
    tid = str(
        obj.get("template-id") or obj.get("template_id") or obj.get("templateID") or ""
    ).strip()
    name = str(info.get("name") or obj.get("name") or tid or "").strip()
    if not name and not tid:
        return None
    sev = str(info.get("severity") or obj.get("severity") or "unknown").lower()
    if sev not in {"critical", "high", "medium", "low", "info", "unknown"}:
        sev = "unknown"
    matched = str(obj.get("matched-at") or obj.get("matched_at") or obj.get("host") or "").strip()
    curl_cmd = str(obj.get("curl-command") or obj.get("curl_command") or "").strip()
    matcher = str(obj.get("matcher-name") or obj.get("matcher_name") or "").strip()
    extracted = obj.get("extracted-results") or obj.get("extracted_results") or []
    if not isinstance(extracted, list):
        extracted = [str(extracted)]
    cve = ""
    meta = info.get("classification") if isinstance(info.get("classification"), dict) else {}
    cve_list = meta.get("cve-id") or meta.get("cve_id") or info.get("cve-id") or []
    if isinstance(cve_list, str):
        cve_list = [cve_list]
    if isinstance(cve_list, list) and cve_list:
        cve = str(cve_list[0]).upper()
    if not cve:
        m = _CVE_RE.search(f"{name} {tid}")
        if m:
            cve = m.group(0).upper()
    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    cvss_score = None
    try:
        raw = meta.get("cvss-score") or meta.get("cvss_score")
        if raw is not None:
            cvss_score = float(raw)
    except (TypeError, ValueError):
        pass
    return {
        "template_id": tid.lower() if tid else "",
        "title": name[:240] or tid,
        "severity": sev,
        "matched_at": matched[:500],
        "url": matched[:500] if matched.startswith("http") else "",
        "curl_command": curl_cmd[:500],
        "matcher_name": matcher[:120],
        "extracted_results": [str(x)[:200] for x in extracted[:10]],
        "cve": cve,
        "tags": [str(t)[:40] for t in (tags or [])[:15]],
        "cvss_score": cvss_score,
        "raw_line": json.dumps(obj, ensure_ascii=False)[:800],
    }


def events_to_finding_patches(
    events: list[dict[str, Any]], *, tool: str, command: str
) -> list[dict[str, Any]]:
    """Converte eventos normalizados em patches para _upsert_finding."""
    patches = []
    for ev in events:
        patches.append(
            {
                "title": ev["title"],
                "severity": ev["severity"],
                "status": "candidate",
                "evidence": (ev.get("raw_line") or ev["title"])[:500],
                "tool": tool,
                "command": command[:300],
                "template_id": ev.get("template_id") or "",
                "cve": ev.get("cve") or "",
                "url": ev.get("url") or "",
                "matched_at": ev.get("matched_at") or "",
                "curl_command": ev.get("curl_command") or "",
                "matcher_name": ev.get("matcher_name") or "",
                "extracted_results": ev.get("extracted_results") or [],
                "tags": ev.get("tags") or [],
                "cvss_score": ev.get("cvss_score"),
                "finding_type": _guess_type(ev),
            }
        )
    return patches


def _guess_type(ev: dict[str, Any]) -> str:
    blob = " ".join(
        [
            str(ev.get("title") or ""),
            str(ev.get("template_id") or ""),
            " ".join(ev.get("tags") or []),
        ]
    ).lower()
    if ev.get("cve") or "cve-" in blob:
        return "cve"
    if any(k in blob for k in ("hsts", "x-frame", "csp", "header", "strict-transport")):
        return "header"
    if any(k in blob for k in ("ssl", "tls", "certificate")):
        return "ssl"
    if "xss" in blob:
        return "xss"
    if "sqli" in blob or "sql-injection" in blob:
        return "sqli"
    return "web_vuln"
