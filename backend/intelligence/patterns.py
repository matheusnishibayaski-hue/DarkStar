"""Extração e agregação de padrões a partir de findings."""

from __future__ import annotations

import re
from typing import Any

_TITLE_NORM = re.compile(r"[^a-z0-9]+")


def pattern_key_for_finding(finding: dict[str, Any]) -> tuple[str, str]:
    """
    Retorna (pattern_key, finding_type).

    Preferência: cve → template_id → título normalizado.
    """
    cve = str(finding.get("cve") or "").strip().upper()
    if cve.startswith("CVE-"):
        return f"cve:{cve}", "cve"
    tid = str(finding.get("template_id") or "").strip().lower()
    if tid:
        return f"template:{tid}", "template"
    title = str(finding.get("title") or "").strip().lower()
    title = _TITLE_NORM.sub("-", title).strip("-")[:80] or "unknown"
    return f"title:{title}", "title"


def compact_finding(finding: dict[str, Any]) -> dict[str, Any]:
    key, _ftype = pattern_key_for_finding(finding)
    sources = finding.get("sources") or []
    if not isinstance(sources, list):
        sources = []
    return {
        "id": str(finding.get("id") or ""),
        "finding_key": key,
        "title": str(finding.get("title") or "")[:512],
        "severity": str(finding.get("severity") or "unknown").lower(),
        "cve": str(finding.get("cve") or "").upper(),
        "template_id": str(finding.get("template_id") or ""),
        "status": str(finding.get("status") or ""),
        "sources": [str(s) for s in sources[:8]],
    }


def bump_patterns(
    patterns: dict[str, Any],
    findings: list[dict[str, Any]],
    *,
    industry: str = "generic",
) -> dict[str, Any]:
    """Incrementa frequência dos padrões no dict `{patterns: {key: {...}}}`."""
    bucket = patterns.setdefault("patterns", {})
    industry_key = (industry or "generic").strip().lower() or "generic"
    for finding in findings:
        key, ftype = pattern_key_for_finding(finding)
        full = f"{industry_key}|{key}"
        entry = bucket.get(full) or {
            "industry": industry_key,
            "pattern_key": key,
            "finding_type": ftype,
            "frequency": 0,
            "severity_hint": str(finding.get("severity") or "unknown").lower(),
            "title_sample": str(finding.get("title") or "")[:200],
        }
        entry["frequency"] = int(entry.get("frequency") or 0) + 1
        entry["severity_hint"] = str(
            finding.get("severity") or entry.get("severity_hint") or "unknown"
        )
        bucket[full] = entry
    return patterns


def top_patterns(
    patterns: dict[str, Any],
    *,
    industry: str | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    items = list((patterns.get("patterns") or {}).values())
    if industry:
        ind = industry.strip().lower()
        items = [i for i in items if i.get("industry") == ind or ind == "generic"]
    items.sort(key=lambda x: int(x.get("frequency") or 0), reverse=True)
    return items[:limit]
