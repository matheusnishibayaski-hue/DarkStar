"""Helpers de relatório CLI: JSON, SARIF e exit codes a partir do Attack Surface."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.ai.findings import findings_for_report
from backend.ai.remediation import remediation_for
from backend.ai.risk_score import risk_score_for_target
from backend.deps import APP_VERSION

# Exit codes documentados em docs/CLI.md
EXIT_OK = 0
EXIT_HIGH = 1
EXIT_CRITICAL = 2
EXIT_ERROR = 100
EXIT_SCOPE = 102

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")


def _sev(finding: dict[str, Any]) -> str:
    return str(finding.get("severity") or "unknown").strip().lower() or "unknown"


def flatten_report_findings(
    buckets: dict[str, list[dict[str, Any]]],
    *,
    include_candidates: bool = True,
) -> list[dict[str, Any]]:
    """Lista única de findings (confirmados primeiro) para JSON/SARIF."""
    order = ("confirmed", "inconclusive", "candidates", "false_positive", "discarded")
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for key in order:
        if key == "candidates" and not include_candidates:
            continue
        for f in buckets.get(key) or []:
            fid = str(f.get("id") or "")
            title = str(f.get("title") or "")
            dedupe = fid or f"{_sev(f)}|{title}"
            if dedupe in seen:
                continue
            seen.add(dedupe)
            rem = remediation_for(f)
            row = dict(f)
            status_map = {
                "confirmed": "confirmed",
                "false_positive": "false_positive",
                "discarded": "discarded",
                "inconclusive": "inconclusive",
                "candidates": "candidate",
            }
            row["status"] = f.get("status") or status_map.get(key) or key
            row["remediation"] = rem.get("action") or ""
            row["remediation_title"] = rem.get("title") or ""
            out.append(row)
    return out


def count_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        s = _sev(f)
        if s not in counts:
            counts[s] = 0
        counts[s] += 1
    return counts


def determine_exit_code(*, critical: int = 0, high: int = 0) -> int:
    if critical > 0:
        return EXIT_CRITICAL
    if high > 0:
        return EXIT_HIGH
    return EXIT_OK


def build_cli_report(
    target: str,
    *,
    risk_profile: str = "",
    scan_profile: str = "",
    rounds: int = 0,
    tools_executed: int = 0,
    stopped_reason: str = "",
    objective_met: bool = False,
    markdown_report: str = "",
    message: str = "",
    include_candidates: bool = True,
) -> dict[str, Any]:
    """Monta relatório JSON estruturado pós-autonomous (ou dry-run pós-validação)."""
    buckets = findings_for_report(target)
    findings = flatten_report_findings(buckets, include_candidates=include_candidates)
    # Exit codes usam confirmados + inconclusive (não FP/discarded); critical/high de todos relevantes
    scored = [
        f
        for f in findings
        if f.get("status") in {"confirmed", "inconclusive", "candidate"}
    ]
    counts = count_by_severity(scored)
    try:
        risk = risk_score_for_target(target)
    except Exception:  # noqa: BLE001
        risk = {"score": 0, "band": "unknown", "label": "—"}

    exit_code = determine_exit_code(critical=counts.get("critical", 0), high=counts.get("high", 0))
    return {
        "status": "completed",
        "target": target,
        "risk_profile": risk_profile,
        "scan_profile": scan_profile,
        "vulnerability_count": len(scored),
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "info": counts.get("info", 0),
        "findings": findings,
        "buckets": {k: len(v or []) for k, v in buckets.items()},
        "risk": risk,
        "rounds": rounds,
        "tools_executed": tools_executed,
        "stopped_reason": stopped_reason,
        "objective_met": objective_met,
        "message": message,
        "markdown_report": markdown_report,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": APP_VERSION,
        "exit_code": exit_code,
    }


def _sarif_level(severity: str) -> str:
    s = (severity or "").lower()
    if s == "critical":
        return "error"
    if s == "high":
        return "error"
    if s == "medium":
        return "warning"
    if s in {"low", "info"}:
        return "note"
    return "warning"


def convert_to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    """SARIF 2.1.0 mínimo — locations usam host/url (pentest), não file:line."""
    results: list[dict[str, Any]] = []
    for f in report.get("findings") or []:
        if not isinstance(f, dict):
            continue
        rule_id = (
            str(f.get("template_id") or "").strip()
            or str(f.get("cve") or "").strip()
            or str(f.get("id") or "").strip()
            or str(f.get("title") or "finding")[:80]
        )
        msg = str(f.get("title") or f.get("evidence") or "Finding")
        desc = str(f.get("evidence") or f.get("remediation") or "")
        uri = str(f.get("url") or f.get("matched_at") or f.get("host") or report.get("target") or "")
        locations: list[dict[str, Any]] = []
        if uri:
            locations.append(
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri if "://" in uri else f"host://{uri}"},
                    }
                }
            )
        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(_sev(f)),
                "message": {"text": msg if not desc else f"{msg}\n{desc}"[:2000]},
                "locations": locations,
                "properties": {
                    "severity": _sev(f),
                    "status": f.get("status"),
                    "tool": f.get("tool"),
                    "remediation": f.get("remediation"),
                },
            }
        )

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DarkStar",
                        "version": str(report.get("version") or APP_VERSION),
                        "informationUri": "https://github.com",
                    }
                },
                "results": results,
            }
        ],
    }


def save_cli_output(report: dict[str, Any], output_file: str, format_type: str) -> None:
    """Persiste report em JSON ou SARIF."""
    import json
    from pathlib import Path

    path = Path(output_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    fmt = (format_type or "json").lower()
    if fmt == "sarif":
        payload = convert_to_sarif(report)
    else:
        payload = report
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
