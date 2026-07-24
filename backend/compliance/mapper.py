"""Mapeamento finding → controles (heurístico conservador)."""

from __future__ import annotations

from typing import Any

from backend.compliance.frameworks import get_framework


def _blob(finding: dict[str, Any]) -> str:
    parts = [
        str(finding.get("title") or ""),
        str(finding.get("template_id") or ""),
        str(finding.get("cve") or ""),
        str(finding.get("severity") or ""),
    ]
    return " ".join(parts).lower()


def map_findings_to_controls(
    findings: list[dict[str, Any]],
    framework_id: str,
) -> dict[str, Any]:
    fw = get_framework(framework_id)
    if not fw:
        raise ValueError(f"Framework desconhecido: {framework_id}")

    controls_out: list[dict[str, Any]] = []
    for control in fw["controls"]:
        matched: list[dict[str, Any]] = []
        keywords = [str(k).lower() for k in (control.get("keywords") or [])]
        for finding in findings:
            text = _blob(finding)
            if any(k in text for k in keywords):
                matched.append(
                    {
                        "id": finding.get("id"),
                        "title": finding.get("title"),
                        "severity": finding.get("severity"),
                        "status": finding.get("status"),
                    }
                )
        controls_out.append(
            {
                "id": control["id"],
                "name": control["name"],
                "critical": bool(control.get("critical")),
                "gap": bool(matched),
                "matched_findings": matched[:20],
            }
        )
    return {
        "framework": framework_id,
        "name": fw["name"],
        "controls": controls_out,
    }
