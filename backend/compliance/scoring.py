"""Score de cobertura indicativa (não é conformidade certificada)."""

from __future__ import annotations

from typing import Any


def indicative_coverage(control_map: dict[str, Any]) -> dict[str, Any]:
    """
    Calcula cobertura indicativa 0–100.

    Controles críticos com gap pesam 2x. Status nunca é 'Compliant'.
    """
    controls = control_map.get("controls") or []
    if not controls:
        return {
            "indicative_coverage_0_100": 100.0,
            "status": "no_mapped_gaps",
            "gaps": 0,
            "controls_total": 0,
            "weighted_gaps": 0.0,
            "weighted_total": 0.0,
        }

    weighted_total = 0.0
    weighted_gaps = 0.0
    gaps = 0
    for c in controls:
        w = 2.0 if c.get("critical") else 1.0
        weighted_total += w
        if c.get("gap"):
            gaps += 1
            weighted_gaps += w

    # coverage = quanto está "sem gap mapeado"
    coverage = 100.0 if weighted_total <= 0 else round(
        (1.0 - (weighted_gaps / weighted_total)) * 100.0, 1
    )
    status = "gaps_detected" if gaps else "no_mapped_gaps"
    return {
        "indicative_coverage_0_100": coverage,
        "status": status,
        "gaps": gaps,
        "controls_total": len(controls),
        "weighted_gaps": weighted_gaps,
        "weighted_total": weighted_total,
    }
