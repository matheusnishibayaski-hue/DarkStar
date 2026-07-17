"""Risk score do engajamento a partir de findings confirmados (gate executive)."""

from __future__ import annotations

from typing import Any

_WEIGHT = {
    "critical": 10.0,
    "high": 6.0,
    "medium": 3.0,
    "low": 1.0,
    "info": 0.2,
    "unknown": 2.0,
}


def compute_risk_score(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Score 0–100 + faixa (critical/high/medium/low/info).
    Usa só confirmados do executivo (chamador filtra).
    """
    if not findings:
        return {
            "score": 0.0,
            "band": "info",
            "label": "Baixo / Informativo",
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "count": 0,
        }

    counts = {k: 0 for k in _WEIGHT}
    raw = 0.0
    for f in findings:
        sev = str(f.get("severity") or "unknown").lower()
        if sev not in counts:
            sev = "unknown"
        counts[sev] = counts.get(sev, 0) + 1
        w = _WEIGHT.get(sev, 2.0)
        # CVSS amplifica
        try:
            cvss = float(f.get("cvss_score") or 0)
        except (TypeError, ValueError):
            cvss = 0.0
        if cvss > 0:
            w = max(w, cvss)
        conf = str(f.get("confidence") or "medium").lower()
        if conf == "high":
            w *= 1.1
        elif conf == "low":
            w *= 0.7
        raw += w

    # Normaliza: 1 critical (~10) → ~40; satura em 100
    score = min(100.0, round(raw * 3.5, 1))
    if counts.get("critical", 0) > 0 or score >= 75:
        band, label = "critical", "Crítico"
    elif counts.get("high", 0) > 0 or score >= 50:
        band, label = "high", "Alto"
    elif counts.get("medium", 0) > 0 or score >= 25:
        band, label = "medium", "Médio"
    elif score > 0:
        band, label = "low", "Baixo"
    else:
        band, label = "info", "Informativo"

    return {
        "score": score,
        "band": band,
        "label": label,
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "info": counts.get("info", 0),
        "count": len(findings),
    }


def risk_score_for_target(target: str) -> dict[str, Any]:
    from backend.ai.verify import confidence_gate_buckets

    gate = confidence_gate_buckets(target)
    return compute_risk_score(gate.get("executive") or [])
