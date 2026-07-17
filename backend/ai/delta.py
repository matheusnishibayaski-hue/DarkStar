"""Delta de reteste: compara baseline anterior com achados confirmados atuais."""

from __future__ import annotations

from typing import Any

from backend.executor.surface import load_surface, save_surface


def _finding_key(f: dict[str, Any]) -> str:
    cve = str(f.get("cve") or "").upper()
    if cve:
        return f"cve:{cve}"
    tid = str(f.get("template_id") or "").lower()
    if tid:
        return f"tpl:{tid}"
    return f"title:{str(f.get('title') or '').lower().strip()[:120]}"


def snapshot_confirmed(target: str) -> list[dict[str, Any]]:
    """Salva baseline dos confirmados atuais (para próximo reteste)."""
    data = load_surface(target)
    if not data:
        return []
    confirmed = [f for f in (data.get("findings") or []) if f.get("status") == "confirmed"]
    baseline = [
        {
            "key": _finding_key(f),
            "id": f.get("id"),
            "title": f.get("title"),
            "severity": f.get("severity"),
            "cve": f.get("cve"),
            "template_id": f.get("template_id"),
            "status": "confirmed",
        }
        for f in confirmed
    ]
    data["baseline_findings"] = baseline
    data["baseline_at"] = data.get("updated_at")
    save_surface(target, data)
    return baseline


def compute_delta(target: str) -> dict[str, Any]:
    """
    Compara baseline_findings com confirmados atuais.
    Retorna: fixed, new, still_open, unchanged_count.
    """
    data = load_surface(target)
    if not data:
        return {
            "has_baseline": False,
            "fixed": [],
            "new": [],
            "still_open": [],
            "baseline_count": 0,
            "current_count": 0,
        }

    baseline = list(data.get("baseline_findings") or [])
    current = [f for f in (data.get("findings") or []) if f.get("status") == "confirmed"]
    base_map: dict[str, Any] = {}
    for b in baseline:
        k = str(b.get("key") or _finding_key(b))
        base_map[k] = b
    cur_map = {_finding_key(f): f for f in current}

    fixed = []
    for k, b in base_map.items():
        if k not in cur_map:
            fixed.append(b)

    new = []
    still_open = []
    for k, f in cur_map.items():
        if k not in base_map:
            new.append(f)
        else:
            still_open.append(f)

    return {
        "has_baseline": bool(baseline),
        "baseline_at": data.get("baseline_at"),
        "fixed": fixed,
        "new": new,
        "still_open": still_open,
        "baseline_count": len(baseline),
        "current_count": len(current),
    }


def format_delta_markdown(delta: dict[str, Any]) -> str:
    if not delta.get("has_baseline"):
        return (
            "*Sem baseline anterior — este engajamento será a referência "
            "para o próximo reteste.*"
        )
    lines = [
        f"**Baseline:** {delta.get('baseline_count', 0)} confirmado(s) · "
        f"**Atual:** {delta.get('current_count', 0)} · "
        f"**Corrigidos:** {len(delta.get('fixed') or [])} · "
        f"**Novos:** {len(delta.get('new') or [])} · "
        f"**Ainda abertos:** {len(delta.get('still_open') or [])}",
        "",
    ]
    if delta.get("fixed"):
        lines.append("### Corrigidos desde o baseline")
        lines.append("")
        for f in delta["fixed"][:30]:
            lines.append(
                f"- [{str(f.get('severity', '?')).upper()}] {f.get('title', f.get('key'))}"
            )
        lines.append("")
    if delta.get("new"):
        lines.append("### Novos confirmados")
        lines.append("")
        for f in delta["new"][:30]:
            lines.append(
                f"- [{str(f.get('severity', '?')).upper()}] {f.get('title')}"
            )
        lines.append("")
    if delta.get("still_open"):
        lines.append("### Ainda abertos")
        lines.append("")
        for f in delta["still_open"][:30]:
            lines.append(
                f"- [{str(f.get('severity', '?')).upper()}] {f.get('title')}"
            )
        lines.append("")
    return "\n".join(lines)
