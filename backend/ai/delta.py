"""Delta de reteste: compara baseline (findings + superfície) com estado atual."""

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


def _port_key(p: dict[str, Any] | Any) -> str:
    if isinstance(p, dict):
        host = str(p.get("host") or "")
        port = str(p.get("port") or "")
        proto = str(p.get("proto") or "tcp")
        return f"{host}:{port}/{proto}"
    return str(p)


def _service_key(s: dict[str, Any] | Any) -> str:
    if isinstance(s, dict):
        return (
            f"{s.get('host') or ''}:{s.get('port') or ''}:"
            f"{s.get('name') or ''}:{s.get('version') or ''}"
        )
    return str(s)


def _host_key(h: Any) -> str:
    if isinstance(h, dict):
        return str(h.get("host") or h.get("name") or "")
    return str(h)


def _snapshot_surface_subset(data: dict[str, Any]) -> dict[str, Any]:
    ports = data.get("ports") or []
    hosts = data.get("hosts") or []
    services = data.get("services") or []
    return {
        "ports": [
            {
                "key": _port_key(p),
                "host": p.get("host") if isinstance(p, dict) else None,
                "port": p.get("port") if isinstance(p, dict) else p,
                "proto": (p.get("proto") if isinstance(p, dict) else "tcp") or "tcp",
                "service": p.get("service") if isinstance(p, dict) else None,
            }
            for p in ports
        ],
        "hosts": [_host_key(h) for h in hosts],
        "services": [
            {
                "key": _service_key(s),
                "host": s.get("host") if isinstance(s, dict) else None,
                "port": s.get("port") if isinstance(s, dict) else None,
                "name": s.get("name") if isinstance(s, dict) else str(s),
                "version": s.get("version") if isinstance(s, dict) else None,
            }
            for s in services
        ],
    }


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
    data["baseline_surface"] = _snapshot_surface_subset(data)
    save_surface(target, data)
    return baseline


def snapshot_surface_baseline(target: str) -> dict[str, Any]:
    """Congela findings confirmados + superfície (portas/hosts/serviços)."""
    baseline = snapshot_confirmed(target)
    data = load_surface(target) or {}
    return {
        "findings": baseline,
        "surface": data.get("baseline_surface") or {},
        "baseline_at": data.get("baseline_at"),
        "baseline_count": len(baseline),
    }


def _diff_keys(
    baseline_items: list[dict[str, Any] | str],
    current_items: list[dict[str, Any] | str],
    key_fn,
) -> tuple[list[Any], list[Any]]:
    base_map = {}
    for item in baseline_items:
        k = key_fn(item) if not isinstance(item, str) else item
        if isinstance(item, dict) and item.get("key"):
            k = str(item["key"])
        base_map[str(k)] = item
    cur_map = {}
    for item in current_items:
        k = key_fn(item) if not isinstance(item, str) else item
        cur_map[str(k)] = item
    added = [cur_map[k] for k in cur_map if k not in base_map]
    removed = [base_map[k] for k in base_map if k not in cur_map]
    return added, removed


def compute_delta(target: str) -> dict[str, Any]:
    """
    Compara baseline_findings + baseline_surface com estado atual.
    Retorna: fixed, new, still_open, surface diffs, counts.
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
            "surface": {
                "ports_opened": [],
                "ports_closed": [],
                "hosts_added": [],
                "hosts_removed": [],
                "services_changed": [],
            },
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

    base_surf = data.get("baseline_surface") or {}
    has_surface_baseline = bool(base_surf) or bool(baseline)
    ports_opened, ports_closed = [], []
    hosts_added, hosts_removed = [], []
    services_changed: list[dict[str, Any]] = []

    if base_surf:
        ports_opened, ports_closed = _diff_keys(
            list(base_surf.get("ports") or []),
            list(data.get("ports") or []),
            _port_key,
        )
        hosts_added, hosts_removed = _diff_keys(
            list(base_surf.get("hosts") or []),
            list(data.get("hosts") or []),
            _host_key,
        )
        # Serviços: versão alterada = mesmo host:port:name com version diferente
        base_svc = {
            f"{s.get('host')}:{s.get('port')}:{s.get('name')}": s
            for s in (base_surf.get("services") or [])
            if isinstance(s, dict)
        }
        for s in data.get("services") or []:
            if not isinstance(s, dict):
                continue
            k = f"{s.get('host')}:{s.get('port')}:{s.get('name')}"
            prev = base_svc.get(k)
            if prev and str(prev.get("version") or "") != str(s.get("version") or ""):
                services_changed.append(
                    {
                        "host": s.get("host"),
                        "port": s.get("port"),
                        "name": s.get("name"),
                        "from_version": prev.get("version"),
                        "to_version": s.get("version"),
                    }
                )
        # Serviços novos
        for s in data.get("services") or []:
            if not isinstance(s, dict):
                continue
            k = f"{s.get('host')}:{s.get('port')}:{s.get('name')}"
            if k not in base_svc:
                services_changed.append(
                    {
                        "host": s.get("host"),
                        "port": s.get("port"),
                        "name": s.get("name"),
                        "from_version": None,
                        "to_version": s.get("version"),
                        "status": "new",
                    }
                )

    return {
        "has_baseline": has_surface_baseline,
        "baseline_at": data.get("baseline_at"),
        "fixed": fixed,
        "new": new,
        "still_open": still_open,
        "baseline_count": len(baseline),
        "current_count": len(current),
        "surface": {
            "ports_opened": ports_opened,
            "ports_closed": ports_closed,
            "hosts_added": hosts_added,
            "hosts_removed": hosts_removed,
            "services_changed": services_changed,
        },
    }


def format_delta_markdown(delta: dict[str, Any]) -> str:
    if not delta.get("has_baseline"):
        return (
            "*Sem baseline anterior — este engajamento será a referência "
            "para o próximo reteste.*"
        )
    surf = delta.get("surface") or {}
    lines = [
        f"**Baseline:** {delta.get('baseline_count', 0)} confirmado(s) · "
        f"**Atual:** {delta.get('current_count', 0)} · "
        f"**Corrigidos:** {len(delta.get('fixed') or [])} · "
        f"**Novos:** {len(delta.get('new') or [])} · "
        f"**Ainda abertos:** {len(delta.get('still_open') or [])}",
        "",
        "### Evolução da superfície",
        "",
        f"- Portas novas: **{len(surf.get('ports_opened') or [])}** · "
        f"fechadas: **{len(surf.get('ports_closed') or [])}**",
        f"- Ativos novos: **{len(surf.get('hosts_added') or [])}** · "
        f"removidos: **{len(surf.get('hosts_removed') or [])}**",
        f"- Serviços alterados/novos: **{len(surf.get('services_changed') or [])}**",
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
    if surf.get("ports_opened"):
        lines.append("### Portas novas abertas")
        lines.append("")
        for p in (surf.get("ports_opened") or [])[:20]:
            if isinstance(p, dict):
                lines.append(
                    f"- {p.get('host') or '—'}:{p.get('port')}/{p.get('proto') or 'tcp'}"
                    + (f" ({p.get('service')})" if p.get("service") else "")
                )
            else:
                lines.append(f"- {p}")
        lines.append("")
    return "\n".join(lines)
