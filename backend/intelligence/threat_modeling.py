"""Threat modeling heurístico — assets + chains + scan_plan."""

from __future__ import annotations

import json
import logging
from typing import Any

from backend.ai.chains import infer_attack_chains
from backend.executor.recon_db import normalize_target
from backend.executor.surface import load_surface
from backend.intelligence.asset_catalog import assets_for_industry
from backend.intelligence.business_context import BusinessContext, parse_business_context
from backend.intelligence import store

logger = logging.getLogger(__name__)

DISCLAIMER = (
    "Modelo heurístico local; não substitui threat model formal (STRIDE/PTES) "
    "nem validação humana."
)


def build_scan_plan(
    surface: dict[str, Any],
    assets: list[dict[str, Any]],
    chains: list[dict[str, str]],
) -> list[dict[str, Any]]:
    plan: list[dict[str, Any]] = []
    ports = surface.get("ports") or []
    urls = surface.get("urls") or []
    findings = surface.get("findings") or []
    tools = {str(t).lower() for t in (surface.get("tools_run") or [])}

    if not ports:
        plan.append(
            {
                "phase": "enumerate",
                "focus": "Descobrir portas/serviços",
                "tools_hint": ["nmap"],
                "priority": 1,
            }
        )
    if urls or any(str(p.get("port")) in {"80", "443", "8080", "8443"} for p in ports):
        if "nuclei" not in tools:
            plan.append(
                {
                    "phase": "vuln_scan",
                    "focus": "Scan de templates web (nuclei -jsonl)",
                    "tools_hint": ["nuclei", "httpx"],
                    "priority": 1,
                }
            )
        plan.append(
            {
                "phase": "enumerate",
                "focus": "Mapear paths/tecnologias web",
                "tools_hint": ["httpx", "whatweb", "ffuf"],
                "priority": 2,
            }
        )

    unverified = [
        f
        for f in findings
        if str(f.get("status") or "") in {"", "candidate", "inconclusive"}
    ]
    if unverified:
        plan.append(
            {
                "phase": "verify",
                "focus": f"PoC/verify de {len(unverified)} candidato(s)",
                "tools_hint": ["curl", "nuclei", "httpx"],
                "priority": 1,
            }
        )

    if chains:
        plan.append(
            {
                "phase": "vuln_scan",
                "focus": f"Validar hipótese de cadeia: {chains[0].get('title', 'chain')}",
                "tools_hint": ["nuclei", "nmap"],
                "priority": 2,
            }
        )

    # assets de alta criticidade empurram foco
    for asset in sorted(assets, key=lambda a: -int(a.get("criticality") or 0))[:2]:
        plan.append(
            {
                "phase": "enumerate",
                "focus": f"Priorizar asset: {asset.get('name')} ({asset.get('focus')})",
                "tools_hint": ["nmap", "httpx", "nuclei"],
                "priority": 2 if int(asset.get("criticality") or 0) >= 9 else 3,
            }
        )

    # dedup por focus
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for step in sorted(plan, key=lambda x: int(x.get("priority") or 9)):
        focus = str(step.get("focus") or "")
        if focus in seen:
            continue
        seen.add(focus)
        unique.append(step)
    return unique[:12]


def generate_threat_model(
    target: str,
    context: BusinessContext | dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Gera e persiste threat model heurístico para o alvo."""
    if isinstance(context, dict) or context is None:
        ctx = parse_business_context(context if isinstance(context, dict) else {})
    else:
        ctx = context

    norm = normalize_target(target)
    surface = load_surface(norm) or {
        "target": norm,
        "findings": [],
        "ports": [],
        "urls": [],
        "tools_run": [],
    }
    industry = ctx.normalized_industry()
    assets = assets_for_industry(industry)
    chains = infer_attack_chains(surface) if surface.get("findings") or surface.get("ports") else []
    scan_plan = build_scan_plan(surface, assets, chains)

    payload = {
        "target": norm,
        "context": ctx.to_dict(),
        "assets": assets,
        "chains": chains,
        "scan_plan": scan_plan,
        "disclaimer": DISCLAIMER,
    }
    _persist_threat_model(norm, payload, industry=industry, ctx=ctx)
    return payload


def get_threat_model(target: str) -> dict[str, Any] | None:
    norm = normalize_target(target)
    if store.use_postgres():
        from backend.database.db import init_db, session_scope
        from backend.database.models_intelligence import TargetIntelligence

        init_db()
        with session_scope() as session:
            row = (
                session.query(TargetIntelligence)
                .filter_by(target_name=norm)
                .one_or_none()
            )
            if not row or not row.threat_model_json:
                return store.load_threat_model_json(norm)
            try:
                data = json.loads(row.threat_model_json)
            except json.JSONDecodeError:
                return None
            return data if isinstance(data, dict) else None
    return store.load_threat_model_json(norm)


def _persist_threat_model(
    target: str,
    payload: dict[str, Any],
    *,
    industry: str,
    ctx: BusinessContext,
) -> None:
    store.save_threat_model_json(target, payload)
    if not store.use_postgres():
        return
    from datetime import datetime, timezone

    from backend.database.db import init_db, session_scope
    from backend.database.models_intelligence import TargetIntelligence

    init_db()
    with session_scope() as session:
        row = session.query(TargetIntelligence).filter_by(target_name=target).one_or_none()
        blob = json.dumps(payload, ensure_ascii=False)
        now = datetime.now(timezone.utc)
        if row is None:
            session.add(
                TargetIntelligence(
                    target_name=target,
                    industry=industry,
                    company_size=ctx.company_size,
                    findings_aggregate="{}",
                    threat_model_json=blob,
                    updated_at=now,
                )
            )
        else:
            row.industry = industry or row.industry
            row.company_size = ctx.company_size or row.company_size
            row.threat_model_json = blob
            row.updated_at = now
