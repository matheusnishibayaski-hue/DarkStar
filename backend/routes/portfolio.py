"""Carteira de engajamentos — filtrada pela conversa ativa."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from backend.ai.delta import compute_delta
from backend.ai.risk_history import load_risk_history
from backend.ai.risk_score import risk_score_for_target
from backend.clients.runtime import get_active_client_id
from backend.clients.store import list_clients
from backend.executor.recon_db import normalize_target
from backend.executor.session_intel import load_session
from backend.executor.surface import list_surface_summaries, load_surface
from backend.schedule.store import list_jobs

router = APIRouter(prefix="/api", tags=["portfolio"])


@router.get("/portfolio")
def api_portfolio(
    session_id: str = Query(..., min_length=1, max_length=128),
    client_id: str | None = Query(default=None, max_length=64),
):
    """Carteira: só engajamentos cujos alvos pertencem à conversa."""
    sid = (session_id or "").strip()
    if not sid:
        raise HTTPException(
            status_code=400,
            detail="session_id required (portfolio is scoped per conversation)",
        )

    session_data = load_session(sid) or {}
    session_targets = {
        normalize_target(t)
        for t in (session_data.get("targets") or [])
        if normalize_target(t)
    }

    cid = (client_id or "").strip() or None
    clients = list_clients()
    if cid:
        clients = [c for c in clients if c.get("client_id") == cid]

    jobs = list_jobs(client_id=cid)
    jobs_by_target: dict[str, list] = {}
    for j in jobs:
        jobs_by_target.setdefault(str(j.get("target")), []).append(j)

    rows = []
    if not session_targets:
        return {
            "active_client_id": get_active_client_id(),
            "filter_client_id": cid,
            "session_id": sid,
            "clients": [
                {
                    "client_id": c.get("client_id"),
                    "display_name": c.get("display_name"),
                    "targets_count": c.get("targets_count"),
                }
                for c in clients
            ],
            "engagements": [],
            "schedules_count": 0,
        }

    for summary in list_surface_summaries(client_id=cid):
        target = str(summary.get("target") or "")
        host = normalize_target(target)
        if host not in session_targets:
            continue
        surface = load_surface(target) or {}
        try:
            risk = risk_score_for_target(target)
        except Exception:  # noqa: BLE001
            risk = {"score": 0, "label": "—"}
        try:
            delta = compute_delta(target)
        except Exception:  # noqa: BLE001
            delta = {"has_baseline": False}
        hist = load_risk_history(target, limit=12)
        next_jobs = sorted(
            jobs_by_target.get(target) or [],
            key=lambda x: str(x.get("next_run_at") or ""),
        )
        rows.append(
            {
                "target": target,
                "client": surface.get("client") or summary.get("client") or "",
                "client_id": surface.get("client_id") or summary.get("client_id") or "default",
                "lifecycle": surface.get("lifecycle") or "active",
                "phase": surface.get("phase"),
                "updated_at": surface.get("updated_at") or summary.get("updated_at"),
                "risk": risk,
                "delta": {
                    "has_baseline": delta.get("has_baseline"),
                    "fixed": len(delta.get("fixed") or []),
                    "new": len(delta.get("new") or []),
                    "still_open": len(delta.get("still_open") or []),
                    "ports_opened": len((delta.get("surface") or {}).get("ports_opened") or []),
                },
                "risk_history": hist,
                "next_schedule": next_jobs[0] if next_jobs else None,
                "findings_confirmed": summary.get("findings_confirmed", 0),
            }
        )

    rows.sort(key=lambda r: float((r.get("risk") or {}).get("score") or 0), reverse=True)
    return {
        "active_client_id": get_active_client_id(),
        "filter_client_id": cid,
        "session_id": sid,
        "clients": [
            {
                "client_id": c.get("client_id"),
                "display_name": c.get("display_name"),
                "targets_count": c.get("targets_count"),
            }
            for c in clients
        ],
        "engagements": rows,
        "schedules_count": len(
            [j for j in jobs if normalize_target(str(j.get("target") or "")) in session_targets]
        ),
    }
