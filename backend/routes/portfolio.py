"""Carteira de engajamentos — filtrada pela conversa ativa."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from backend.ai.delta import compute_delta
from backend.ai.risk_history import load_risk_history
from backend.ai.risk_score import compute_risk_score, risk_score_for_target
from backend.clients.runtime import get_active_client_id
from backend.clients.store import list_clients
from backend.executor.recon_db import normalize_target
from backend.executor.session_intel import (
    aggregate_session_findings,
    load_session,
    sync_session_intel_from_logs,
)
from backend.executor.surface import list_surface_summaries, load_surface
from backend.schedule.store import list_jobs

router = APIRouter(prefix="/api", tags=["portfolio"])

_LIFECYCLE_PT = {
    "active": "ativo",
    "paused": "pausado",
    "closed": "encerrado",
    "archived": "arquivado",
}


def _host(value: str) -> str:
    raw = str(value or "").strip()
    if not raw or raw in {"_session", "-", "—"}:
        return ""
    h = normalize_target(raw)
    if not h or h in {"unknown", "_session"}:
        return ""
    return h


def _status_counts(items: list[dict]) -> dict[str, int]:
    confirmed = pending = fp = discarded = 0
    for f in items:
        st = str(f.get("status") or "candidate")
        if st == "confirmed":
            confirmed += 1
        elif st == "false_positive":
            fp += 1
        elif st == "discarded":
            discarded += 1
        else:
            pending += 1
    return {
        "confirmed": confirmed,
        "pending": pending,
        "false_positive": fp,
        "discarded": discarded,
        "total": len(items),
    }


def _collect_hosts(session_data: dict, findings: list[dict]) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    for t in session_data.get("targets") or []:
        h = _host(str(t))
        if h and h not in seen and h != "_session":
            seen.add(h)
            hosts.append(h)
    for f in findings:
        h = _host(str(f.get("surface_target") or f.get("host") or ""))
        if h and h not in seen and h != "_session":
            seen.add(h)
            hosts.append(h)
    return hosts


def _findings_for_host(findings: list[dict], host: str) -> list[dict]:
    out: list[dict] = []
    for f in findings:
        h = _host(str(f.get("surface_target") or f.get("host") or ""))
        if h == host or (not h and host == "_session"):
            out.append(f)
    return out


def _delta_payload(target: str) -> dict:
    try:
        delta = compute_delta(target)
    except Exception:  # noqa: BLE001
        delta = {"has_baseline": False}
    return {
        "has_baseline": bool(delta.get("has_baseline")),
        "fixed": len(delta.get("fixed") or []),
        "new": len(delta.get("new") or []),
        "still_open": len(delta.get("still_open") or []),
        "ports_opened": len((delta.get("surface") or {}).get("ports_opened") or []),
    }


def _risk_payload(target: str, host_findings: list[dict]) -> dict:
    try:
        risk = risk_score_for_target(target)
        if (risk.get("count") or 0) > 0 or (risk.get("score") or 0) > 0:
            return risk
    except Exception:  # noqa: BLE001
        pass
    confirmed = [f for f in host_findings if f.get("status") == "confirmed"]
    return compute_risk_score(confirmed)


@router.get("/portfolio")
def api_portfolio(
    session_id: str = Query(..., min_length=1, max_length=128),
    client_id: str | None = Query(default=None, max_length=64),
):
    """Carteira: alvos e achados da conversa (não exige arquivo de surface)."""
    sid = (session_id or "").strip()
    if not sid:
        raise HTTPException(
            status_code=400,
            detail="session_id required (portfolio is scoped per conversation)",
        )

    try:
        sync_session_intel_from_logs(sid)
    except Exception:  # noqa: BLE001
        pass

    session_data = load_session(sid) or {}
    try:
        findings = aggregate_session_findings(sid, sync=False) or []
    except Exception:  # noqa: BLE001
        findings = [f for f in (session_data.get("session_findings") or []) if isinstance(f, dict)]

    cid = (client_id or "").strip() or None
    clients = list_clients()
    if cid:
        clients = [c for c in clients if c.get("client_id") == cid]

    jobs = list_jobs(client_id=cid)
    jobs_by_target: dict[str, list] = {}
    for j in jobs:
        jobs_by_target.setdefault(_host(str(j.get("target") or "")), []).append(j)

    summaries = { _host(str(s.get("target") or "")): s for s in list_surface_summaries(client_id=cid) }
    hosts = _collect_hosts(session_data, findings)
    if not hosts and any(isinstance(f, dict) for f in findings):
        hosts = ["_session"]

    rows = []
    for host in hosts:
        summary = summaries.get(host) or {}
        surface = load_surface(host) or {} if host != "_session" else {}
        host_findings = _findings_for_host(findings, host)
        counts = _status_counts(host_findings)
        risk = _risk_payload(host, host_findings)
        delta = _delta_payload(host) if host != "_session" else {
            "has_baseline": False,
            "fixed": 0,
            "new": 0,
            "still_open": 0,
            "ports_opened": 0,
        }
        hist = load_risk_history(host, limit=12) if host != "_session" else []
        next_jobs = sorted(
            jobs_by_target.get(host) or [],
            key=lambda x: str(x.get("next_run_at") or ""),
        )
        lifecycle = surface.get("lifecycle") or summary.get("lifecycle") or "active"
        display = host if host != "_session" else "Achados do chat (sem hostname)"
        rows.append(
            {
                "target": display,
                "host": host,
                "client": surface.get("client") or summary.get("client") or "",
                "client_id": surface.get("client_id") or summary.get("client_id") or "default",
                "lifecycle": lifecycle,
                "lifecycle_label": _LIFECYCLE_PT.get(str(lifecycle).lower(), str(lifecycle)),
                "phase": surface.get("phase"),
                "updated_at": surface.get("updated_at") or summary.get("updated_at") or session_data.get("updated_at"),
                "risk": risk,
                "delta": delta,
                "risk_history": hist,
                "next_schedule": next_jobs[0] if next_jobs else None,
                "findings_confirmed": counts["confirmed"],
                "findings_pending": counts["pending"],
                "findings_fp": counts["false_positive"],
                "findings_total": counts["total"],
            }
        )

    rows.sort(key=lambda r: float((r.get("risk") or {}).get("score") or 0), reverse=True)
    session_hosts = {_host(str(t)) for t in (session_data.get("targets") or [])}
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
            [j for j in jobs if _host(str(j.get("target") or "")) in session_hosts]
        ),
    }
