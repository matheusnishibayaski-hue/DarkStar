"""Webhook genérico (Slack/Teams/Discord/custom) para alertas de recorrência."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any

from backend.config import ALERT_ON_CRITICAL, ALERT_RISK_JUMP, ALERT_WEBHOOK_URL
from backend.security.audit import record_event
from backend.security.http_client import http_urlopen

logger = logging.getLogger(__name__)


def send_webhook(text: str, *, payload: dict[str, Any] | None = None) -> bool:
    url = ALERT_WEBHOOK_URL
    if not url:
        return False
    body: dict[str, Any] = {"text": text}
    if payload:
        body["payload"] = payload
    # Compat Slack incoming webhook
    body.setdefault("content", text)
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with http_urlopen(req, timeout=8) as resp:
            ok = 200 <= getattr(resp, "status", 200) < 300
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        logger.warning("alert_webhook_failed: %s", exc)
        record_event("alert_webhook_failed", {"error": str(exc)[:200]})
        return False
    record_event("alert_webhook_sent", {"ok": ok, "preview": text[:160]})
    return ok


def maybe_alert_delta(
    target: str,
    *,
    delta: dict[str, Any],
    risk: dict[str, Any],
    previous_score: float | None = None,
) -> list[str]:
    """Dispara alertas se houver críticos novos, portas sensíveis ou salto de risco."""
    messages: list[str] = []
    new_findings = delta.get("new") or []
    critical_new = [
        f for f in new_findings if str(f.get("severity") or "").lower() in {"critical", "high"}
    ]
    surf = delta.get("surface") or {}
    ports_opened = surf.get("ports_opened") or []
    sensitive = []
    for p in ports_opened:
        port = str(p.get("port") if isinstance(p, dict) else p)
        if port in {"22", "23", "3389", "445", "3306", "5432", "6379", "27017", "9200"}:
            sensitive.append(p)

    if ALERT_ON_CRITICAL and critical_new:
        titles = ", ".join(
            str(f.get("title") or f.get("key") or "?")[:60] for f in critical_new[:5]
        )
        messages.append(
            f"[DarkStar] {target}: {len(critical_new)} achado(s) critical/high novo(s): {titles}"
        )
    if sensitive:
        messages.append(
            f"[DarkStar] {target}: porta(s) sensível(is) aberta(s): "
            + ", ".join(f"{p.get('port') if isinstance(p, dict) else p}" for p in sensitive[:8])
        )
    score = float(risk.get("score") or 0)
    if previous_score is not None and (score - previous_score) >= ALERT_RISK_JUMP:
        messages.append(
            f"[DarkStar] {target}: risco subiu de {previous_score:.0f} → {score:.0f} "
            f"(+{score - previous_score:.0f})"
        )

    for msg in messages:
        send_webhook(
            msg,
            payload={
                "target": target,
                "risk": risk,
                "delta_counts": {
                    "new": len(new_findings),
                    "fixed": len(delta.get("fixed") or []),
                    "ports_opened": len(ports_opened),
                },
            },
        )
        try:
            from backend.integrations.notifications import notification_manager

            sev = "critical" if critical_new else "high"
            notification_manager.notify(
                title=f"DarkStar alert — {target}",
                message=msg,
                severity=sev,
            )
        except Exception:  # noqa: BLE001
            pass
    return messages
