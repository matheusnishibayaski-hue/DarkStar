"""Rotas de notificações multicanal."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.integrations.notifications import notification_manager

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


class SendNotificationRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=300)
    message: str = Field(..., min_length=1, max_length=8000)
    severity: str = Field(default="info", max_length=16)
    channels: list[str] | None = None


class AlertFindingRequest(BaseModel):
    finding: dict[str, Any]
    channels: list[str] | None = None


@router.get("/channels")
def get_channels():
    configured = notification_manager.get_configured_channels()
    return {
        "status": "ok",
        "configured_channels": configured,
        "channel_count": len(configured),
        "available_channels": list(notification_manager.channels.keys()),
    }


@router.post("/send")
def send_notification(req: SendNotificationRequest):
    sev = (req.severity or "info").lower()
    if sev not in {"critical", "high", "medium", "low", "info"}:
        raise HTTPException(status_code=400, detail=f"Invalid severity: {sev}")
    # Explicit channels bypass auto severity gate
    channels = req.channels
    if channels is None and sev not in {"critical", "high"}:
        # For medium/low/info require explicit channel list
        raise HTTPException(
            status_code=400,
            detail="For medium/low/info severity, pass channels explicitly",
        )
    results = notification_manager.notify(
        title=req.title,
        message=req.message,
        severity=sev,
        channels=channels,
    )
    success = any(results.values()) if results else False
    return {
        "status": "success" if success else "partial",
        "results": results,
        "channels_sent": sum(1 for v in results.values() if v),
        "channels_failed": sum(1 for v in results.values() if not v),
    }


@router.post("/test/{channel}")
def test_channel(channel: str):
    if channel not in notification_manager.channels:
        raise HTTPException(status_code=404, detail=f"Unknown channel: {channel}")
    notifier = notification_manager.channels[channel]
    if not notifier.is_configured():
        raise HTTPException(status_code=400, detail=f"Channel not configured: {channel}")
    ok = notifier.send(
        title="DarkStar Test Notification",
        message="Test message to verify this notification channel.",
        severity="info",
    )
    return {
        "status": "success" if ok else "failed",
        "channel": channel,
        "message": "Test notification sent" if ok else "Test notification failed",
    }


@router.post("/alert-finding")
def alert_finding(req: AlertFindingRequest):
    results = notification_manager.alert_finding(req.finding, channels=req.channels)
    return {
        "status": "sent",
        "finding": (req.finding or {}).get("title"),
        "results": results,
    }
