"""Alertas locais (webhook) para recorrência MSSP."""

from backend.alerts.webhook import maybe_alert_delta, send_webhook

__all__ = ["maybe_alert_delta", "send_webhook"]
