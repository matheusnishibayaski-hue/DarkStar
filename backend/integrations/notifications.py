"""Notificações multicanal sync — Slack, Discord, Telegram, Email, Jira."""

from __future__ import annotations

import base64
import json
import logging
import smtplib
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from backend.config import (
    ALERT_WEBHOOK_URL,
    DISCORD_WEBHOOK_URL,
    EMAIL_FROM,
    EMAIL_TO,
    JIRA_PROJECT,
    JIRA_TOKEN,
    JIRA_URL,
    JIRA_USER,
    SLACK_CHANNEL,
    SLACK_WEBHOOK_URL,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_SERVER,
    SMTP_USER,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
)
from backend.security.audit import record_event
from backend.security.http_client import http_urlopen

logger = logging.getLogger(__name__)

_SEVERITY_AUTO = frozenset({"critical", "high"})


class NotificationChannel(ABC):
    @abstractmethod
    def send(self, title: str, message: str, severity: str = "info") -> bool:
        raise NotImplementedError

    @abstractmethod
    def is_configured(self) -> bool:
        raise NotImplementedError


def _post_json(url: str, payload: dict[str, Any], *, timeout: float = 8) -> tuple[bool, int]:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with http_urlopen(req, timeout=timeout) as resp:
            code = getattr(resp, "status", 200)
            return 200 <= code < 300 or code == 204, int(code)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        logger.warning("notification_http_failed: %s", exc)
        return False, 0


class SlackNotifier(NotificationChannel):
    def __init__(self) -> None:
        self.webhook_url = SLACK_WEBHOOK_URL or ALERT_WEBHOOK_URL
        self.channel = SLACK_CHANNEL or "#security"

    def is_configured(self) -> bool:
        return bool(self.webhook_url)

    def send(self, title: str, message: str, severity: str = "info") -> bool:
        if not self.is_configured():
            return False
        colors = {
            "critical": "#FF0000",
            "high": "#FF6600",
            "medium": "#FFCC00",
            "low": "#00CC00",
            "info": "#0099FF",
        }
        payload = {
            "channel": self.channel,
            "text": f"{title}\n{message}",
            "attachments": [
                {
                    "color": colors.get(severity, "#808080"),
                    "title": title,
                    "text": message[:3500],
                    "ts": int(datetime.now(timezone.utc).timestamp()),
                }
            ],
        }
        ok, _ = _post_json(self.webhook_url, payload)
        return ok


class DiscordNotifier(NotificationChannel):
    def __init__(self) -> None:
        self.webhook_url = DISCORD_WEBHOOK_URL

    def is_configured(self) -> bool:
        return bool(self.webhook_url)

    def send(self, title: str, message: str, severity: str = "info") -> bool:
        if not self.is_configured():
            return False
        colors = {
            "critical": 0xFF0000,
            "high": 0xFF6600,
            "medium": 0xFFCC00,
            "low": 0x00CC00,
            "info": 0x0099FF,
        }
        payload = {
            "embeds": [
                {
                    "title": title[:250],
                    "description": message[:4000],
                    "color": colors.get(severity, 0x808080),
                    "footer": {"text": "DarkStar Security"},
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ]
        }
        ok, code = _post_json(self.webhook_url, payload)
        return ok or code == 204


class TelegramNotifier(NotificationChannel):
    def __init__(self) -> None:
        self.bot_token = TELEGRAM_BOT_TOKEN
        self.chat_id = TELEGRAM_CHAT_ID

    def is_configured(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    def send(self, title: str, message: str, severity: str = "info") -> bool:
        if not self.is_configured():
            return False
        emoji = {"critical": "!", "high": "!", "medium": "*", "low": "-", "info": "-"}.get(
            severity, "-"
        )
        text = f"{emoji} {title}\n\n{message}"[:4000]
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        ok, _ = _post_json(url, {"chat_id": self.chat_id, "text": text})
        return ok


class EmailNotifier(NotificationChannel):
    def __init__(self) -> None:
        self.smtp_server = SMTP_SERVER
        self.smtp_port = SMTP_PORT
        self.smtp_user = SMTP_USER
        self.smtp_pass = SMTP_PASSWORD
        self.from_email = EMAIL_FROM
        self.to_email = EMAIL_TO

    def is_configured(self) -> bool:
        return all(
            [self.smtp_server, self.smtp_user, self.smtp_pass, self.from_email, self.to_email]
        )

    def send(self, title: str, message: str, severity: str = "info") -> bool:
        if not self.is_configured():
            return False
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[DarkStar] {title}"[:200]
            msg["From"] = self.from_email
            msg["To"] = self.to_email
            body = f"<h2>{title}</h2><p>Severity: {severity}</p><pre>{message}</pre>"
            msg.attach(MIMEText(body, "html", "utf-8"))
            with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=15) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_pass)
                recipients = [x.strip() for x in self.to_email.split(",") if x.strip()]
                server.sendmail(self.from_email, recipients, msg.as_string())
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("email_notify_failed: %s", exc)
            return False


class JiraNotifier(NotificationChannel):
    def __init__(self) -> None:
        self.url = (JIRA_URL or "").rstrip("/")
        self.user = JIRA_USER
        self.token = JIRA_TOKEN
        self.project = JIRA_PROJECT or "SEC"

    def is_configured(self) -> bool:
        return bool(self.url and self.user and self.token)

    def send(self, title: str, message: str, severity: str = "info") -> bool:
        if not self.is_configured():
            return False
        priority = {
            "critical": "Highest",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Low",
        }.get(severity, "Medium")
        payload = {
            "fields": {
                "project": {"key": self.project},
                "summary": title[:250],
                "description": message[:8000],
                "issuetype": {"name": "Bug"},
                "priority": {"name": priority},
                "labels": ["security", "darkstar", severity],
            }
        }
        auth = base64.b64encode(f"{self.user}:{self.token}".encode()).decode()
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.url}/rest/api/2/issue",
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Basic {auth}",
            },
            method="POST",
        )
        try:
            with http_urlopen(req, timeout=15) as resp:
                return 200 <= getattr(resp, "status", 200) < 300
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            logger.warning("jira_notify_failed: %s", exc)
            return False


class NotificationManager:
    def __init__(self) -> None:
        self.channels: dict[str, NotificationChannel] = {
            "slack": SlackNotifier(),
            "discord": DiscordNotifier(),
            "telegram": TelegramNotifier(),
            "email": EmailNotifier(),
            "jira": JiraNotifier(),
        }

    def get_configured_channels(self) -> list[str]:
        return [name for name, ch in self.channels.items() if ch.is_configured()]

    def notify(
        self,
        title: str,
        message: str,
        severity: str = "info",
        channels: list[str] | None = None,
    ) -> dict[str, bool]:
        sev = (severity or "info").lower()
        if channels is None:
            if sev not in _SEVERITY_AUTO:
                return {}
            channels = self.get_configured_channels()

        results: dict[str, bool] = {}
        for name in channels:
            ch = self.channels.get(name)
            if not ch or not ch.is_configured():
                results[name] = False
                continue
            try:
                results[name] = bool(ch.send(title, message, sev))
            except Exception as exc:  # noqa: BLE001
                logger.warning("notify_%s_failed: %s", name, exc)
                results[name] = False
        record_event(
            "notification_sent",
            {
                "title": title[:120],
                "severity": sev,
                "ok": sum(1 for v in results.values() if v),
                "channels": list(results.keys()),
            },
        )
        return results

    def alert_finding(
        self,
        finding: dict[str, Any],
        *,
        channels: list[str] | None = None,
    ) -> dict[str, bool]:
        sev = str(finding.get("severity") or "info").lower()
        title = f"{sev.upper()}: {finding.get('title') or 'Security issue'}"
        message = (
            f"Target: {finding.get('target') or 'N/A'}\n"
            f"Tool: {finding.get('tool') or 'N/A'}\n"
            f"Evidence: {str(finding.get('evidence') or '')[:800]}\n"
            f"Remediation: {finding.get('remediation') or 'N/A'}"
        )
        return self.notify(title, message, severity=sev, channels=channels)


notification_manager = NotificationManager()
