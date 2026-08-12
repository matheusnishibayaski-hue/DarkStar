"""Testes de notificações multicanal (sem rede)."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from backend.integrations.notifications import (
    NotificationManager,
    SlackNotifier,
    notification_manager,
)
from fastapi.testclient import TestClient

from tests.auth_patch import patch_chat_api_token


class TestNotificationManager(unittest.TestCase):
    def test_no_channels_for_low_without_list(self):
        mgr = NotificationManager()
        with patch.object(mgr, "get_configured_channels", return_value=["slack"]):
            results = mgr.notify("t", "m", severity="low")
            self.assertEqual(results, {})

    def test_critical_uses_configured(self):
        mgr = NotificationManager()
        fake = MagicMock()
        fake.is_configured.return_value = True
        fake.send.return_value = True
        mgr.channels = {"slack": fake}
        results = mgr.notify("Critical alert", "body", severity="critical")
        self.assertTrue(results.get("slack"))
        fake.send.assert_called_once()

    def test_slack_not_configured(self):
        with (
            patch("backend.integrations.notifications.SLACK_WEBHOOK_URL", ""),
            patch("backend.integrations.notifications.ALERT_WEBHOOK_URL", ""),
        ):
            n = SlackNotifier()
            self.assertFalse(n.is_configured())


class TestNotificationRoutes(unittest.TestCase):
    def test_channels_and_send_gate(self):
        with patch_chat_api_token(""):
            from backend.main import app

            client = TestClient(app)
            r = client.get("/api/notifications/channels")
            self.assertEqual(r.status_code, 200)
            body = r.json()
            self.assertIn("available_channels", body)
            r2 = client.post(
                "/api/notifications/send",
                json={"title": "x", "message": "y", "severity": "low"},
            )
            self.assertEqual(r2.status_code, 400)

    def test_send_with_explicit_channel_mocked(self):
        fake = MagicMock()
        fake.is_configured.return_value = True
        fake.send.return_value = True
        with (
            patch_chat_api_token(""),
            patch.dict(notification_manager.channels, {"slack": fake}, clear=False),
        ):
            from backend.main import app

            client = TestClient(app)
            r = client.post(
                "/api/notifications/send",
                json={
                    "title": "Test",
                    "message": "Hello",
                    "severity": "info",
                    "channels": ["slack"],
                },
            )
            self.assertEqual(r.status_code, 200)
            self.assertTrue(r.json()["results"].get("slack"))


if __name__ == "__main__":
    unittest.main()
