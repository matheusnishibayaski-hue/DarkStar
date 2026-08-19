"""Carteira: alvos da conversa mesmo sem arquivo de surface."""

from __future__ import annotations

import unittest
from unittest.mock import patch


class TestPortfolioSessionScope(unittest.TestCase):
    def test_rows_from_session_findings_without_surface(self):
        from backend.routes import portfolio as port

        findings = [
            {
                "id": "1",
                "title": "Missing HSTS",
                "severity": "medium",
                "status": "confirmed",
                "surface_target": "shop.test",
            },
            {
                "id": "2",
                "title": "80/tcp open",
                "severity": "info",
                "status": "candidate",
                "host": "shop.test",
            },
        ]
        with (
            patch.object(port, "sync_session_intel_from_logs"),
            patch.object(
                port,
                "load_session",
                return_value={"session_id": "sess-abc12345", "targets": ["shop.test"]},
            ),
            patch.object(port, "aggregate_session_findings", return_value=findings),
            patch.object(port, "list_surface_summaries", return_value=[]),
            patch.object(port, "load_surface", return_value={}),
            patch.object(port, "list_clients", return_value=[]),
            patch.object(port, "list_jobs", return_value=[]),
            patch.object(port, "load_risk_history", return_value=[]),
            patch.object(port, "get_active_client_id", return_value="default"),
        ):
            out = port.api_portfolio(session_id="sess-abc12345", client_id=None)

        rows = out["engagements"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["target"], "shop.test")
        self.assertEqual(rows[0]["findings_confirmed"], 1)
        self.assertEqual(rows[0]["findings_pending"], 1)
        self.assertGreater(rows[0]["risk"]["score"], 0)

    def test_empty_session_has_no_rows(self):
        from backend.routes import portfolio as port

        with (
            patch.object(port, "sync_session_intel_from_logs"),
            patch.object(port, "load_session", return_value={"targets": []}),
            patch.object(port, "aggregate_session_findings", return_value=[]),
            patch.object(port, "list_surface_summaries", return_value=[]),
            patch.object(port, "load_surface", return_value={}),
            patch.object(port, "list_clients", return_value=[]),
            patch.object(port, "list_jobs", return_value=[]),
            patch.object(port, "get_active_client_id", return_value="default"),
        ):
            out = port.api_portfolio(session_id="sess-empty99", client_id=None)

        self.assertEqual(out["engagements"], [])

    def test_findings_without_hostname_still_listed(self):
        from backend.routes import portfolio as port

        findings = [
            {
                "id": "x",
                "title": "Banner HTTP",
                "severity": "info",
                "status": "candidate",
            }
        ]
        with (
            patch.object(port, "sync_session_intel_from_logs"),
            patch.object(port, "load_session", return_value={"targets": []}),
            patch.object(port, "aggregate_session_findings", return_value=findings),
            patch.object(port, "list_surface_summaries", return_value=[]),
            patch.object(port, "load_surface", return_value={}),
            patch.object(port, "list_clients", return_value=[]),
            patch.object(port, "list_jobs", return_value=[]),
            patch.object(port, "load_risk_history", return_value=[]),
            patch.object(port, "get_active_client_id", return_value="default"),
        ):
            out = port.api_portfolio(session_id="sess-nohost01", client_id=None)

        self.assertEqual(len(out["engagements"]), 1)
        self.assertIn("chat", out["engagements"][0]["target"].lower())
        self.assertNotEqual(out["engagements"][0]["host"], "unknown")
        self.assertEqual(out["engagements"][0]["findings_pending"], 1)

    def test_junk_code_hosts_filtered(self):
        from backend.routes import portfolio as port

        with (
            patch.object(port, "sync_session_intel_from_logs"),
            patch.object(
                port,
                "load_session",
                return_value={
                    "targets": [
                        "shop.lab.test",
                        "env.production",
                        "process.cwd",
                        "basepath.endswith",
                    ]
                },
            ),
            patch.object(port, "aggregate_session_findings", return_value=[]),
            patch.object(port, "list_surface_summaries", return_value=[]),
            patch.object(port, "load_surface", return_value={}),
            patch.object(port, "list_clients", return_value=[]),
            patch.object(port, "list_jobs", return_value=[]),
            patch.object(port, "load_risk_history", return_value=[]),
            patch.object(port, "get_active_client_id", return_value="default"),
        ):
            out = port.api_portfolio(session_id="sess-junk01", client_id=None)

        hosts = [r["host"] for r in out["engagements"]]
        self.assertEqual(hosts, ["shop.lab.test"])
