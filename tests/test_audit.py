"""Testes da trilha de auditoria."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from tests.auth_patch import patch_chat_api_token


class TestAudit(unittest.TestCase):
    def setUp(self):
        from backend.main import app

        self.client = TestClient(app)

    def test_record_and_list_events(self):
        import backend.config as cfg
        import backend.security.audit as audit_mod

        with tempfile.TemporaryDirectory() as tmp:
            audit_dir = Path(tmp)
            with (
                patch.object(cfg, "AUDIT_DIR", audit_dir),
                patch.object(audit_mod, "AUDIT_DIR", audit_dir),
            ):
                audit_mod.record_tool_execution(
                    command="nmap -sV scanme.nmap.org",
                    tool="nmap",
                    targets=["scanme.nmap.org"],
                    success=True,
                    exit_code=0,
                    log_file_id="abc123",
                )
                events = audit_mod.list_events(limit=10)
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]["event"], "tool_execution")
                self.assertEqual(events[0]["tool"], "nmap")

    def test_redacts_secrets(self):
        import backend.config as cfg
        import backend.security.audit as audit_mod

        with tempfile.TemporaryDirectory() as tmp:
            audit_dir = Path(tmp)
            with (
                patch.object(cfg, "AUDIT_DIR", audit_dir),
                patch.object(audit_mod, "AUDIT_DIR", audit_dir),
            ):
                audit_mod.record_event(
                    "test",
                    {
                        "command": "curl -H Authorization: Bearer sk-secret1234567890abcdef",
                    },
                )
                path = next(audit_dir.glob("events-*.jsonl"))
                raw = path.read_text(encoding="utf-8")
                self.assertNotIn("sk-secret", raw)

    def test_audit_api(self):
        import backend.config as cfg
        import backend.security.audit as audit_mod

        with tempfile.TemporaryDirectory() as tmp:
            audit_dir = Path(tmp)
            with (
                patch.object(cfg, "AUDIT_DIR", audit_dir),
                patch.object(audit_mod, "AUDIT_DIR", audit_dir),
            ):
                audit_mod.record_tool_execution(
                    command="whois example.com",
                    tool="whois",
                    targets=["example.com"],
                    success=True,
                )
                res = self.client.get("/api/audit?limit=5")
                self.assertEqual(res.status_code, 200)
                self.assertGreaterEqual(len(res.json()["events"]), 1)

    def test_audit_api_requires_auth_when_token_set(self):
        from backend.main import app

        with patch_chat_api_token("audit-secret"):
            client = TestClient(app)
            res = client.get("/api/audit")
            self.assertEqual(res.status_code, 401)
