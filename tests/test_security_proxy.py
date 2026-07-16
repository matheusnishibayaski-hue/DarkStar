"""Testes de trust proxy, client_ip na auditoria e files traversal."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient


class TestClientIpTrust(unittest.TestCase):
    def test_ignores_x_forwarded_for_by_default(self):
        from backend.deps import client_ip

        request = MagicMock()
        request.headers = {"X-Forwarded-For": "1.2.3.4"}
        request.client.host = "127.0.0.1"
        with patch("backend.deps.TRUST_PROXY", False):
            self.assertEqual(client_ip(request), "127.0.0.1")

    def test_honors_x_forwarded_for_when_trust_proxy(self):
        from backend.deps import client_ip

        request = MagicMock()
        request.headers = {"X-Forwarded-For": "9.9.9.9, 10.0.0.1"}
        request.client.host = "127.0.0.1"
        with patch("backend.deps.TRUST_PROXY", True):
            self.assertEqual(client_ip(request), "9.9.9.9")


class TestAuditClientIp(unittest.TestCase):
    def test_blocked_execution_records_client_ip(self):
        from backend.executor import kali as kali_mod
        from backend.observability import set_client_ip

        set_client_ip("203.0.113.10")
        with patch.object(kali_mod, "record_tool_execution") as record_mock:
            list(
                kali_mod.execute_kali_command_stream(
                    ["not-a-real-tool", "x"],
                    reason="audit ip",
                    execution_id="audip1",
                )
            )
        self.assertTrue(record_mock.called)
        kwargs = record_mock.call_args.kwargs
        self.assertEqual(kwargs.get("client_ip"), "203.0.113.10")


class TestFilesStoreTraversal(unittest.TestCase):
    def test_resolve_rejects_traversal_and_absolute(self):
        from backend.executor import files_store as fs

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ok.txt").write_text("x", encoding="utf-8")
            with patch.object(fs, "OUTPUTS_DIR", root):
                self.assertIsNone(fs.resolve_output_file("../ok.txt"))
                self.assertIsNone(fs.resolve_output_file("/etc/passwd"))
                self.assertIsNone(fs.resolve_output_file("..\\ok.txt"))
                self.assertIsNotNone(fs.resolve_output_file("ok.txt"))


class TestOpenApiMetrics(unittest.TestCase):
    def test_metrics_route_in_openapi(self):
        from backend.main import app

        client = TestClient(app)
        paths = client.get("/openapi.json").json()["paths"]
        self.assertIn("/api/metrics", paths)


class TestOpenRouterCommon(unittest.TestCase):
    def test_retryable_and_error_messages(self):
        from backend.ai.openrouter_common import is_retryable_error, openrouter_error_message

        self.assertTrue(is_retryable_error("HTTP 429 rate limit"))
        self.assertIn("OpenRouter", openrouter_error_message("401 invalid key"))
        self.assertIn("Cota", openrouter_error_message("429 overloaded"))


if __name__ == "__main__":
    unittest.main()
