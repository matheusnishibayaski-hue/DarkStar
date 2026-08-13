"""Testes de observabilidade: request ID, logs JSON e métricas."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from tests.auth_patch import patch_chat_api_token


class TestObservability(unittest.TestCase):
    def test_request_id_generated_and_returned(self):
        from backend.main import app

        client = TestClient(app)
        response = client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.headers.get("X-Request-ID"))
        self.assertGreaterEqual(len(response.headers["X-Request-ID"]), 8)

    def test_request_id_propagated_from_header(self):
        from backend.main import app

        client = TestClient(app)
        response = client.get("/api/health", headers={"X-Request-ID": "abc123fixedid"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("X-Request-ID"), "abc123fixedid")

    def test_metrics_endpoint_returns_counters(self):
        from backend.main import app
        from backend.observability import incr

        incr("requests_total", 0)
        client = TestClient(app)
        response = client.get("/api/metrics")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("requests_total", data)
        self.assertIn("tool_executions_total", data)
        self.assertIn("errors_total", data)

    def test_metrics_requires_auth_when_token_set(self):
        from backend.main import app

        with patch_chat_api_token("secret-token"):
            client = TestClient(app)
            denied = client.get("/api/metrics")
            self.assertEqual(denied.status_code, 401)
            ok = client.get("/api/metrics", headers={"X-Chat-Token": "secret-token"})
            self.assertEqual(ok.status_code, 200)

    def test_json_log_formatter_includes_ids(self):
        from backend.observability import (
            JsonFormatter,
            get_logger,
            set_correlation_id,
            set_request_id,
        )

        set_request_id("req-1")
        set_correlation_id("corr-1")
        logger = get_logger()
        record = logger.makeRecord(
            logger.name, 20, "test", 1, "hello OPENROUTER_API_KEY=secret", (), None
        )
        line = JsonFormatter().format(record)
        payload = json.loads(line)
        self.assertEqual(payload["request_id"], "req-1")
        self.assertEqual(payload["correlation_id"], "corr-1")
        self.assertIn("***", payload["message"])
        self.assertNotIn("secret", payload["message"])

    def test_timed_records_duration(self):
        from backend.observability import timed

        with patch("backend.observability.log_event") as log_mock:
            with timed("unit_op", tool="nmap"):
                pass
            self.assertTrue(log_mock.called)
            args, kwargs = log_mock.call_args
            self.assertEqual(args[0], "INFO")
            self.assertIn("duration_ms", kwargs)


class TestImportRegression(unittest.TestCase):
    """Garante que imports críticos do orquestrador existam (bugs P0)."""

    def test_agent_imports_stream_hub(self):
        import backend.ai.agent as agent

        self.assertTrue(hasattr(agent, "get_stream_hub"))
        self.assertTrue(callable(agent.get_stream_hub))

    def test_autopilot_imports_recon_and_model_helpers(self):
        import backend.ai.autopilot as autopilot

        self.assertTrue(hasattr(autopilot, "normalize_target"))
        self.assertTrue(hasattr(autopilot, "build_recon_context"))
        self.assertTrue(hasattr(autopilot, "get_llm_provider"))
        self.assertEqual(autopilot.normalize_target("Example.COM"), "example.com")


class TestKaliFinalize(unittest.TestCase):
    def test_blocked_command_finalizes_without_docker(self):
        from backend.executor import kali as kali_mod
        from backend.executor.stream_hub import get_stream_hub

        hub = get_stream_hub()
        exec_id = "blocktest1"
        hub.create(exec_id, "rm -rf /")

        events = list(
            kali_mod.execute_kali_command_stream(
                ["rm", "-rf", "/"],
                reason="should block",
                execution_id=exec_id,
            )
        )
        done = [e for e in events if e.get("type") == "done"]
        self.assertEqual(len(done), 1)
        result = done[0]["result"]
        self.assertTrue(result.blocked)
        self.assertFalse(result.success)
        stream = hub.get(exec_id)
        self.assertTrue(stream is None or stream.finished)

    def test_path_traversal_blocked(self):
        from backend.executor import kali as kali_mod

        events = list(
            kali_mod.execute_kali_command_stream(
                ["nmap", "-oA", "../etc/passwd", "scanme.nmap.org"],
                reason="path traversal",
                execution_id="travtest1",
            )
        )
        done = [e for e in events if e.get("type") == "done"]
        self.assertEqual(len(done), 1)
        self.assertTrue(done[0]["result"].blocked)


if __name__ == "__main__":
    unittest.main()
