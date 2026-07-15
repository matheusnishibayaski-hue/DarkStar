"""Testes SSE dos endpoints de streaming (agente mockado)."""

import json
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.ai.sse import format_sse


def _parse_sse_events(body: str) -> list[tuple[str, dict]]:
    events: list[tuple[str, dict]] = []
    for block in body.split("\n\n"):
        block = block.strip()
        if not block:
            continue
        event = "message"
        data_str = ""
        for line in block.split("\n"):
            if line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:"):
                data_str = line[5:].strip()
        if data_str:
            events.append((event, json.loads(data_str)))
    return events


class TestChatStreamSse(unittest.TestCase):
    def setUp(self):
        from backend.main import app
        from backend.security.rate_limit import get_rate_limiter
        from backend.config import RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SEC

        get_rate_limiter(RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SEC).reset()
        self.client = TestClient(app)

    def test_chat_stream_emits_tool_and_done(self):
        def mock_chat_stream(*_args, **_kwargs):
            yield format_sse("tool_start", {
                "execution_id": "exec-test-1",
                "command": "nmap -sV scanme.nmap.org",
            })
            yield format_sse("tool_done", {"execution_id": "exec-test-1"})
            yield format_sse("done", {
                "message": "Scan concluído.",
                "tool_executions": [{
                    "command": "nmap -sV scanme.nmap.org",
                    "reason": "scan",
                    "stdout": "80/tcp open http",
                    "stderr": "",
                    "exit_code": 0,
                    "success": True,
                    "blocked": False,
                    "log_file_id": "exec-test-1",
                    "tool": "nmap",
                }],
            })

        with patch("backend.routes.chat.chat_stream", mock_chat_stream):
            res = self.client.post(
                "/api/chat/stream",
                json={"message": "scan scanme.nmap.org", "history": []},
            )

        self.assertEqual(res.status_code, 200)
        self.assertIn("text/event-stream", res.headers.get("content-type", ""))

        events = _parse_sse_events(res.text)
        types = [e[0] for e in events]
        self.assertIn("tool_start", types)
        self.assertIn("tool_done", types)
        self.assertIn("done", types)

        done = next(data for ev, data in events if ev == "done")
        self.assertEqual(done["message"], "Scan concluído.")
        self.assertEqual(len(done["tool_executions"]), 1)

    def test_chat_stream_cancelled_stopped_reason(self):
        def mock_chat_stream(*_args, **_kwargs):
            yield format_sse("done", {
                "message": "Operação cancelada pelo usuário.",
                "tool_executions": [],
                "stopped_reason": "cancelled",
            })

        with patch("backend.routes.chat.chat_stream", mock_chat_stream):
            res = self.client.post(
                "/api/chat/stream",
                json={"message": "teste", "history": [], "mission_id": "mission-cancel-test"},
            )

        self.assertEqual(res.status_code, 200)
        events = _parse_sse_events(res.text)
        done = next(data for ev, data in events if ev == "done")
        self.assertEqual(done["stopped_reason"], "cancelled")
        self.assertIn("cancelada", done["message"].lower())

    def test_chat_stream_agent_error(self):
        def mock_chat_stream(*_args, **_kwargs):
            yield format_sse("error", {"detail": "OpenRouter indisponível"})

        with patch("backend.routes.chat.chat_stream", mock_chat_stream):
            res = self.client.post(
                "/api/chat/stream",
                json={"message": "teste", "history": []},
            )

        self.assertEqual(res.status_code, 200)
        events = _parse_sse_events(res.text)
        self.assertTrue(any(ev == "error" for ev, _ in events))

    def test_autonomous_stream_emits_mission_and_done(self):
        def mock_autonomous_stream(*_args, **_kwargs):
            yield format_sse("mission_start", {"target": "scanme.nmap.org", "objective": "portas"})
            yield format_sse("round_start", {"round": 1, "max_rounds": 10, "tools_executed": 0})
            yield format_sse("tool_start", {
                "execution_id": "auto-exec-1",
                "command": "nmap scanme.nmap.org",
            })
            yield format_sse("tool_done", {"execution_id": "auto-exec-1"})
            yield format_sse("done", {
                "message": "Missão concluída.",
                "tool_executions": [],
                "report": "# Relatório\n",
                "objective_met": True,
                "rounds": 1,
                "stopped_reason": "objective_met",
                "tools_executed": 1,
            })

        with patch("backend.routes.autonomous.run_autonomous_stream", mock_autonomous_stream):
            res = self.client.post(
                "/api/autonomous/stream",
                json={
                    "target": "scanme.nmap.org",
                    "objective": "Mapear portas abertas",
                },
            )

        self.assertEqual(res.status_code, 200)
        events = _parse_sse_events(res.text)
        types = [e[0] for e in events]
        self.assertIn("mission_start", types)
        self.assertIn("round_start", types)
        self.assertIn("tool_start", types)
        self.assertIn("done", types)

        done = next(data for ev, data in events if ev == "done")
        self.assertTrue(done["objective_met"])
        self.assertIn("Relatório", done["report"])


if __name__ == "__main__":
    unittest.main()
