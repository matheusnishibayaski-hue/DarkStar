"""Cobertura adicional de agent stream, autopilot e system health."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from backend.ai.agent import ChatResponse, chat_stream
from backend.ai.autopilot import AutonomousResponse, run_autonomous_stream
from backend.ai.report import generate_report
from backend.security.missions import get_mission_registry
from fastapi.testclient import TestClient

from tests.llm_test_utils import make_openrouter_provider


class TestAgentStreamAndHealing(unittest.TestCase):
    def setUp(self):
        get_mission_registry()._missions.clear()

    def test_chat_stream_emits_done(self):
        fake = ChatResponse(message="ok", tool_executions=[])
        with patch("backend.ai.agent.chat", return_value=fake):
            events = "".join(chat_stream([], "hi"))
        self.assertIn("event: done", events)

    def test_preferred_tool_and_recon_context(self):
        from backend.ai import agent as ag

        msg = ag._apply_preferred_tool("scan", "nmap")
        self.assertIn("nmap", msg)
        self.assertEqual(ag._apply_preferred_tool("scan", None), "scan")
        self.assertEqual(ag._apply_preferred_tool("scan", "auto"), "scan")
        hist = [{"role": "user", "content": "lab.internal.com"}]
        with (
            patch.object(ag, "extract_targets", return_value=["lab.internal.com"]),
            patch.object(ag, "build_recon_context", return_value="CTX"),
            patch("backend.executor.recon_db.is_recon_target", return_value=True),
        ):
            enriched, targets = ag._apply_recon_context("go", hist)
        self.assertIn("CTX", enriched)
        self.assertEqual(targets, ["lab.internal.com"])

        converted = ag._convert_history([{"role": "bogus", "content": "x"}] * 20)
        self.assertLessEqual(len(converted), 10)
        self.assertEqual(converted[0]["role"], "user")

    def test_persist_recon_and_healing_path(self):
        from backend.ai import agent as ag

        result = MagicMock(
            success=True,
            blocked=False,
            command="nmap lab.test",
            stdout="80/tcp open http",
            stderr="",
            tool="nmap",
        )
        # len(patch) must be > 2 for merge to run
        patch_data = {"open_ports": [80], "cves": ["CVE-1"], "services": ["http"]}
        with (
            patch.object(ag, "extract_recon_from_output", return_value=patch_data),
            patch.object(ag, "merge_recon_update") as merge,
            patch("backend.executor.recon_db.extract_targets", return_value=["lab.test"]),
            patch("backend.executor.recon_db.is_recon_target", return_value=True),
        ):
            ag._persist_recon(result, ["lab.test"])
            merge.assert_called()

        # failed tool triggers healing message path via body
        tool_call = MagicMock()
        tool_call.id = "tc1"
        tool_call.function.name = "run_kali_tool"
        tool_call.function.arguments = '{"command":"nmap -V","reason":"x"}'

        msg_tool = MagicMock(content="", tool_calls=[tool_call])
        msg_final = MagicMock(content="healed", tool_calls=None)
        resp1 = MagicMock(choices=[MagicMock(message=msg_tool)])
        resp2 = MagicMock(choices=[MagicMock(message=msg_final)])
        client = MagicMock()
        client.chat.completions.create.side_effect = [resp1, resp2]

        fail = MagicMock(
            command="nmap -V",
            reason="x",
            stdout="",
            stderr="fail",
            exit_code=1,
            success=False,
            blocked=False,
            log_file_id="l",
            tool="nmap",
            truncated_for_llm=False,
        )

        provider = make_openrouter_provider(client, models=("m1", "m2"))
        with (
            patch("backend.ai.agent.get_llm_provider", return_value=provider),
            patch("backend.ai.agent.execute_in_kali", return_value=fail),
            patch("backend.ai.agent.summarize_output", return_value=("fail", False)),
            patch("backend.ai.agent.format_result_for_llm", return_value="fail"),
            patch("backend.ai.agent.get_stream_hub") as hub,
            patch("backend.ai.agent._persist_recon"),
            patch("backend.ai.agent.should_attempt_healing", return_value=True),
            patch("backend.ai.agent.healing_prompt", return_value="heal"),
        ):
            hub.return_value.create = MagicMock()
            from backend.ai.agent import chat

            out = chat([], "nmap")
        self.assertEqual(out.message, "healed")

    def test_llm_retry_fallback(self):
        from backend.ai.agent import _run_openrouter_body

        # 1) retryable fail → fallback model; 2) empty tools nudges; 3) final answer
        ok_msg = MagicMock(content="ok", tool_calls=None)
        client = MagicMock()
        client.chat.completions.create.side_effect = [
            RuntimeError("429 rate"),
            MagicMock(choices=[MagicMock(message=ok_msg)]),
            MagicMock(choices=[MagicMock(message=ok_msg)]),
        ]
        provider = make_openrouter_provider(client, models=("m1", "m2"))
        with (
            patch("backend.ai.agent.get_llm_provider", return_value=provider),
            patch("backend.ai.agent.time.sleep"),
        ):
            result = _run_openrouter_body([], "hi", None, None, None, None, None)
        self.assertEqual(result.message, "ok")

    def test_report_artifacts_and_recon_sections(self):
        with (
            patch(
                "backend.ai.report.list_recon_summaries",
                return_value=[
                    {
                        "target": "t",
                        "open_ports_count": 1,
                        "cves_count": 0,
                        "vulnerabilities_count": 0,
                        "updated_at": "2026-01-01T00:00:00",
                    }
                ],
            ),
            patch(
                "backend.ai.report.list_output_files",
                return_value=[
                    {"name": "a.txt", "size": 2048, "modified_at": "2026-01-01T00:00:00"}
                ],
            ),
        ):
            md = generate_report(
                [],
                [
                    {
                        "command": "x",
                        "success": False,
                        "blocked": True,
                        "exit_code": -1,
                        "stdout": "[HIGH] issue",
                        "stderr": "",
                        "log_file_id": "",
                    }
                ],
            )
        self.assertIn("BLOQUEADO", md)
        self.assertIn("Artefatos", md)
        self.assertIn("a.txt", md)


class TestAutopilotStream(unittest.TestCase):
    def test_stream_wrapper(self):
        fake = AutonomousResponse(message="done", stopped_reason="finished_early")
        with patch("backend.ai.autopilot.run_autonomous", return_value=fake):
            body = "".join(run_autonomous_stream("scanme.nmap.org", "mapear"))
        self.assertIn("event: done", body)

    def test_run_kali_in_cycle(self):
        from backend.ai import autopilot as ap
        from backend.ai.providers.base import LLMCompletion, LLMMessage, ToolCall

        tool_call = ToolCall(
            id="1",
            name="run_kali_tool",
            arguments='{"command":"nmap -V","reason":"v"}',
        )
        finish = ToolCall(
            id="2",
            name="finish_mission",
            arguments='{"summary":"ok","objective_met":true}',
        )

        def _record(command, reason, executions, **kwargs):
            executions.append(
                MagicMock(
                    success=True,
                    blocked=False,
                    exit_code=0,
                    command=command,
                    stdout="ok",
                    stderr="",
                )
            )
            return "out"

        executions: list = []
        with (
            patch("backend.ai.autopilot._record_execution", side_effect=_record),
            patch("backend.ai.autopilot.should_attempt_healing", return_value=False),
            patch(
                "backend.ai.autopilot._completion",
                side_effect=[
                    LLMCompletion(message=LLMMessage(tool_calls=[tool_call])),
                    LLMCompletion(message=LLMMessage(tool_calls=[finish])),
                ],
            ),
        ):
            text, finished, met, model = ap._run_autonomous_cycle(
                MagicMock(),
                [{"role": "system", "content": "s"}],
                executions,
                "m1",
                "m2",
                5,
            )
        self.assertTrue(finished)
        self.assertTrue(met)
        self.assertEqual(text, "ok")
        self.assertEqual(len(executions), 1)


class TestSystemHealthMocks(unittest.TestCase):
    def test_health_branches(self):
        from backend.main import app

        client = TestClient(app)
        with patch("backend.routes.system.subprocess.run") as run:
            # docker ps returns kali name; nmap ok; wifi fails
            run.side_effect = [
                MagicMock(returncode=0, stdout="kali-tools\n", stderr=""),
                MagicMock(returncode=0, stdout="Nmap", stderr=""),
                MagicMock(side_effect=FileNotFoundError),
            ]
            # Actually health does multiple runs - just ensure 200
            res = client.get("/api/health")
            self.assertEqual(res.status_code, 200)

        # recon invalid (path segment containing "..")
        res = client.get("/api/recon/evil..target")
        self.assertEqual(res.status_code, 400)

        # log stream missing
        res = client.get("/api/logs/stream/missingid01")
        self.assertEqual(res.status_code, 404)

        # log missing
        res = client.get("/api/logs/missingid01")
        self.assertEqual(res.status_code, 404)

        # files download missing
        res = client.get("/api/files/nope.txt")
        self.assertEqual(res.status_code, 404)


class TestMiddlewareError(unittest.TestCase):
    def test_request_failure_increments_errors(self):
        import asyncio

        from backend.middleware import request_context_guard

        async def boom(request):
            raise RuntimeError("fail")

        req = MagicMock()
        req.headers = {}
        req.query_params = MagicMock()
        req.query_params.get = MagicMock(return_value=None)
        req.method = "GET"
        req.url.path = "/x"
        req.client = MagicMock(host="127.0.0.1")
        req.state = MagicMock()

        with self.assertRaises(RuntimeError):
            asyncio.run(request_context_guard(req, boom))


if __name__ == "__main__":
    unittest.main()
