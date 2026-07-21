"""Testes unitários do chat agent com OpenRouter/executor mockados."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from backend.ai.agent import ChatResponse, _run_openrouter_body, chat, generate_report
from backend.security.missions import get_mission_registry


class TestAgentUnit(unittest.TestCase):
    def setUp(self):
        get_mission_registry()._missions.clear()

    def test_missing_api_key(self):
        with patch("backend.ai.agent.OPENROUTER_API_KEY", ""):
            result = chat([], "scan nmap")
        self.assertIsInstance(result, ChatResponse)
        self.assertIn("OPENROUTER", result.message.upper())

    def test_cancel_before_llm_call(self):
        mission_id = "chat-cancel-1"
        fake_client = MagicMock()
        get_mission_registry().register(mission_id)
        get_mission_registry().cancel(mission_id)

        with (
            patch("backend.ai.agent.OPENROUTER_API_KEY", "sk-test"),
            patch("backend.ai.agent.OpenAI", return_value=fake_client),
            patch("backend.ai.agent.resolve_model", return_value=("m1", "m2")),
        ):
            result = _run_openrouter_body([], "teste", None, None, None, None, mission_id)

        self.assertEqual(result.stopped_reason, "cancelled")
        fake_client.chat.completions.create.assert_not_called()

    def test_tool_call_then_final_text(self):
        tool_call = MagicMock()
        tool_call.id = "tc1"
        tool_call.function.name = "run_kali_tool"
        tool_call.function.arguments = '{"command":"nmap -V","reason":"versão"}'

        msg_with_tool = MagicMock()
        msg_with_tool.content = ""
        msg_with_tool.tool_calls = [tool_call]

        msg_final = MagicMock()
        msg_final.content = "nmap ok"
        msg_final.tool_calls = None

        choice1 = MagicMock()
        choice1.message = msg_with_tool
        choice2 = MagicMock()
        choice2.message = msg_final

        resp1 = MagicMock()
        resp1.choices = [choice1]
        resp2 = MagicMock()
        resp2.choices = [choice2]

        fake_client = MagicMock()
        fake_client.chat.completions.create.side_effect = [resp1, resp2]

        fake_result = MagicMock()
        fake_result.command = "nmap -V"
        fake_result.reason = "versão"
        fake_result.stdout = "Nmap version"
        fake_result.stderr = ""
        fake_result.exit_code = 0
        fake_result.success = True
        fake_result.blocked = False
        fake_result.log_file_id = "log1"
        fake_result.tool = "nmap"
        fake_result.truncated_for_llm = False

        with (
            patch("backend.ai.agent.OPENROUTER_API_KEY", "sk-test"),
            patch("backend.ai.agent.OpenAI", return_value=fake_client),
            patch("backend.ai.agent.resolve_model", return_value=("m1", "m2")),
            patch("backend.ai.agent.execute_in_kali", return_value=fake_result),
            patch("backend.ai.agent.summarize_output", return_value=("Nmap version", False)),
            patch("backend.ai.agent.format_result_for_llm", return_value="ok"),
            patch("backend.ai.agent.get_stream_hub") as hub_mock,
            patch("backend.ai.agent._persist_recon"),
        ):
            hub_mock.return_value.create = MagicMock()
            result = chat([], "versão do nmap")

        self.assertEqual(result.message, "nmap ok")
        self.assertEqual(len(result.tool_executions), 1)
        self.assertTrue(result.tool_executions[0].success)

    def test_conversational_answer_without_forcing_tools(self):
        msg = MagicMock()
        msg.content = "Nmap é um scanner de portas e serviços de rede."
        msg.tool_calls = None

        choice = MagicMock()
        choice.message = msg
        resp = MagicMock()
        resp.choices = [choice]

        fake_client = MagicMock()
        fake_client.chat.completions.create.return_value = resp

        with (
            patch("backend.ai.agent.OPENROUTER_API_KEY", "sk-test"),
            patch("backend.ai.agent.OpenAI", return_value=fake_client),
            patch("backend.ai.agent.resolve_model", return_value=("m1", "m2")),
        ):
            result = chat([], "O que é o nmap?")

        self.assertIn("Nmap", result.message)
        self.assertEqual(len(result.tool_executions), 0)
        self.assertEqual(fake_client.chat.completions.create.call_count, 1)

    def test_generate_report_contains_sections(self):
        md = generate_report(
            [
                {"role": "user", "content": "scan lab"},
                {"role": "assistant", "content": "feito"},
            ],
            [
                {
                    "command": "nmap -sV lab",
                    "reason": "portas",
                    "stdout": "80/tcp open http\nCVE-2024-1234",
                    "stderr": "",
                    "exit_code": 0,
                    "success": True,
                    "blocked": False,
                    "log_file_id": "abc",
                }
            ],
        )
        self.assertIn("Resumo Executivo", md)
        self.assertIn("CVE-2024-1234", md)
        self.assertIn("nmap -sV lab", md)


class TestMissionConcurrency(unittest.TestCase):
    def test_multiple_missions_independent_cancel(self):
        reg = get_mission_registry()
        reg._missions.clear()
        a = reg.register("m-a")
        b = reg.register("m-b")
        self.assertFalse(reg.is_cancelled("m-a"))
        self.assertFalse(reg.is_cancelled("m-b"))
        reg.cancel("m-a")
        self.assertTrue(reg.is_cancelled("m-a"))
        self.assertFalse(reg.is_cancelled("m-b"))
        self.assertTrue(a.cancel_event.is_set())
        self.assertFalse(b.cancel_event.is_set())

    def test_concurrent_cancel_from_thread(self):
        import threading

        reg = get_mission_registry()
        reg._missions.clear()
        mid = "m-thread"
        reg.register(mid)
        done = threading.Event()

        def worker():
            reg.cancel(mid)
            done.set()

        t = threading.Thread(target=worker)
        t.start()
        self.assertTrue(done.wait(timeout=2))
        t.join(timeout=2)
        self.assertTrue(reg.is_cancelled(mid))


if __name__ == "__main__":
    unittest.main()
