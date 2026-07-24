"""Testes unitários do chat agent com LLM provider/executor mockados."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from backend.ai.agent import ChatResponse, _run_openrouter_body, chat, generate_report
from backend.ai.providers.base import LLMCompletion, LLMMessage, ToolCall
from backend.ai.providers.factory import reset_llm_provider_cache
from backend.security.missions import get_mission_registry


def _provider_mock(*, configured: bool = True):
    p = MagicMock()
    p.name = "openrouter"
    p.is_configured.return_value = configured
    p.configuration_error.return_value = (
        "Configure OPENROUTER_API_KEY no arquivo .env.\n\nObtenha uma chave em: https://openrouter.ai/keys"
    )
    p.resolve_models.return_value = ("m1", "m2")
    p.is_retryable_error.return_value = False
    p.format_error.side_effect = lambda e: f"Erro: {e}"
    return p


class TestAgentUnit(unittest.TestCase):
    def setUp(self):
        get_mission_registry()._missions.clear()
        reset_llm_provider_cache()

    def tearDown(self):
        reset_llm_provider_cache()

    def test_missing_api_key(self):
        provider = _provider_mock(configured=False)
        with patch("backend.ai.agent.get_llm_provider", return_value=provider):
            result = chat([], "scan nmap")
        self.assertIsInstance(result, ChatResponse)
        self.assertIn("OPENROUTER", result.message.upper())

    def test_cancel_before_llm_call(self):
        mission_id = "chat-cancel-1"
        provider = _provider_mock()
        get_mission_registry().register(mission_id)
        get_mission_registry().cancel(mission_id)

        with patch("backend.ai.agent.get_llm_provider", return_value=provider):
            result = _run_openrouter_body([], "teste", None, None, None, None, mission_id)

        self.assertEqual(result.stopped_reason, "cancelled")
        provider.complete.assert_not_called()

    def test_tool_call_then_final_text(self):
        tool_call = ToolCall(
            id="tc1",
            name="run_kali_tool",
            arguments='{"command":"nmap -V","reason":"versão"}',
        )
        provider = _provider_mock()
        provider.complete.side_effect = [
            LLMCompletion(message=LLMMessage(content="", tool_calls=[tool_call])),
            LLMCompletion(message=LLMMessage(content="nmap ok")),
        ]

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
            patch("backend.ai.agent.get_llm_provider", return_value=provider),
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
        provider = _provider_mock()
        provider.complete.return_value = LLMCompletion(
            message=LLMMessage(content="Nmap é um scanner de portas e serviços de rede.")
        )

        with patch("backend.ai.agent.get_llm_provider", return_value=provider):
            result = chat([], "O que é o nmap?")

        self.assertIn("Nmap", result.message)
        self.assertEqual(len(result.tool_executions), 0)
        self.assertEqual(provider.complete.call_count, 1)

    def test_malformed_tool_args_healed(self):
        broken = ToolCall(id="tc1", name="run_kali_tool", arguments="{command: nmap -V")
        provider = _provider_mock()
        provider.complete.side_effect = [
            LLMCompletion(message=LLMMessage(tool_calls=[broken])),
            LLMCompletion(message=LLMMessage(content="ok após heal")),
        ]

        fake_result = MagicMock()
        fake_result.command = "nmap -V"
        fake_result.reason = "versão"
        fake_result.stdout = "Nmap"
        fake_result.stderr = ""
        fake_result.exit_code = 0
        fake_result.success = True
        fake_result.blocked = False
        fake_result.log_file_id = "log1"
        fake_result.tool = "nmap"
        fake_result.truncated_for_llm = False

        with (
            patch("backend.ai.agent.get_llm_provider", return_value=provider),
            patch(
                "backend.ai.agent.resolve_tool_arguments",
                return_value=({"command": "nmap -V", "reason": "versão"}, ""),
            ),
            patch("backend.ai.agent.execute_in_kali", return_value=fake_result),
            patch("backend.ai.agent.summarize_output", return_value=("Nmap", False)),
            patch("backend.ai.agent.format_result_for_llm", return_value="ok"),
            patch("backend.ai.agent.get_stream_hub") as hub_mock,
            patch("backend.ai.agent._persist_recon"),
        ):
            hub_mock.return_value.create = MagicMock()
            result = chat([], "nmap")

        self.assertEqual(result.tool_executions[0].command, "nmap -V")
        self.assertEqual(result.message, "ok após heal")

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
        reg.cancel("m-b")
        self.assertTrue(reg.is_cancelled("m-b"))
        # cleanup removes entries
        reg.cleanup("m-a")
        reg.cleanup("m-b")


if __name__ == "__main__":
    unittest.main()
