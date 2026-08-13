"""Testes unitários do Auto-Pilot com LLM provider/executor mockados."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from backend.ai.autopilot import AutonomousResponse, run_autonomous
from backend.ai.providers.base import LLMCompletion, LLMMessage, ToolCall
from backend.ai.providers.factory import reset_llm_provider_cache
from backend.security.missions import get_mission_registry


def _provider_mock(*, configured: bool = True):
    p = MagicMock()
    p.name = "openrouter"
    p.is_configured.return_value = configured
    p.configuration_error.return_value = "Configure OPENROUTER_API_KEY no arquivo .env.\n\nObtenha uma chave em: https://openrouter.ai/keys"
    p.resolve_models.return_value = ("m1", "m2")
    p.is_retryable_error.return_value = False
    p.format_error.side_effect = lambda e: f"Erro: {e}"
    return p


class TestAutopilotUnit(unittest.TestCase):
    def setUp(self):
        get_mission_registry()._missions.clear()
        reset_llm_provider_cache()

    def tearDown(self):
        reset_llm_provider_cache()

    def test_missing_target_or_objective(self):
        provider = _provider_mock()
        with patch("backend.ai.autopilot.get_llm_provider", return_value=provider):
            result = run_autonomous("", "mapear portas")
            self.assertIsInstance(result, AutonomousResponse)
            self.assertEqual(result.stopped_reason, "error")

            result2 = run_autonomous("scanme.nmap.org", "")
            self.assertEqual(result2.stopped_reason, "error")

    def test_missing_api_key(self):
        provider = _provider_mock(configured=False)
        with patch("backend.ai.autopilot.get_llm_provider", return_value=provider):
            result = run_autonomous("scanme.nmap.org", "scan rápido")
        self.assertEqual(result.stopped_reason, "error")
        self.assertIn("OPENROUTER", result.message.upper())

    def test_cancel_on_mission_start(self):
        mission_id = "auto-cancel-1"

        def emit(event: str, data: dict) -> None:
            if event == "mission_start":
                get_mission_registry().cancel(mission_id)

        provider = _provider_mock()
        with (
            patch("backend.ai.autopilot.get_llm_provider", return_value=provider),
            patch("backend.ai.autopilot.build_recon_context", return_value=""),
        ):
            result = run_autonomous(
                "scanme.nmap.org",
                "mapear portas",
                mission_id=mission_id,
                emit=emit,
            )

        self.assertEqual(result.stopped_reason, "cancelled")
        provider.complete.assert_not_called()

    def test_finish_mission_tool_ends_loop(self):
        mission_id = "auto-finish-1"
        tool_call = ToolCall(
            id="tc1",
            name="finish_mission",
            arguments='{"summary":"Portas mapeadas","objective_met":true}',
        )
        provider = _provider_mock()
        provider.complete.return_value = LLMCompletion(
            message=LLMMessage(content="", tool_calls=[tool_call])
        )

        with (
            patch("backend.ai.autopilot.get_llm_provider", return_value=provider),
            patch("backend.ai.autopilot.build_recon_context", return_value=""),
            patch("backend.ai.autopilot.generate_report", return_value="# relatorio"),
        ):
            result = run_autonomous(
                "scanme.nmap.org",
                "mapear portas",
                mission_id=mission_id,
            )

        self.assertTrue(result.objective_met)
        self.assertEqual(result.stopped_reason, "objective_met")
        self.assertIn("Portas mapeadas", result.message)


if __name__ == "__main__":
    unittest.main()
