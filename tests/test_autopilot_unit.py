"""Testes unitários do Auto-Pilot com OpenRouter/executor mockados."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from backend.ai.autopilot import AutonomousResponse, run_autonomous
from backend.security.missions import get_mission_registry


class TestAutopilotUnit(unittest.TestCase):
    def setUp(self):
        get_mission_registry()._missions.clear()

    def test_missing_target_or_objective(self):
        with patch("backend.ai.autopilot.OPENROUTER_API_KEY", "sk-test"):
            result = run_autonomous("", "mapear portas")
            self.assertIsInstance(result, AutonomousResponse)
            self.assertEqual(result.stopped_reason, "error")

            result2 = run_autonomous("scanme.nmap.org", "")
            self.assertEqual(result2.stopped_reason, "error")

    def test_missing_api_key(self):
        with patch("backend.ai.autopilot.OPENROUTER_API_KEY", ""):
            result = run_autonomous("scanme.nmap.org", "scan rápido")
        self.assertEqual(result.stopped_reason, "error")
        self.assertIn("OPENROUTER", result.message.upper())

    def test_cancel_on_mission_start(self):
        mission_id = "auto-cancel-1"

        def emit(event: str, data: dict) -> None:
            if event == "mission_start":
                get_mission_registry().cancel(mission_id)

        fake_client = MagicMock()
        with (
            patch("backend.ai.autopilot.OPENROUTER_API_KEY", "sk-test"),
            patch("backend.ai.autopilot._create_client", return_value=fake_client),
            patch("backend.ai.autopilot.build_recon_context", return_value=""),
            patch("backend.ai.autopilot.resolve_model", return_value=("m1", "m2")),
        ):
            result = run_autonomous(
                "scanme.nmap.org",
                "mapear portas",
                mission_id=mission_id,
                emit=emit,
            )

        self.assertEqual(result.stopped_reason, "cancelled")
        fake_client.chat.completions.create.assert_not_called()

    def test_finish_mission_tool_ends_loop(self):
        mission_id = "auto-finish-1"

        tool_call = MagicMock()
        tool_call.id = "tc1"
        tool_call.function.name = "finish_mission"
        tool_call.function.arguments = (
            '{"summary":"Portas mapeadas","objective_met":true,"findings":["80/tcp"]}'
        )

        message = MagicMock()
        message.content = ""
        message.tool_calls = [tool_call]

        choice = MagicMock()
        choice.message = message
        response = MagicMock()
        response.choices = [choice]

        fake_client = MagicMock()
        fake_client.chat.completions.create.return_value = response

        with (
            patch("backend.ai.autopilot.OPENROUTER_API_KEY", "sk-test"),
            patch("backend.ai.autopilot._create_client", return_value=fake_client),
            patch("backend.ai.autopilot.build_recon_context", return_value=""),
            patch("backend.ai.autopilot.resolve_model", return_value=("m1", "m2")),
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
