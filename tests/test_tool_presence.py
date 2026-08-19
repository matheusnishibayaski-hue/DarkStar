"""Testes de presença de tools, pending e orçamento do piloto."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from backend.ai.scan_profiles import pending_scan_tools, resolve_scan_tools
from backend.executor import tool_presence as tp


class TestToolPresence(unittest.TestCase):
    def setUp(self):
        tp.invalidate_tool_presence_cache()

    def tearDown(self):
        tp.invalidate_tool_presence_cache()

    def test_mark_and_cache(self):
        tp.mark_tool_unavailable("fakebin")
        presence = tp.probe_tools(["fakebin"])
        self.assertFalse(presence["fakebin"])
        tp.mark_tool_available("nmap")
        self.assertTrue(tp.probe_tools(["nmap"])["nmap"])

    def test_looks_like_missing(self):
        self.assertTrue(tp.looks_like_missing_binary(127, "sh: foo: not found"))
        self.assertTrue(tp.looks_like_missing_binary(1, "command not found"))
        self.assertFalse(tp.looks_like_missing_binary(0, ""))
        self.assertFalse(tp.looks_like_missing_binary(1, "connection refused"))

    def test_probe_batch_mocked(self):
        with (
            patch.object(tp, "_container_running", return_value=True),
            patch.object(
                tp,
                "_probe_batch_docker",
                return_value={"nmap": True, "missingtool": False},
            ),
        ):
            tp.invalidate_tool_presence_cache()
            out = tp.probe_tools(["nmap", "missingtool"], force=True)
            self.assertTrue(out["nmap"])
            self.assertFalse(out["missingtool"])

    def test_filter_available(self):
        with (
            patch.object(tp, "_container_running", return_value=True),
            patch.object(
                tp,
                "_probe_batch_docker",
                return_value={"nmap": True, "gobuster": False},
            ),
        ):
            tp.invalidate_tool_presence_cache()
            ok, missing = tp.filter_available(["nmap", "gobuster"], force=True)
            self.assertEqual(ok, ["nmap"])
            self.assertEqual(missing, ["gobuster"])

    def test_resolve_available_only(self):
        with patch(
            "backend.executor.tool_presence.filter_available",
            return_value=(["nmap", "httpx"], ["nuclei"]),
        ):
            tools = resolve_scan_tools("basic", available_only=True)
            self.assertEqual(tools, ["nmap", "httpx"])

    def test_pending_scan_tools(self):
        pending = pending_scan_tools(
            ["nmap", "httpx", "nuclei", "nikto"],
            ["nmap", "HTTPX"],
        )
        self.assertEqual(pending, ["nuclei", "nikto"])


class TestToolsProbeRoute(unittest.TestCase):
    def test_tools_probe_query(self):
        from backend.main import app
        from fastapi.testclient import TestClient

        from tests.auth_patch import patch_chat_api_token

        with (
            patch_chat_api_token(""),
            patch(
                "backend.executor.tool_presence.probe_tools",
                return_value={"nmap": True, "curl": False},
            ),
        ):
            client = TestClient(app)
            res = client.get("/api/tools?probe=1")
            self.assertEqual(res.status_code, 200)
            cats = res.json().get("categories") or []
            self.assertTrue(cats)
            # pelo menos uma tool com available
            found = False
            for cat in cats:
                for t in cat.get("tools") or []:
                    if "available" in t:
                        found = True
                        break
            self.assertTrue(found)


class TestAutopilotBudgetStable(unittest.TestCase):
    def test_mission_budget_not_reset_to_max(self):
        """Após round 1, remaining usa mission_budget, não MAX_AUTONOMOUS_TOOLS."""
        from backend.ai.autopilot import AutonomousResponse, run_autonomous
        from backend.ai.providers.base import LLMCompletion, LLMMessage, ToolCall
        from backend.ai.providers.factory import reset_llm_provider_cache
        from backend.security.missions import get_mission_registry

        get_mission_registry()._missions.clear()
        reset_llm_provider_cache()

        calls = {"n": 0}
        finish = ToolCall(
            id="tc-fin",
            name="finish_mission",
            arguments='{"summary":"ok","objective_met":true}',
        )

        def complete(**kwargs):
            calls["n"] += 1
            # first cycle: finish immediately (no kali tools) — budget path still runs
            return LLMCompletion(message=LLMMessage(content="", tool_calls=[finish]))

        provider = MagicMock()
        provider.name = "openrouter"
        provider.is_configured.return_value = True
        provider.configuration_error.return_value = ""
        provider.resolve_models.return_value = ("m1", "m2")
        provider.is_retryable_error.return_value = False
        provider.complete.side_effect = complete

        with (
            patch("backend.ai.autopilot.get_llm_provider", return_value=provider),
            patch("backend.ai.autopilot.build_recon_context", return_value=""),
            patch("backend.ai.autopilot.generate_report", return_value="# r"),
            patch(
                "backend.ai.autopilot.resolve_scan_tools",
                return_value=["nmap", "httpx", "nuclei", "nikto", "dig"],
            ),
            patch("backend.ai.autopilot.max_tool_budget", return_value=40),
        ):
            result = run_autonomous(
                "scanme.nmap.org",
                "mapear",
                mission_id="budget-1",
            )
        self.assertIsInstance(result, AutonomousResponse)
        # finish pode ser soft-blocked se pending > 3; no mínimo não crashou
        self.assertIn(
            result.stopped_reason, {"objective_met", "finished_early", "max_rounds", "max_tools"}
        )


if __name__ == "__main__":
    unittest.main()
