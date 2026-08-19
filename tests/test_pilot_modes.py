"""Piloto por modos — presets, scan block, soft-block, preflight, waive."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from backend.ai.pilot_helpers import (
    classify_target_kind,
    command_looks_repeated,
    interpret_preflight_output,
)
from backend.ai.pilot_presets import (
    default_objective,
    resolve_engagement_mode,
    resolve_pilot_preset,
)
from backend.ai.scan_profiles import scan_profile_prompt_block
from backend.ai.tool_playbook import compact_playbook_block, rank_pending_tools
from backend.executor.surface import empty_surface


class TestPilotPresets(unittest.TestCase):
    def test_mode_priority_offline_wins(self):
        self.assertEqual(
            resolve_engagement_mode(
                engagement_mode="offensive",
                offline_flag=True,
                elevated=True,
                risk_profile="full",
            ),
            "offline",
        )
        self.assertEqual(
            resolve_engagement_mode(
                engagement_mode="offensive",
                elevated=True,
                risk_profile="full",
            ),
            "offensive",
        )
        self.assertEqual(resolve_engagement_mode(engagement_mode="safe"), "safe")

    def test_preset_objectives_differ(self):
        s = default_objective("safe", "basic")
        o = default_objective("offensive", "basic")
        g = default_objective("offline", "basic")
        self.assertNotEqual(s, o)
        self.assertNotEqual(o, g)
        self.assertTrue("low-noise" in g.lower() or "pegada" in g.lower() or "passive" in g.lower())

    def test_offensive_iters_higher(self):
        off = resolve_pilot_preset(engagement_mode="offensive", scan_profile="full")
        safe = resolve_pilot_preset(engagement_mode="safe", scan_profile="basic")
        self.assertGreaterEqual(off.per_round_iters, safe.per_round_iters)
        self.assertTrue(off.offensive)
        self.assertFalse(off.offline)


class TestScanBlockFindingDriven(unittest.TestCase):
    def test_no_cada_ferramenta(self):
        text = scan_profile_prompt_block(
            "basic", ["nmap", "httpx", "nuclei"], target="t.com", phase="enumerate"
        )
        self.assertNotIn("CADA ferramenta", text)
        self.assertIn("FILA DE PRIORIDADE", text)
        self.assertIn("coverage_waived", text)


class TestPlaybookPhase(unittest.TestCase):
    def test_phase_filters_categories(self):
        recon = compact_playbook_block(None, phase="recon", offline=False)
        self.assertIn("DNS", recon)
        self.assertNotIn("## Vuln", recon)
        off = compact_playbook_block(None, phase="vuln_scan", offline=True)
        self.assertIn("OPSEC", off)
        self.assertNotIn("ATTACK PATHS", off)

    def test_rank_offline_prefers_quiet(self):
        ranked = rank_pending_tools(["masscan", "dig", "nuclei"], offline=True, offensive=False)
        self.assertEqual(ranked[0], "dig")


class TestPreflightHelpers(unittest.TestCase):
    def test_classify_target(self):
        self.assertEqual(classify_target_kind("https://x.com/a"), "url")
        self.assertEqual(classify_target_kind("10.0.0.1"), "ip")
        self.assertEqual(classify_target_kind("example.com"), "domain")

    def test_interpret_dead_and_alive(self):
        dead = interpret_preflight_output(
            commands=["ping -c 1 x"],
            results=[{"command": "ping -c 1 x", "exit_code": 1, "stdout": "", "stderr": ""}],
        )
        self.assertTrue(dead.get("waive"))
        alive = interpret_preflight_output(
            commands=["ping -c 1 x"],
            results=[
                {
                    "command": "ping -c 1 x",
                    "exit_code": 0,
                    "stdout": "64 bytes from 1.2.3.4",
                    "stderr": "",
                }
            ],
        )
        self.assertTrue(alive.get("alive"))
        self.assertFalse(alive.get("waive"))

    def test_anti_repeat(self):
        self.assertTrue(
            command_looks_repeated(
                "nmap -sV t.com",
                ["nmap"],
                ["nmap -sV t.com"],
            )
        )
        self.assertFalse(
            command_looks_repeated("httpx -u https://t.com", ["nmap"], ["nmap -sV t.com"])
        )


class TestPilotModesIntegration(unittest.TestCase):
    def setUp(self):
        from backend.ai.providers.factory import reset_llm_provider_cache
        from backend.security.missions import get_mission_registry

        get_mission_registry()._missions.clear()
        reset_llm_provider_cache()

    def _provider_finish(self, *, waived: bool = False):
        from backend.ai.providers.base import LLMCompletion, LLMMessage, ToolCall

        args = '{"summary":"ok","objective_met":true'
        if waived:
            args += ',"coverage_waived":true'
        args += "}"
        tc = ToolCall(id="t1", name="finish_mission", arguments=args)
        p = MagicMock()
        p.name = "openrouter"
        p.is_configured.return_value = True
        p.resolve_models.return_value = ("m1", "m2")
        p.is_retryable_error.return_value = False
        p.complete.return_value = LLMCompletion(message=LLMMessage(content="", tool_calls=[tc]))
        return p

    def test_safe_basic_system_finding_driven(self):
        from backend.ai.autopilot import run_autonomous
        from backend.ai.providers.base import LLMCompletion, LLMMessage, ToolCall

        provider = self._provider_finish()
        captured = {}

        def capture(**kwargs):
            msgs = kwargs.get("messages") or []
            captured["system"] = msgs[0]["content"] if msgs else ""
            return LLMCompletion(
                message=LLMMessage(
                    content="",
                    tool_calls=[
                        ToolCall(
                            id="t1",
                            name="finish_mission",
                            arguments='{"summary":"ok","objective_met":true,"coverage_waived":true}',
                        )
                    ],
                )
            )

        provider.complete.side_effect = capture

        with (
            patch("backend.ai.autopilot.get_llm_provider", return_value=provider),
            patch("backend.ai.autopilot.build_recon_context", return_value=""),
            patch("backend.ai.autopilot.generate_report", return_value="# r"),
            patch("backend.ai.pilot_helpers.preflight_commands", return_value=[]),
            patch("backend.security.privileges.is_elevated", return_value=False),
        ):
            res = run_autonomous(
                "lab.test",
                "mapear",
                mission_id="mode-safe-1",
                scan_profile="basic",
                engagement_mode="safe",
                risk_profile="safe-active",
            )
        self.assertNotIn("CADA ferramenta", captured.get("system", ""))
        self.assertIn("FILA DE PRIORIDADE", captured.get("system", ""))
        self.assertEqual(res.stopped_reason, "objective_met")

    def test_offline_overlay_in_system(self):
        from backend.ai.autopilot import run_autonomous
        from backend.ai.providers.base import LLMCompletion, LLMMessage, ToolCall

        provider = self._provider_finish(waived=True)
        captured = {}

        def capture(**kwargs):
            msgs = kwargs.get("messages") or []
            captured["system"] = msgs[0]["content"] if msgs else ""
            return LLMCompletion(
                message=LLMMessage(
                    content="",
                    tool_calls=[
                        ToolCall(
                            id="t1",
                            name="finish_mission",
                            arguments='{"summary":"ok","objective_met":true,"coverage_waived":true}',
                        )
                    ],
                )
            )

        provider.complete.side_effect = capture

        with (
            patch("backend.ai.autopilot.get_llm_provider", return_value=provider),
            patch("backend.ai.autopilot.build_recon_context", return_value=""),
            patch("backend.ai.autopilot.generate_report", return_value="# r"),
            patch("backend.ai.pilot_helpers.preflight_commands", return_value=[]),
            patch("backend.ai.providers.get_active_provider_name", return_value="ollama"),
        ):
            run_autonomous(
                "lab.test",
                "mapear quieto",
                mission_id="mode-off-1",
                scan_profile="intermediate",
                engagement_mode="offline",
                offline=True,
            )
        self.assertIn("OFFLINE", captured.get("system", ""))
        self.assertIn("OPSEC", captured.get("system", ""))

    def test_coverage_waived_allows_finish(self):
        from backend.ai.autopilot import run_autonomous

        provider = self._provider_finish(waived=True)
        surface = empty_surface("waive.test")
        surface["phase"] = "vuln_scan"
        surface["ports"] = [{"port": "443"}]
        surface["findings"] = [{"status": "candidate", "severity": "critical", "title": "rce"}]
        surface["tools_run"] = ["nmap"]

        with (
            patch("backend.ai.autopilot.get_llm_provider", return_value=provider),
            patch("backend.ai.autopilot.build_recon_context", return_value=""),
            patch("backend.ai.autopilot.generate_report", return_value="# r"),
            patch("backend.ai.pilot_helpers.preflight_commands", return_value=[]),
            patch("backend.ai.autopilot.get_or_create_surface", return_value=surface),
            patch("backend.ai.autopilot.load_surface", return_value=surface),
            patch("backend.ai.autopilot.save_surface"),
            patch(
                "backend.ai.autopilot.resolve_scan_tools",
                return_value=["nmap", "httpx", "nuclei", "nikto", "ffuf"],
            ),
        ):
            res = run_autonomous(
                "waive.test",
                "mapear",
                mission_id="waive-1",
                scan_profile="custom",
                custom_tools=["nmap", "httpx", "nuclei", "nikto", "ffuf"],
            )
        self.assertEqual(res.stopped_reason, "objective_met")
        self.assertTrue(surface.get("coverage_waived"))

    def test_preflight_dead_skips_loop(self):
        from backend.ai.autopilot import run_autonomous

        provider = MagicMock()
        provider.name = "openrouter"
        provider.is_configured.return_value = True
        provider.resolve_models.return_value = ("m1", "m2")

        with (
            patch("backend.ai.autopilot.get_llm_provider", return_value=provider),
            patch("backend.ai.autopilot.build_recon_context", return_value=""),
            patch("backend.ai.autopilot.generate_report", return_value="# r"),
            patch(
                "backend.ai.pilot_helpers.preflight_commands",
                return_value=["ping -c 1 dead.test"],
            ),
            patch(
                "backend.ai.pilot_helpers.interpret_preflight_output",
                return_value={
                    "alive": False,
                    "waive": True,
                    "reason": "morto",
                },
            ),
            patch("backend.ai.autopilot._record_execution", return_value="ok"),
            patch("backend.ai.autopilot.save_surface"),
        ):
            res = run_autonomous(
                "dead.test",
                "mapear",
                mission_id="pf-1",
                scan_profile="basic",
            )
        self.assertEqual(res.stopped_reason, "preflight_dead")
        provider.complete.assert_not_called()

    def test_custom_empty_error(self):
        from backend.ai.autopilot import run_autonomous

        provider = MagicMock()
        provider.is_configured.return_value = True
        with patch("backend.ai.autopilot.get_llm_provider", return_value=provider):
            res = run_autonomous(
                "t.com",
                "x",
                scan_profile="custom",
                custom_tools=[],
            )
        self.assertEqual(res.stopped_reason, "error")


class TestAutonomousCycleContract(unittest.TestCase):
    def test_cycle_returns_five_values(self):
        from backend.ai import autopilot as ap

        mid = "cycle-contract-cancel"
        from backend.security.missions import get_mission_registry

        get_mission_registry().register(mid)
        get_mission_registry().cancel(mid)
        result = ap._run_autonomous_cycle(
            MagicMock(),
            [{"role": "system", "content": "s"}],
            [],
            "m1",
            "m2",
            1,
            mission_id=mid,
        )
        self.assertEqual(len(result), 5)
        text, finished, met, model, waived = result
        self.assertTrue(finished)
        self.assertFalse(met)
        self.assertFalse(waived)
        self.assertEqual(model, "m1")
        self.assertIn("cancel", text.lower())


if __name__ == "__main__":
    unittest.main()
