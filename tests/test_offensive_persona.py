"""Prompts dual, playbook, phases endurecidas e soft-block offensive."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from backend.ai.phases import evaluate_phase_advance, kickoff_for_phase
from backend.ai.tool_playbook import compact_playbook_block, next_actions_from_surface
from backend.config_prompts import (
    AUTONOMOUS_OFFENSIVE_OVERLAY,
    AUTONOMOUS_OFFLINE_OVERLAY,
    OFFENSIVE_SYSTEM_PROMPT,
    OFFLINE_SYSTEM_PROMPT,
    SYSTEM_PROMPT,
    resolve_autonomous_system,
    resolve_chat_prompts,
)
from backend.executor.surface import empty_surface


class TestDualPrompts(unittest.TestCase):
    def test_safe_vs_offensive_chat(self):
        sys_s, nudge_s, fin_s = resolve_chat_prompts(offensive=False)
        sys_o, nudge_o, fin_o = resolve_chat_prompts(offensive=True)
        self.assertIs(sys_s, SYSTEM_PROMPT)
        self.assertIs(sys_o, OFFENSIVE_SYSTEM_PROMPT)
        self.assertIn("consultor", sys_s.lower())
        self.assertIn("OFFENSIVE", sys_o)
        self.assertIn("adversário", sys_o.lower())
        self.assertNotIn("Só chame outra ferramenta se ainda faltar", nudge_s)
        self.assertIn("próximo teste útil", nudge_s)
        self.assertIn("oportunidade de ataque", nudge_o)
        self.assertIn("kill chain", fin_o.lower())
        self.assertNotEqual(nudge_s, nudge_o)

    def test_offline_persona_and_priority(self):
        sys_off, nudge_off, fin_off = resolve_chat_prompts(offline=True)
        self.assertIs(sys_off, OFFLINE_SYSTEM_PROMPT)
        self.assertIn("fantasma", sys_off.lower())
        self.assertIn("OPSEC", sys_off)
        self.assertIn("silencioso", nudge_off.lower())
        self.assertIn("rastro", fin_off.lower())
        # offline vence offensive
        sys_both, _, _ = resolve_chat_prompts(offensive=True, offline=True)
        self.assertIs(sys_both, OFFLINE_SYSTEM_PROMPT)

    def test_autonomous_overlay_on_full(self):
        safe = resolve_autonomous_system(
            target="t.com", objective="mapear", risk_profile="safe-active"
        )
        full = resolve_autonomous_system(
            target="t.com", objective="mapear", risk_profile="full"
        )
        off = resolve_autonomous_system(
            target="t.com",
            objective="mapear",
            risk_profile="safe-active",
            offensive=True,
        )
        ghost = resolve_autonomous_system(
            target="t.com",
            objective="mapear",
            risk_profile="safe-active",
            offline=True,
        )
        both = resolve_autonomous_system(
            target="t.com",
            objective="mapear",
            risk_profile="full",
            offline=True,
        )
        self.assertNotIn("MODO OFFENSIVE", safe)
        self.assertIn("MODO OFFENSIVE", full)
        self.assertIn("MODO OFFENSIVE", off)
        self.assertIn("finding-driven", safe.lower())
        self.assertIn(AUTONOMOUS_OFFENSIVE_OVERLAY.strip().split("\n")[0], full)
        self.assertIn("OFFLINE", ghost)
        self.assertIn(AUTONOMOUS_OFFLINE_OVERLAY.strip().split("\n")[0], ghost)
        self.assertIn("OFFLINE", both)
        self.assertIn("OFFENSIVE", both)


class TestPlaybook(unittest.TestCase):
    def test_compact_has_categories_and_size(self):
        text = compact_playbook_block(None, offensive=False)
        self.assertIn("TOOL PLAYBOOK", text)
        self.assertIn("DNS", text)
        self.assertIn("nuclei", text)
        self.assertLessEqual(len(text), 3600)
        self.assertNotIn("ATTACK PATHS", text)

    def test_offensive_attack_paths(self):
        text = compact_playbook_block(None, offensive=True)
        self.assertIn("ATTACK PATHS", text)
        self.assertIn("IDOR", text)

    def test_offline_opsec_block(self):
        text = compact_playbook_block(None, offline=True)
        self.assertIn("OPSEC", text)
        self.assertIn("LOW-NOISE", text)
        self.assertNotIn("ATTACK PATHS", text)

    def test_next_actions_from_ports(self):
        surface = {
            "phase": "enumerate",
            "ports": [{"host": "x", "port": "443"}],
            "urls": ["https://x/swagger.json"],
            "findings": [],
        }
        actions = next_actions_from_surface(surface, offensive=True)
        self.assertTrue(actions)
        blob = " ".join(actions).lower()
        self.assertTrue("http" in blob or "nuclei" in blob or "api" in blob)


class TestPhaseGates(unittest.TestCase):
    def test_recon_needs_tool_not_command_count(self):
        s = empty_surface("lab.test")
        s["commands_run"] = 5
        d = evaluate_phase_advance(s)
        self.assertFalse(d.advanced)

        s["tools_run"] = ["subfinder"]
        d = evaluate_phase_advance(s)
        self.assertTrue(d.advanced)
        self.assertEqual(d.phase, "enumerate")

    def test_enumerate_needs_ports_or_urls(self):
        s = empty_surface("lab.test")
        s["phase"] = "enumerate"
        s["commands_run"] = 10
        s["tools_run"] = ["nmap"]
        self.assertFalse(evaluate_phase_advance(s).advanced)
        s["ports"] = [{"host": "lab.test", "port": "80"}]
        self.assertEqual(evaluate_phase_advance(s).phase, "vuln_scan")

    def test_verify_blocks_on_high_unverified(self):
        s = empty_surface("lab.test")
        s["phase"] = "verify"
        s["findings"] = [
            {"status": "candidate", "severity": "critical", "title": "rce"},
        ]
        s["commands_run"] = 9
        d = evaluate_phase_advance(s)
        self.assertFalse(d.advanced)

        s["findings"][0]["status"] = "confirmed"
        s["findings"][0]["verified_at"] = "now"
        d = evaluate_phase_advance(s)
        self.assertTrue(d.advanced)
        self.assertEqual(d.phase, "report")

    def test_kickoff_includes_next_actions(self):
        text = kickoff_for_phase(
            phase="enumerate",
            target="t.com",
            objective="mapear",
            round_idx=0,
            max_rounds=10,
            tools_executed=0,
            surface_summary_data={"ports_count": 1, "urls_count": 0},
            surface={
                "phase": "enumerate",
                "ports": [{"port": "443"}],
                "urls": [],
                "findings": [],
            },
            offensive=True,
        )
        self.assertIn("NEXT BEST ACTIONS", text)
        self.assertIn("TOOL PLAYBOOK", text)
        self.assertIn("ATTACK PATHS", text)


class TestOffensiveWire(unittest.TestCase):
    def test_resolve_offensive_requires_elevation(self):
        from backend.ai.agent import _resolve_offensive
        from backend.security.privileges import set_elevated

        set_elevated(False)
        self.assertFalse(_resolve_offensive(True))
        set_elevated(True)
        self.assertTrue(_resolve_offensive(True))
        self.assertFalse(_resolve_offensive(False))
        set_elevated(False)

    def test_build_system_skips_playbook_in_ask(self):
        from backend.ai.agent import _build_system_prompt

        with patch("backend.security.privileges.is_elevated", return_value=True):
            sys_ask = _build_system_prompt(
                offensive=False,
                offline=False,
                chat_mode="ask",
                recon_targets=[],
            )
            sys_agent = _build_system_prompt(
                offensive=False,
                offline=False,
                chat_mode="agent",
                recon_targets=[],
            )
        self.assertNotIn("TOOL PLAYBOOK", sys_ask)
        self.assertIn("TOOL PLAYBOOK", sys_agent)

    def test_build_system_offensive_persona(self):
        from backend.ai.agent import _build_system_prompt

        text = _build_system_prompt(
            offensive=True,
            offline=False,
            chat_mode="agent",
            recon_targets=[],
        )
        self.assertIn("MODO OFFENSIVE", text)
        self.assertIn("ATTACK PATHS", text)

    def test_build_system_offline_persona(self):
        from backend.ai.agent import _build_system_prompt

        text = _build_system_prompt(
            offensive=True,
            offline=True,
            chat_mode="agent",
            recon_targets=[],
        )
        self.assertIn("MODO OFFLINE", text)
        self.assertIn("OPSEC", text)
        self.assertNotIn("MODO OFFENSIVE", text)

    def test_resolve_offline_flag_or_ollama(self):
        from backend.ai.agent import _resolve_offline

        with patch(
            "backend.ai.providers.get_active_provider_name", return_value="openrouter"
        ):
            self.assertFalse(_resolve_offline(False))
            self.assertTrue(_resolve_offline(True))
        with patch(
            "backend.ai.providers.get_active_provider_name", return_value="ollama"
        ):
            self.assertTrue(_resolve_offline(False))


class TestSoftBlockFinish(unittest.TestCase):
    def test_soft_block_defers_objective_met_with_pending(self):
        from backend.ai.autopilot import run_autonomous
        from backend.ai.providers.base import LLMCompletion, LLMMessage, ToolCall
        from backend.ai.providers.factory import reset_llm_provider_cache
        from backend.security.missions import get_mission_registry

        get_mission_registry()._missions.clear()
        reset_llm_provider_cache()

        tool_call = ToolCall(
            id="tc1",
            name="finish_mission",
            arguments='{"summary":"cedo demais","objective_met":true}',
        )
        provider = MagicMock()
        provider.name = "openrouter"
        provider.is_configured.return_value = True
        provider.resolve_models.return_value = ("m1", "m2")
        provider.is_retryable_error.return_value = False
        provider.complete.return_value = LLMCompletion(
            message=LLMMessage(content="", tool_calls=[tool_call])
        )

        # Surface com high candidate sem verify + muitas tools pendentes
        surface = empty_surface("softblock.test")
        surface["phase"] = "vuln_scan"
        surface["ports"] = [{"host": "softblock.test", "port": "443"}]
        surface["findings"] = [
            {"status": "candidate", "severity": "high", "title": "xss"},
        ]
        surface["tools_run"] = ["nmap"]

        with (
            patch("backend.ai.autopilot.get_llm_provider", return_value=provider),
            patch("backend.ai.autopilot.build_recon_context", return_value=""),
            patch("backend.ai.autopilot.build_surface_context", return_value=""),
            patch("backend.ai.autopilot.generate_report", return_value="# r"),
            patch(
                "backend.ai.autopilot.get_or_create_surface",
                return_value=surface,
            ),
            patch("backend.ai.autopilot.load_surface", return_value=surface),
            patch("backend.ai.autopilot.save_surface"),
            patch(
                "backend.ai.autopilot.resolve_scan_tools",
                return_value=["nmap", "httpx", "nuclei", "nikto", "ffuf", "katana"],
            ),
            patch("backend.ai.autopilot.MAX_AUTONOMOUS_ROUNDS", 3),
            patch("backend.ai.pilot_helpers.preflight_commands", return_value=[]),
        ):
            result = run_autonomous(
                "softblock.test",
                "mapear",
                mission_id="soft-1",
                scan_profile="custom",
                custom_tools=["nmap", "httpx", "nuclei", "nikto", "ffuf", "katana"],
                risk_profile="safe-active",
            )

        # Deve ter chamado complete mais de uma vez (soft-block) e só aceitar no fim
        self.assertGreaterEqual(provider.complete.call_count, 2)
        self.assertEqual(result.stopped_reason, "objective_met")
        self.assertTrue(result.objective_met)


if __name__ == "__main__":
    unittest.main()
