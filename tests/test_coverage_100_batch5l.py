"""Lote 5l: Miss do piloto/playbook/report/autopilot (fail-under=100)."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from backend.ai.providers.base import LLMCompletion, LLMMessage, ToolCall


class TestPilotHelpersCov(unittest.TestCase):
    def test_preflight_kinds_and_interpret(self):
        from backend.ai.pilot_helpers import (
            command_looks_repeated,
            interpret_preflight_output,
            kickoff_target_hint,
            preflight_commands,
        )

        url_cmds = preflight_commands("https://lab.test/x")
        self.assertTrue(any("httpx" in c for c in url_cmds))
        bare = preflight_commands("lab.test")
        self.assertTrue(any("httpx" in c for c in bare) or any("ping" in c for c in bare))
        # bare domain without scheme → not url kind
        dom = preflight_commands("example.com")
        self.assertTrue(any("ping" in c for c in dom))
        self.assertTrue(any("dig" in c for c in dom))
        offline = preflight_commands("example.com", offline=True)
        self.assertEqual(len(offline), 1)
        self.assertIn("dig", offline[0])
        ip = preflight_commands("10.0.0.1")
        self.assertEqual(len(ip), 1)
        self.assertIn("ping", ip[0])

        empty = interpret_preflight_output(commands=[], results=[])
        self.assertTrue(empty["alive"])
        self.assertFalse(empty["waive"])

        alive_exit = interpret_preflight_output(
            commands=["ping -c 2 1.1.1.1"],
            results=[
                {"command": "ping -c 2 1.1.1.1", "exit_code": 0, "stdout": "ok", "stderr": ""}
            ],
        )
        self.assertTrue(alive_exit["alive"])

        alive_httpx = interpret_preflight_output(
            commands=["httpx -u https://a -status-code"],
            results=[
                {
                    "command": "httpx -u https://a -status-code",
                    "exit_code": 1,
                    "stdout": "https://a [200]",
                    "stderr": "",
                }
            ],
        )
        self.assertTrue(alive_httpx["alive"])

        alive_dig = interpret_preflight_output(
            commands=["dig a.com"],
            results=[
                {
                    "command": "dig a.com",
                    "exit_code": 1,
                    "stdout": "a.com. has address 1.2.3.4",
                    "stderr": "",
                }
            ],
        )
        self.assertTrue(alive_dig["alive"])

        alive_ping = interpret_preflight_output(
            commands=["ping -c 2 x"],
            results=[
                {
                    "command": "ping -c 2 x",
                    "exit_code": 1,
                    "stdout": "64 bytes from 1.2.3.4",
                    "stderr": "",
                }
            ],
        )
        self.assertTrue(alive_ping["alive"])

        infra = interpret_preflight_output(
            commands=["ping -c 2 x"],
            results=[
                {
                    "command": "ping -c 2 x",
                    "exit_code": 1,
                    "stdout": "",
                    "stderr": "Cannot connect to docker daemon",
                }
            ],
        )
        self.assertTrue(infra["alive"])
        self.assertFalse(infra["waive"])

        dead = interpret_preflight_output(
            commands=["ping -c 2 x"],
            results=[{"command": "ping -c 2 x", "exit_code": 1, "stdout": "timeout", "stderr": ""}],
        )
        self.assertFalse(dead["alive"])
        self.assertTrue(dead["waive"])

        self.assertFalse(command_looks_repeated("", ["nmap"], ["nmap -sV t"]))
        self.assertFalse(command_looks_repeated("nuclei -u t", ["nmap"], ["nmap -sV t"]))
        self.assertTrue(
            command_looks_repeated(
                "nmap -sV t.com",
                ["nmap"],
                ["", "nmap -sV t.com"],
            )
        )
        self.assertTrue(
            command_looks_repeated(
                "nmap -sV t.com -Pn",
                ["nmap"],
                ["nmap -sV t.com"],
            )
        )
        self.assertFalse(
            command_looks_repeated("nmap -p 80 t.com", ["nmap"], ["httpx -u https://t.com"])
        )

        hint = kickoff_target_hint("https://a.test")
        self.assertIn("-", hint)
        self.assertTrue(kickoff_target_hint("1.2.3.4", offline=True))


class TestPilotPresetsCov(unittest.TestCase):
    def test_normalize_and_resolve_branches(self):
        from backend.ai.pilot_presets import (
            normalize_engagement_mode,
            resolve_engagement_mode,
            resolve_pilot_preset,
        )

        self.assertEqual(normalize_engagement_mode("nope"), "safe")
        self.assertEqual(normalize_engagement_mode(None), "safe")
        self.assertEqual(
            resolve_engagement_mode(risk_profile="full", elevated=True),
            "offensive",
        )
        preset = resolve_pilot_preset(engagement_mode="safe", scan_profile="weird")
        self.assertEqual(preset.engagement_mode, "safe")
        self.assertIn("Mapear", preset.objective_default)


class TestToolPlaybookCov(unittest.TestCase):
    def test_next_actions_ports_urls_tech_limit(self):
        from backend.ai.tool_playbook import (
            adaptive_first_actions,
            classify_target_kind,
            compact_playbook_block,
            next_actions_from_surface,
            rank_pending_tools,
        )

        self.assertEqual(next_actions_from_surface(None), [])
        summary = next_actions_from_surface(
            {
                "phase": "recon",
                "ports_count": 0,
                "urls_count": 0,
                "findings_candidates": 2,
            },
            offline=True,
        )
        self.assertTrue(any("Passive" in a or "DNS" in a for a in summary))
        self.assertTrue(any("Verifique" in a or "candidato" in a for a in summary))

        surf = {
            "phase": "enumerate",
            "ports": [80, {"port": "443/tcp"}, "nope", None, {"port": "445"}],
            "urls": [
                "https://x/login",
                "https://x/api/upload",
                "https://x/swagger.json",
            ],
            "hosts": ["x"],
            "services": ["WordPress", "express"],
            "findings": [
                {"status": "candidate", "severity": "low", "title": "info"},
            ],
        }
        acts = next_actions_from_surface(surf, limit=20)
        blob = " ".join(acts).lower()
        self.assertIn("smb", blob)
        self.assertIn("SSH", " ".join(next_actions_from_surface({**surf, "ports": [22]})))
        ldap = next_actions_from_surface({**surf, "ports": [389]})
        self.assertTrue(any("ldap" in a.lower() for a in ldap))
        self.assertTrue(any("auth" in a.lower() for a in acts))
        self.assertTrue(any("upload" in a.lower() for a in acts))
        self.assertTrue(any("wordpress" in a.lower() for a in acts))
        self.assertTrue(any("node" in a.lower() for a in acts))
        self.assertTrue(any("candidato" in a.lower() for a in acts))
        capped = next_actions_from_surface(surf, limit=1)
        self.assertEqual(len(capped), 1)

        off = next_actions_from_surface(surf, offensive=True, offline=False, limit=10)
        self.assertTrue(off)

        self.assertEqual(classify_target_kind("10.0.0.abc"), "domain")
        self.assertTrue(adaptive_first_actions("https://a.test"))
        self.assertTrue(adaptive_first_actions("1.2.3.4"))
        self.assertTrue(adaptive_first_actions("1.2.3.4", offline=True))
        self.assertTrue(adaptive_first_actions("example.com", offline=True))

        ranked = rank_pending_tools(["nuclei", "dig", "masscan"], offensive=True)
        self.assertEqual(ranked[0], "nuclei")

        short = compact_playbook_block(
            surf, phase="recon", offline=True, max_chars=80, target_hint="example.com"
        )
        self.assertIn("truncado", short)


class TestLiveReportCov(unittest.TestCase):
    def test_hbar_charts_iso_success(self):
        from backend.ai import live_report as lr

        bar = lr._hbar("X", 5, 10, "#111")
        self.assertIn("svg", bar)
        low = lr._charts_html({"risk": {"score": 10, "label": "Baixo"}, "severity": {}})
        self.assertIn("charts", low)
        mid = lr._charts_html(
            {
                "risk": {"score": 40, "label": "Médio"},
                "severity": {"high": 1},
                "kinds": {},
                "tools": {},
            }
        )
        self.assertIn("Sem tipos", mid)
        high = lr._charts_html(
            {
                "risk": {"score": 80, "label": "Alto"},
                "severity": {"critical": 1, "high": 2},
                "kinds": {"XSS": 2},
                "tools": {"nuclei": 3},
                "confirmed": [{}],
                "fps": [{}],
                "pending": [{}],
                "discarded": [{}],
            }
        )
        self.assertIn("XSS", high)
        iso = lr._render_iso_soc2(
            [],
            "t.com",
            report={
                "disclaimer_pt": "Indicativo",
                "frameworks": {
                    "ISO27001": {"name": "ISO", "indicative_coverage_0_100": 40},
                    "SOC2": {"name": "SOC2", "indicative_coverage_0_100": 55},
                },
            },
        )
        self.assertIn("ISO", iso)
        self.assertIn("40%", iso)


class TestReportModelCov(unittest.TestCase):
    def test_filter_scope_cards_summary_kinds(self):
        import sys
        import types

        from backend.ai import report_model as rm

        # Import fail → pass-through
        fake = types.ModuleType("backend.executor.recon_db")
        with patch.dict(sys.modules, {"backend.executor.recon_db": fake}):
            out = rm._filter_client_targets(["a.com", "  "])
            self.assertIn("a.com", out)

        filtered = rm._filter_client_targets(
            ["lab.test", "C:\\foo.ts", "https://lab.test", "LAB.TEST"]
        )
        self.assertTrue(all("foo" not in t.lower() for t in filtered))
        self.assertEqual(len(filtered), 1)

        scope = rm._clean_scope(
            [
                "",
                "Analise o mapa e os arquivos do projeto. Regras:",
                "entregue somente o relatório final por favor e ignore o resto",
                "x" * 12,
                "Escopo autorizado: app.cliente.com e api.cliente.com " + ("y" * 200),
                "Mais um bloco de escopo válido com detalhes suficientes " + ("z" * 200),
                "Ainda mais texto para estourar o budget de quinhentos " + ("w" * 200),
            ]
        )
        self.assertTrue(len(scope) >= 12)
        self.assertNotIn("Analise o mapa", scope)

        cards = rm.build_client_cards(
            [{"title": "XSS", "plain_title": "Script", "severity": "high"}],
            [],
        )
        self.assertEqual(cards[0]["fix_title"], "Corrigir conforme a evidência deste achado")

        more = rm.build_simple_summary(
            {
                "risk": {"score": 60, "label": "Médio alto"},
                "confirmed": [{"title": "a"}, {"title": "b"}],
                "client_cards": [
                    {"title": "a", "fix_title": "Fix A"},
                    {"title": "b", "fix_title": "Fix B"},
                ],
                "remediations": [],
            }
        )
        self.assertIn("mais 1", more["now"])

        generic = rm.build_simple_summary(
            {
                "risk": {"score": 40, "label": "Médio"},
                "confirmed": [{"title": "a"}],
                "client_cards": [],
                "remediations": [],
            }
        )
        self.assertIn("Corrija os itens", generic["now"])

        findings = [
            {
                "title": "XSS",
                "status": "confirmed",
                "severity": "high",
                "kind": "xss",
                "kind_label": "XSS",
            },
            {
                "title": "FP",
                "status": "false_positive",
                "severity": "low",
                "kind": "banner",
                "kind_label": "Banner",
            },
        ]
        with (
            patch.object(rm, "_merge_extracted", return_value=findings),
            patch("backend.ai.report_model.enrich_finding", side_effect=lambda f: f),
            patch("backend.ai.report_model.is_reportable_finding", return_value=True),
            patch(
                "backend.executor.session_intel.collect_session_tool_executions",
                return_value=[],
            ),
        ):
            model = rm.assemble_session_report(
                history=[{"role": "user", "content": "teste example.com autorizado"}],
                tool_executions=[],
            )
        self.assertIn("XSS", model.get("kinds") or {})
        self.assertNotIn("Banner", model.get("kinds") or {})


class TestPdfReportCov(unittest.TestCase):
    def test_bar_drawing_and_lazy_fills(self):
        from backend.ai.pdf_report import _bar_drawing, _pdf_from_session_model

        d = _bar_drawing([("Alto", 3, "#dc2626"), ("Baixo", 1, "#166534")], max_value=5)
        self.assertTrue(d)

        model = {
            "title": "Sessao 5l",
            "target": "a.test",
            "now": "01/01/2026 00:00 UTC",
            "targets": ["a.test"],
            "risk": {"score": 40, "label": "Médio"},
            "severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            "kinds": {},
            "tools": {},
            "executive": "resumo",
            "scope": "escopo",
            "ok_exec": 0,
            "fail_exec": 0,
            "executions": [],
            "findings": [],
            "report_findings": [],
            "client_cards": [],
            "ai_prompt": "",
            "simple_summary": {},
            "confirmed": [
                {
                    "title": "XSS",
                    "plain_title": "Script",
                    "status": "confirmed",
                    "severity": "high",
                    "severity_label": "Grave",
                }
            ],
            "fps": [],
            "pending": [],
            "discarded": [],
            "remediations": [],
            "notes": [],
            "iso_cov": 0,
            "soc_cov": 0,
            "compliance": None,
            "empty": False,
        }
        with patch("backend.ai.report_model.assemble_session_report", return_value=model):
            raw = _pdf_from_session_model(
                session_id="pdf5l01",
                title="Sessao",
                tool_executions=[],
                history=[],
            )
        self.assertTrue(raw.startswith(b"%PDF"))


class TestPhasesCov(unittest.TestCase):
    def test_vuln_scan_to_report_without_candidates(self):
        from backend.ai.phases import evaluate_phase_advance

        d = evaluate_phase_advance(
            {
                "phase": "vuln_scan",
                "tools_run": ["nuclei"],
                "ports": [{"port": 80}],
                "urls": [],
                "findings": [],
            }
        )
        self.assertTrue(d.advanced)
        self.assertEqual(d.phase, "report")
        self.assertTrue(d.can_finish)


class TestAgentResolveCov(unittest.TestCase):
    def test_resolve_except_and_surface_phase(self):
        from backend.ai import agent as ag

        with patch(
            "backend.security.privileges.is_elevated",
            side_effect=RuntimeError("priv"),
        ):
            self.assertFalse(ag._resolve_offensive(True))
        with patch(
            "backend.ai.providers.get_active_provider_name",
            side_effect=RuntimeError("prov"),
        ):
            self.assertFalse(ag._resolve_offline(False))

        def load_side(t):
            if t == "miss.test":
                return {}
            return {"phase": "enumerate", "ports": []}

        with patch("backend.executor.surface.load_surface", side_effect=load_side):
            text = ag._build_system_prompt(
                offensive=False,
                offline=False,
                chat_mode="agent",
                recon_targets=["miss.test", "hit.test"],
            )
        self.assertIn("TOOL PLAYBOOK", text)
        self.assertIn("Portas", text)


class TestAutopilotMissCov(unittest.TestCase):
    def _provider(self):
        p = MagicMock()
        p.name = "openrouter"
        p.is_configured.return_value = True
        p.resolve_models.return_value = ("m1", "m2")
        p.is_retryable_error.return_value = False
        p.format_error.side_effect = lambda e: str(e)
        return p

    def test_anti_repeat_and_budget_zero(self):
        from backend.ai import autopilot as ap
        from backend.ai.agent import ToolExecution

        tc = ToolCall(
            id="t1",
            name="run_kali_tool",
            arguments='{"command":"nmap -sV t.com","reason":"ports"}',
        )
        provider = self._provider()
        # Two identical tool calls: first continues after anti-repeat, second exhausts budget
        provider.complete.side_effect = [
            LLMCompletion(message=LLMMessage(content="", tool_calls=[tc])),
            LLMCompletion(message=LLMMessage(content="", tool_calls=[tc])),
        ]
        executions = [
            ToolExecution(
                command="nmap -sV t.com",
                reason="r",
                stdout="ok",
                stderr="",
                exit_code=0,
                success=True,
                tool="nmap",
            )
        ]
        with patch.object(
            ap,
            "resolve_tool_arguments",
            return_value=({"command": "nmap -sV t.com", "reason": "r"}, ""),
        ):
            text, finished, met, model, waived = ap._run_autonomous_cycle(
                provider,
                [{"role": "system", "content": "s"}],
                executions,
                "m1",
                "m1",
                2,
                phase="recon",
                risk_profile="safe-active",
            )
        self.assertFalse(finished)
        self.assertEqual(text, "")
        # also hit elif ex.command branch for tools_run_hint
        executions2 = [
            ToolExecution(
                command="nmap -sV t.com",
                reason="r",
                stdout="ok",
                stderr="",
                exit_code=0,
                success=True,
                tool="",
            )
        ]
        provider.complete.side_effect = None
        provider.complete.return_value = LLMCompletion(
            message=LLMMessage(content="", tool_calls=[tc])
        )
        with patch.object(
            ap,
            "resolve_tool_arguments",
            return_value=({"command": "nmap -sV t.com", "reason": "r"}, ""),
        ):
            ap._run_autonomous_cycle(
                provider,
                [{"role": "system", "content": "s"}],
                executions2,
                "m1",
                "m1",
                1,
                phase="recon",
                risk_profile="safe-active",
            )

    def test_mode_clamps_provider_priv_except(self):
        from backend.ai.autopilot import run_autonomous

        provider = self._provider()
        events: list[str] = []

        def cycle(*_a, **_k):
            return "done", True, True, "m1", False

        with (
            patch("backend.ai.autopilot.get_llm_provider", return_value=provider),
            patch(
                "backend.ai.providers.get_active_provider_name",
                side_effect=RuntimeError("no-prov"),
            ),
            patch(
                "backend.security.privileges.is_elevated",
                side_effect=RuntimeError("no-priv"),
            ),
            patch("backend.ai.autopilot.build_recon_context", return_value=""),
            patch("backend.ai.autopilot.generate_report", return_value="# r"),
            patch("backend.ai.pilot_helpers.preflight_commands", return_value=[]),
            patch("backend.ai.autopilot._run_autonomous_cycle", side_effect=cycle),
            patch("backend.ai.autopilot.run_verification_pipeline", return_value=None),
            patch(
                "backend.ai.autopilot.findings_for_report",
                return_value={
                    "confirmed": [],
                    "false_positive": [],
                    "discarded": [],
                    "candidate": [],
                },
            ),
        ):
            res = run_autonomous(
                "clamp5l.test",
                "mapear",
                mission_id="clamp-5l",
                engagement_mode="safe",
                risk_profile="full",
                emit=lambda e, _d: events.append(e),
            )
        self.assertTrue(res.message)

        # offensive + elevated → profile full
        with (
            patch("backend.ai.autopilot.get_llm_provider", return_value=provider),
            patch("backend.ai.providers.get_active_provider_name", return_value="openrouter"),
            patch("backend.security.privileges.is_elevated", return_value=True),
            patch(
                "backend.security.privileges.effective_risk_profile",
                side_effect=lambda p: p,
            ),
            patch("backend.ai.autopilot.build_recon_context", return_value=""),
            patch("backend.ai.autopilot.generate_report", return_value="# r"),
            patch("backend.ai.pilot_helpers.preflight_commands", return_value=[]),
            patch("backend.ai.autopilot._run_autonomous_cycle", side_effect=cycle),
            patch("backend.ai.autopilot.run_verification_pipeline", return_value=None),
            patch(
                "backend.ai.autopilot.findings_for_report",
                return_value={
                    "confirmed": [],
                    "false_positive": [],
                    "discarded": [],
                    "candidate": [],
                },
            ),
        ):
            res2 = run_autonomous(
                "off5l.test",
                "abuso",
                mission_id="off-5l",
                engagement_mode="offensive",
                risk_profile="safe-active",
            )
        self.assertTrue(res2.message)

    def test_missing_bin_parse_finding_update_verify_fail(self):
        from backend.ai.agent import ToolExecution
        from backend.ai.autopilot import run_autonomous
        from backend.executor.surface import empty_surface

        provider = self._provider()
        surface = empty_surface("hud5l.test")
        surface["phase"] = "vuln_scan"
        surface["findings"] = [
            {"status": "candidate", "severity": "critical", "title": "RCE"},
        ]
        surface["tools_run"] = ["nmap"]
        events: list[tuple[str, dict]] = []

        def cycle(_c, _m, executions, *a, **k):
            if not executions:
                executions.append(
                    ToolExecution(
                        command="/usr/bin/ghosttool -h",
                        reason="r",
                        stdout="",
                        stderr="not found",
                        exit_code=127,
                        success=False,
                        tool="",
                    )
                )
                return "", False, False, "m1", False
            return "done", True, True, "m1", False

        with (
            patch("backend.ai.autopilot.get_llm_provider", return_value=provider),
            patch("backend.ai.autopilot.build_recon_context", return_value=""),
            patch("backend.ai.autopilot.generate_report", return_value="# r"),
            patch("backend.ai.pilot_helpers.preflight_commands", return_value=[]),
            patch("backend.ai.autopilot.get_or_create_surface", return_value=surface),
            patch("backend.ai.autopilot.load_surface", return_value=surface),
            patch("backend.ai.autopilot.save_surface"),
            patch(
                "backend.ai.autopilot.advance_surface_phase",
                return_value=(
                    surface,
                    MagicMock(advanced=False, phase="vuln_scan", reason="", can_finish=False),
                ),
            ),
            patch("backend.ai.autopilot._run_autonomous_cycle", side_effect=cycle),
            patch(
                "backend.executor.tool_presence.looks_like_missing_binary",
                return_value=True,
            ),
            patch("backend.executor.tool_presence.mark_tool_unavailable") as mark,
            patch(
                "backend.ai.autopilot.run_verification_pipeline",
                side_effect=RuntimeError("verify-down"),
            ),
            patch(
                "backend.ai.autopilot.findings_for_report",
                return_value={
                    "confirmed": [],
                    "false_positive": [],
                    "discarded": [],
                    "candidate": [],
                },
            ),
            patch("backend.ai.autopilot.MAX_AUTONOMOUS_ROUNDS", 2),
        ):
            res = run_autonomous(
                "hud5l.test",
                "mapear",
                mission_id="hud-5l",
                scan_profile="basic",
                emit=lambda e, d: events.append((e, d)),
            )
        self.assertTrue(res.message)
        mark.assert_called()
        self.assertTrue(any(e == "finding_update" for e, _ in events))


if __name__ == "__main__":
    unittest.main()
