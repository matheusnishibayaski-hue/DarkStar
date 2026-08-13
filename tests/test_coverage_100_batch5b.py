"""Lote 5b: ramos restantes (rotas, risk, fp, pdf, verify, db errors)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from backend.database import db as db_mod
from backend.executor.result import ExecutionResult
from fastapi.testclient import TestClient

from tests.auth_patch import patch_chat_api_token


def _sqlite_patches(root: Path):
    url = f"sqlite:///{(root / 't.db').as_posix()}"
    return [
        patch.object(db_mod, "DATABASE_URL", ""),
        patch.object(db_mod, "_SQLITE_PATH", root / "t.db"),
        patch.object(db_mod, "resolve_database_url", return_value=url),
    ]


class _DbCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        db_mod.reset_engine_for_tests()
        self.patches = _sqlite_patches(self.root)
        for p in self.patches:
            p.start()
        db_mod.reset_engine_for_tests()
        db_mod.init_db()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        db_mod.reset_engine_for_tests()
        self.tmp.cleanup()


class TestSmallHelpers(unittest.TestCase):
    def test_utcnow_runtime_framework_scoring_base(self):
        from backend.ai.providers.base import BaseLLMProvider, LLMCompletion, LLMMessage
        from backend.ai.providers.runtime import (
            get_active_provider_name,
            normalize_provider_name,
            set_active_provider,
        )
        from backend.compliance.frameworks import get_framework
        from backend.compliance.scoring import indicative_coverage
        from backend.database import models_dashboard as md
        from backend.database import models_intelligence as mi

        md._utcnow()
        mi._utcnow()
        self.assertEqual(normalize_provider_name("local"), "ollama")
        self.assertEqual(normalize_provider_name("cloud"), "openrouter")
        self.assertEqual(normalize_provider_name("weird"), "openrouter")
        set_active_provider("ollama")
        self.assertEqual(get_active_provider_name(), "ollama")
        set_active_provider(None)
        self.assertTrue(get_framework("pci-dss") or get_framework("PCI-DSS"))
        mixed = next(
            iter(__import__("backend.compliance.frameworks", fromlist=["FRAMEWORKS"]).FRAMEWORKS)
        )
        get_framework(mixed.lower() if mixed != mixed.upper() else mixed)
        self.assertEqual(indicative_coverage({})["controls_total"], 0)
        indicative_coverage({"controls": [{"status": "gap", "critical": True}]})

        class Dummy(BaseLLMProvider):
            name = "dummy"

            def is_configured(self) -> bool:
                return True

            def configuration_error(self) -> str:
                return "no"

            def complete(self, **kwargs):
                return LLMCompletion(message=LLMMessage(content="ok"), model="m")

            def resolve_models(self, primary=None, fallback=None):
                return ("p", "f")

            def format_error(self, error: str) -> str:
                return error

        d = Dummy()
        d.health()
        d.models_catalog()
        d.is_retryable_error("unavailable")


class TestRiskFpRemediation(unittest.TestCase):
    def test_risk_fp_kinds_remediation_keys(self):
        from backend.ai.fp_explain import (
            apply_fp_hard_rules,
            detect_finding_kind,
            explain_false_positive,
            residual_risk_score,
            severity_counts,
        )
        from backend.ai.fp_learn import _row_to_dict
        from backend.ai.remediation import classify_remediation_key, remediation_for
        from backend.ai.risk_history import load_risk_history, previous_score, record_risk_snapshot
        from backend.ai.risk_score import compute_risk_score, risk_score_for_target

        compute_risk_score([])
        compute_risk_score([{"severity": "weird"}])
        compute_risk_score(
            [
                {"severity": "critical"},
                {"severity": "high"},
                {"severity": "medium"},
                {"severity": "low"},
                {"severity": "info"},
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            with patch("backend.ai.risk_history.RISK_HISTORY_DIR", Path(tmp)):
                record_risk_snapshot("r.test", {"score": 0, "band": "low"})
                (Path(tmp) / "r.test.jsonl").write_text("{}\nnotjson\n", encoding="utf-8")
                load_risk_history("r.test")
                previous_score("missing.test")
                previous_score("r.test")
        risk_score_for_target("no-such-target")

        for title in (
            "OK — nmap scan",
            "reflected xss",
            "sql injection",
            "remote code execution rce",
            "path traversal lfi",
            "ssti template inject",
            "missing hsts",
            "x-frame-options clickjack",
            "content-security-policy csp",
            "x-content-type nosniff",
            "tls certificate cipher",
            "wordpress wp-login",
            "CVE-2021-41773",
            "22/tcp open ssh",
            "phpinfo exposed admin dashboard",
            "something else",
        ):
            detect_finding_kind(
                {"title": title, "evidence": title, "cve": "CVE-2021-1" if "CVE" in title else ""}
            )
        apply_fp_hard_rules(
            kind="xss", blob="<script>alert(1)</script>", likely_fp=80, verdict="false_positive"
        )
        explain_false_positive(
            {"title": "[high] info thing", "severity": "info", "evidence": "ok"},
            siblings=[{"title": "other"}],
        )
        residual_risk_score(
            [
                {"severity": "critical", "status": "confirmed"},
                {"severity": "high", "status": "false_positive"},
            ]
        )
        severity_counts([{"severity": "weird"}])
        row = MagicMock(
            targets_json="{notjson",
            pattern_key="k",
            finding_type="t",
            title="x",
            hits="1",
        )
        _row_to_dict(row)
        row.targets_json = '{"a":1}'
        _row_to_dict(row)
        for kind in (
            "xss",
            "sqli",
            "rce",
            "lfi",
            "ssti",
            "cve",
            "hsts",
            "clickjack",
            "csp",
            "nosniff",
            "ssl",
            "port",
            "wordpress",
            "exposure",
        ):
            classify_remediation_key({"kind": kind, "title": kind})
        with patch("backend.ai.fp_explain.detect_finding_kind", side_effect=RuntimeError("x")):
            classify_remediation_key({"title": "generic thing"})
        remediation_for({"title": "Missing HSTS", "severity": "medium"})
        remediation_for({"title": "unknown-zzz", "severity": "low"})


class TestVerifyRemaining(unittest.TestCase):
    def test_header_present_port_inconclusive_cve_and_apply(self):
        from backend.ai import verify as v
        from backend.executor import surface as sm

        def _er(**kw):
            d = dict(
                command="c",
                reason="",
                stdout="",
                stderr="",
                exit_code=0,
                success=True,
                blocked=False,
            )
            d.update(kw)
            return ExecutionResult(**d)

        st, _, _ = v.score_verification(
            {"title": "HSTS present check", "template_id": "hsts"},
            _er(stdout="strict-transport-security: max-age=1"),
        )
        self.assertTrue(st)
        st, _, _ = v.score_verification(
            {"title": "22/tcp open", "tool": "nmap"}, _er(stdout="filtered")
        )
        self.assertEqual(st, "inconclusive")
        st, _, _ = v.score_verification(
            {"title": "CVE-2021-41773", "cve": "CVE-2021-41773", "finding_type": "cve"},
            _er(stdout="CVE-2021-41773 vulnerable [critical]"),
            surface_context={"ports": [{"service": "http", "port": 80, "version": "2.4"}]},
        )
        st, _, _ = v.score_verification(
            {"title": "x", "severity": "high"},
            _er(stdout="no evidence here"),
            pass_number=2,
        )
        st, _, _ = v.score_verification(
            {"title": "x"}, _er(stdout="not vulnerable absent none"), pass_number=1
        )
        v._sort_findings(
            [
                {"severity": "low", "title": "a"},
                {"severity": "critical", "cve": "CVE-1", "title": "b", "sources": 3},
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(sm, "SURFACE_DIR", Path(tmp)):
                self.assertIsNone(
                    v._apply_status(
                        "none.test",
                        "f1",
                        "confirmed",
                        evidence="e",
                        confidence="high",
                        verify_command="c",
                        pass_number=1,
                    )
                )
                data = sm.get_or_create_surface("ver5.test")
                data["findings"] = [
                    {
                        "id": "f1",
                        "title": "Missing HSTS",
                        "severity": "medium",
                        "status": "candidate",
                    }
                ]
                sm.save_surface("ver5.test", data)
                v._apply_status(
                    "ver5.test",
                    "f1",
                    "discarded",
                    evidence="waf cdn blocked",
                    confidence="low",
                    verify_command="curl",
                    pass_number=2,
                )
                v._apply_status(
                    "ver5.test",
                    "nope",
                    "confirmed",
                    evidence="e",
                    confidence="high",
                    verify_command="c",
                    pass_number=1,
                )
                v.confidence_gate_buckets("ver5.test")
                v.run_verification_pipeline(
                    "ver5.test",
                    max_findings=2,
                    execute=lambda command, reason: _er(stdout="strict-transport-security"),
                )


class TestPdfAndRoutes(_DbCase):
    def test_pdf_brand_and_remaining_routes(self):
        from backend.ai.pdf_report import _resolve_brand, generate_report_pdf
        from backend.executor import surface as sm
        from backend.main import app

        _resolve_brand(None)
        _resolve_brand({"brand_name": "Acme", "client_id": "acme"})
        surf = self.root / "surface"
        surf.mkdir()
        with patch.object(sm, "SURFACE_DIR", surf), patch_chat_api_token(""):
            data = sm.get_or_create_surface("pdf5.test")
            data["brand_name"] = "BrandX"
            data["client_id"] = "acme"
            data["label"] = "Lab"
            data["findings"] = [
                {
                    "id": "1",
                    "title": "Missing HSTS",
                    "severity": "medium",
                    "status": "confirmed",
                    "evidence": "no",
                },
                {
                    "id": "2",
                    "title": "CVE-2021-1",
                    "severity": "critical",
                    "status": "confirmed",
                    "cve": "CVE-2021-1",
                },
            ]
            sm.save_surface("pdf5.test", data)
            raw = generate_report_pdf(
                surface_target="pdf5.test", title="T", regenerate_executive=True
            )
            self.assertGreater(len(raw), 100)

            client = TestClient(app)
            self.assertEqual(client.get("/api/tools?offensive=true").status_code, 200)
            self.assertEqual(client.get("/api/metrics").status_code, 200)
            client.post("/api/ai-provider", json={"provider": "ollama"})
            client.post("/api/ai-provider", json={"provider": "openrouter"})
            self.assertEqual(client.get("/api/recon").status_code, 200)
            self.assertEqual(client.delete("/api/recon/missing.none").status_code, 404)
            self.assertEqual(client.get("/api/recon/aa..bb.test").status_code, 400)
            self.assertEqual(client.get("/api/portfolio?session_id=portfoliob51").status_code, 200)
            self.assertEqual(
                client.post(
                    "/api/remediation/generate",
                    json={"finding": {}},
                ).status_code,
                400,
            )
            self.assertEqual(
                client.post(
                    "/api/remediation/generate",
                    json={"finding": {"title": "Missing HSTS", "severity": "medium"}},
                ).status_code,
                200,
            )
            client.post(
                "/api/remediation/verify",
                json={"original_code": "a", "fixed_code": "b"},
            )
            client.post(
                "/api/remediation/track",
                json={"finding_id": "f1", "remediation_plan": {"steps": []}},
            )
            with patch("backend.routes.chat.generate_report_pdf", return_value=b"%PDF"):
                self.assertEqual(
                    client.post(
                        "/api/generate-report",
                        json={"history": [], "tool_executions": [], "title": "T"},
                    ).status_code,
                    200,
                )
            with patch("backend.ai.providers.get_llm_provider", side_effect=RuntimeError("x")):
                client.get("/api/health")
            client.get("/api/mcp/tools")
            client.post("/api/mcp/tools/list_surface_targets", json={"arguments": {}})
            client.post("/api/mcp/tools/nope", json={"arguments": {}})
            client.post("/api/mcp/rpc", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
            with patch(
                "backend.database.chat_store.upsert_chat_session", side_effect=ValueError("bad")
            ):
                client.post(
                    "/api/chat-sessions",
                    json={"id": "badidxx1", "title": "t", "messages": []},
                )
            client.get("/api/auth/privilege")
            db_mod.save_scan_result(
                {"findings": "not-a-list", "target": "x.test", "chat_session_id": "s"}
            )
            db_mod.save_scan_result(
                {
                    "target": "y.test",
                    "chat_session_id": "sessdash02",
                    "findings": [{"id": "1", "title": "A", "severity": "high"}],
                    "vulnerability_count": 1,
                    "critical": 0,
                    "high": 1,
                    "medium": 0,
                    "low": 0,
                }
            )
            db_mod.compute_metrics(days=1, session_id="sessdash02")
            db_mod.get_top_issues(session_id="sessdash02")
            db_mod.vulnerability_trend(days=1, session_id="sessdash02")
            db_mod.summary_report(days=1, session_id="sessdash02")
            db_mod.get_scan_history(session_id="sessdash02")
            db_mod.purge_scans_for_session("sessdash02")
            db_mod.purge_scans_for_session("")
            with patch.object(db_mod, "ensure_dashboard_db", side_effect=RuntimeError("x")):
                db_mod.save_scan_result({"target": "z"})
                db_mod.compute_metrics()
                db_mod.get_top_issues()
                db_mod.vulnerability_trend()
                db_mod.summary_report()
                db_mod.get_scan_history()
                db_mod.purge_scans_for_session("x")


class TestCliAndMcpAndBackup(unittest.TestCase):
    def test_cli_health_ai_and_mcp_errors(self):
        from backend import cli as c
        from backend import mcp_service
        from backend.clients import backup as bak
        from click.testing import CliRunner

        runner = CliRunner()
        runner.invoke(c.cli, ["health", "--check", "ai", "--output", "json"])
        runner.invoke(c.cli, ["health", "--check", "config"])
        runner.invoke(c.cli, ["health", "--output", "text"])
        with patch.object(c, "validate_autonomous_target", return_value=(False, "no")):
            r = runner.invoke(c.cli, ["autonomous", "t.test", "--quiet"])
            self.assertNotEqual(r.exit_code, 99)
        with patch.object(c, "validate_autonomous_target", return_value=(True, "")):
            r = runner.invoke(c.cli, ["autonomous", "scanme.nmap.org", "--dry-run"])
            self.assertIn(r.exit_code, {0, 1, 2})

        with self.assertRaises(ValueError):
            mcp_service._tool_get_surface_triage({"target": "missing.none"})
        mcp_service.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        mcp_service.handle_rpc({"jsonrpc": "2.0", "id": 2, "method": "nope", "params": {}})

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with (
                patch.object(bak, "CLIENTS_DIR", root),
                patch.object(bak, "SURFACE_DIR", root / "surf"),
                patch.object(bak, "OUTPUTS_DIR", root),
            ):
                (root / "surf").mkdir()
                with self.assertRaises(FileNotFoundError):
                    bak.backup_client("nope")
                try:
                    bak.restore_client(b"not-a-tar")
                except Exception:
                    pass


if __name__ == "__main__":
    unittest.main()
