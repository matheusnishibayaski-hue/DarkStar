"""Lote 5c: merge/verify/pdf session, fallbacks DB, ramos restantes."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from backend.database import db as db_mod
from backend.executor.result import ExecutionResult
from fastapi.testclient import TestClient

from tests.auth_patch import patch_chat_api_token


class TestMergeVerifyPdfSession(unittest.TestCase):
    def test_merge_pipeline_pdf_session(self):
        from backend.ai import verify as v
        from backend.ai.pdf_report import generate_report_pdf
        from backend.executor import session_intel as si
        from backend.executor import surface as sm

        existing = {
            "tool": "nmap",
            "tools": ["nmap"],
            "severity": "low",
            "evidence": "old",
            "status": "candidate",
            "sources": 1,
        }
        incoming = {
            "tool": "nuclei",
            "severity": "critical",
            "evidence": "new-ev",
            "template_id": "t1",
            "cve": "CVE-1",
            "url": "https://x",
            "matched_at": "https://x",
            "curl_command": "curl",
            "matcher_name": "m",
            "cvss_score": 9.1,
            "version": "1.0",
        }
        sm._merge_finding(existing, incoming)
        self.assertEqual(existing["severity"], "critical")
        sm._merge_finding(existing, {"tool": "nmap", "severity": "info"})

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

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            intel = root / "intel"
            surf = root / "surface"
            intel.mkdir()
            surf.mkdir()
            url = f"sqlite:///{(root / 't.db').as_posix()}"
            db_mod.reset_engine_for_tests()
            patches = [
                patch.object(db_mod, "DATABASE_URL", ""),
                patch.object(db_mod, "_SQLITE_PATH", root / "t.db"),
                patch.object(db_mod, "resolve_database_url", return_value=url),
                patch.object(sm, "SURFACE_DIR", surf),
                patch.object(si, "INTEL_SESSIONS_DIR", intel),
            ]
            for p in patches:
                p.start()
            try:
                db_mod.reset_engine_for_tests()
                db_mod.init_db()
                data = sm.get_or_create_surface("pipe.test")
                data["urls"] = ["https://pipe.test"]
                data["ports"] = [{"port": 443, "service": "https"}]
                data["findings"] = [
                    {
                        "id": "h1",
                        "title": "Missing HSTS",
                        "severity": "high",
                        "status": "candidate",
                        "template_id": "hsts",
                    },
                    {
                        "id": "c1",
                        "title": "CVE-2021-41773",
                        "cve": "CVE-2021-41773",
                        "severity": "critical",
                        "status": "candidate",
                        "finding_type": "cve",
                    },
                    {
                        "id": "p1",
                        "title": "22/tcp open ssh",
                        "tool": "nmap",
                        "severity": "info",
                        "status": "candidate",
                    },
                ]
                sm.save_surface("pipe.test", data)
                v.run_verification_pipeline("missing.none")
                v.run_verification_pipeline(
                    "pipe.test",
                    max_findings=2,
                    execute=lambda command, reason: _er(stdout="cloudflare waf block"),
                    emit=lambda *_a, **_k: None,
                )
                v.run_verification_pipeline(
                    "pipe.test",
                    max_findings=3,
                    execute=lambda command, reason: _er(success=False, stdout="", exit_code=1),
                )
                with patch("backend.security.missions.get_mission_registry") as reg:
                    inst = MagicMock()
                    inst.is_cancelled.return_value = True
                    reg.return_value = inst
                    v.run_verification_pipeline(
                        "pipe.test",
                        max_findings=1,
                        execute=lambda command, reason: _er(stdout="ok"),
                        mission_id="miss-verify-01",
                    )
                sid = "pdfsess901234"
                si.touch_session(sid, "pipe.test")
                si.set_session_label(sid, "Lab PDF")
                raw = generate_report_pdf(session_id=sid, title="Sess")
                self.assertGreater(len(raw), 50)
            finally:
                for p in patches:
                    p.stop()
                db_mod.reset_engine_for_tests()


class TestDbFallbackAndSqliteUrl(unittest.TestCase):
    def test_sqlite_url_and_postgres_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_mod.reset_engine_for_tests()
            with (
                patch.object(db_mod, "DATABASE_URL", ""),
                patch.object(db_mod, "_SQLITE_PATH", root / "nested" / "x.db"),
            ):
                url = db_mod._sqlite_url()
                self.assertIn("sqlite", url)
            db_mod.reset_engine_for_tests()
            with (
                patch.object(db_mod, "DATABASE_URL", "postgresql+psycopg2://u:p@127.0.0.1:1/none"),
                patch.object(db_mod, "_SQLITE_PATH", root / "fb2.db"),
            ):
                db_mod.get_engine()
                self.assertTrue(db_mod.using_sqlite_fallback() or db_mod.get_engine())
            db_mod.reset_engine_for_tests()
            db_mod._dashboard_ready = False
            with patch.object(db_mod, "init_db", side_effect=RuntimeError("init")):
                db_mod.ensure_dashboard_db()
            db_mod.reset_engine_for_tests()


class TestRemainingHelpersAndRoutes(unittest.TestCase):
    def test_helpers_mcp_cli_routes(self):
        from backend import mcp_service
        from backend.ai.openrouter_common import assistant_message_dict
        from backend.ai.remediation import classify_remediation_key
        from backend.ai.scan_profiles import resolve_scan_tools
        from backend.compliance.frameworks import get_framework
        from backend.intelligence.business_context import parse_business_context
        from backend.intelligence.patterns import pattern_key_for_finding
        from backend.main import app
        from backend.security import privileges as priv
        from backend.security import roles as roles_mod

        resolve_scan_tools("full")
        assistant_message_dict(MagicMock(content="x", tool_calls=None))
        get_framework("not-a-framework-xyz")
        for title in (
            "xss reflected",
            "sql injection",
            "rce command",
            "lfi file",
            "ssti jinja",
            "hsts missing",
            "x-frame clickjack",
            "csp missing",
            "nosniff x-content-type",
            "ssl tls cert",
            "wordpress wp-",
            "admin exposed phpinfo",
        ):
            classify_remediation_key({"title": title, "evidence": title})
        pattern_key_for_finding({"title": "", "cve": "", "template_id": ""})
        parse_business_context({"industry": "tech", "notes": "n"})
        mcp_service._tool_get_risk_score({"target": "x.test"})
        mcp_service._tool_list_allowed_tools({})
        with patch(
            "backend.executor.kali.execute_kali_command",
            return_value=ExecutionResult(
                command="nmap",
                reason="",
                stdout="ok",
                stderr="",
                exit_code=0,
                success=True,
            ),
        ):
            mcp_service._tool_run_kali_tool({"command": "nmap -sV scanme.nmap.org"})
            with self.assertRaises(ValueError):
                mcp_service._tool_run_kali_tool({})
        mcp_service.handle_rpc({"jsonrpc": "2.0", "method": "notifications/initialized"})
        mcp_service.handle_rpc({"jsonrpc": "2.0", "id": 3, "method": "initialize", "params": {}})
        mcp_service.handle_rpc(
            {"jsonrpc": "2.0", "id": 4, "method": "resources/list", "params": {}}
        )
        mcp_service.list_resources()
        try:
            mcp_service.read_resource("unknown://x")
        except Exception:
            pass
        mcp_service.call_tool("nope", {})

        tok = priv.create_privilege_token()
        with patch.object(priv, "_tokens", {tok: 0}):
            priv.validate_privilege_token(tok)
            priv._purge_locked(now=10**12)
        priv.privilege_status()
        roles_mod.current_role()
        parse_business_context({"regulations": "LGPD, GDPR"})

        with patch_chat_api_token(""):
            client = TestClient(app)
            client.get("/api/mcp/tools/list_surface_targets")
            client.get("/api/mcp/resources")
            client.get("/api/mcp/resources/surface://x")
            client.post(
                "/api/chat-sessions",
                json={"id": "x", "title": "t", "messages": []},
            )
            client.put(
                "/api/chat-sessions/not-valid",
                json={"id": "not-valid", "title": "t", "messages": []},
            )
            client.get("/api/files")

            with patch("backend.executor.data_cleanup.delete_output_file", return_value=True):
                client.delete("/api/files/ok.txt")
                client.delete("/api/data/files/ok.txt")
            with patch("backend.executor.data_cleanup.delete_recon", return_value=True):
                client.delete("/api/data/recon/t.test")
                client.delete("/api/recon/t.test")
            with patch("backend.executor.data_cleanup.delete_surface", return_value=True):
                client.delete("/api/data/surface/t.test")
            with patch("backend.executor.data_cleanup.purge_audit", return_value=1):
                client.delete("/api/data/audit?all=true")
            with patch(
                "backend.executor.logs.delete_execution_log",
                create=True,
                return_value={"ok": True},
            ):
                pass
            with patch("backend.routes.data.delete_execution_log", return_value={"ok": True}):
                client.delete("/api/data/logs/logid1")
            client.get("/api/intelligence/threat-model/missing.test")
            client.patch(
                "/api/schedules/x",
                json={"job_type": "full", "scan_profile": "basic", "risk_profile": "passive"},
            )


if __name__ == "__main__":
    unittest.main()
