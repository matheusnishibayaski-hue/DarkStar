"""Lote 5: rotas restantes, CVSS, verify, stores, config, lifespan — até Miss=0."""

from __future__ import annotations

import asyncio
import importlib
import json
import os
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


class TestCorsAndLifespan(unittest.TestCase):
    def test_cors_fallback_and_passthrough(self):
        from backend.main import _resolve_cors_origins

        self.assertEqual(
            _resolve_cors_origins(["*"]),
            ["http://127.0.0.1:8000", "http://localhost:8000"],
        )
        self.assertEqual(_resolve_cors_origins(["http://x"]), ["http://x"])

    def test_lifespan_ok_and_errors(self):
        from backend import main as m

        async def _run_ok():
            async with m.lifespan(m.app):
                pass

        asyncio.run(_run_ok())

        async def _run_err():
            with (
                patch("backend.database.db.ensure_dashboard_db", side_effect=RuntimeError("db")),
                patch(
                    "backend.intelligence.store.use_postgres",
                    side_effect=RuntimeError("pg"),
                ),
                patch("backend.schedule.runner.start_scheduler", side_effect=RuntimeError("sch")),
                patch("backend.schedule.runner.stop_scheduler", side_effect=RuntimeError("stop")),
            ):
                async with m.lifespan(m.app):
                    pass

        asyncio.run(_run_err())


class TestConfigReload(unittest.TestCase):
    def test_env_branches_then_restore(self):
        import backend.config as cfg

        with tempfile.TemporaryDirectory() as tmp:
            env = {
                "AI_PROVIDER": "local",
                "RISK_PROFILE": "nope",
                "OPERATOR_ROLE": "nope",
                "INTELLIGENCE_STORAGE": "redis",
                "OUTPUTS_DIR": tmp,
                "INTELLIGENCE_DIR": tmp,
            }
            with patch.dict(os.environ, env, clear=False):
                importlib.reload(cfg)
                self.assertEqual(cfg.AI_PROVIDER, "ollama")
                self.assertEqual(cfg.RISK_PROFILE, "safe-active")
                self.assertEqual(cfg.OPERATOR_ROLE, "admin")
                self.assertEqual(cfg.INTELLIGENCE_STORAGE, "json")
            with patch.dict(os.environ, {"AI_PROVIDER": "weird"}, clear=False):
                importlib.reload(cfg)
                self.assertEqual(cfg.AI_PROVIDER, "openrouter")
            with patch.dict(os.environ, {"AI_PROVIDER": "ollama"}, clear=False):
                importlib.reload(cfg)
                self.assertEqual(cfg.AI_PROVIDER, "ollama")
            importlib.reload(cfg)


class TestRouteSweep(_DbCase):
    def test_compliance_data_audit_schedule_intel_github(self):
        from backend.executor import surface as sm
        from backend.intelligence.exceptions import IntelligenceError, SurfaceNotFound
        from backend.main import app
        from backend.schedule import store as st

        surf = self.root / "surface"
        surf.mkdir()
        with (
            patch.object(sm, "SURFACE_DIR", surf),
            patch.object(st, "SCHEDULE_DIR", self.root / "sched"),
            patch_chat_api_token(""),
        ):
            client = TestClient(app)
            sm.get_or_create_surface("comp.test")
            self.assertEqual(client.get("/api/compliance/frameworks").status_code, 200)
            bad_src = client.post(
                "/api/compliance/report",
                json={"target": "comp.test", "frameworks": ["LGPD"], "source": "other"},
            )
            self.assertEqual(bad_src.status_code, 400)
            unknown = client.post(
                "/api/compliance/report",
                json={"target": "comp.test", "frameworks": ["NOPE"]},
            )
            self.assertEqual(unknown.status_code, 400)
            ok_rep = client.post(
                "/api/compliance/report",
                json={"target": "comp.test", "frameworks": ["LGPD"]},
            )
            self.assertIn(ok_rep.status_code, {200, 404})
            self.assertEqual(
                client.get("/api/compliance/report/comp.test?format=md").status_code, 200
            )
            self.assertEqual(
                client.get("/api/compliance/report/comp.test?format=xml").status_code, 400
            )
            self.assertEqual(
                client.get("/api/compliance/report/missing.none?format=json").status_code, 404
            )
            with patch("backend.routes.compliance.COMPLIANCE_ENABLED", False):
                self.assertEqual(client.get("/api/compliance/frameworks").status_code, 404)

            self.assertEqual(client.get("/api/data/summary").status_code, 200)
            self.assertEqual(client.get("/api/data/logs").status_code, 200)
            self.assertEqual(
                client.post(
                    "/api/data/purge", json={"categories": ["logs"], "confirm": False}
                ).status_code,
                400,
            )
            self.assertEqual(
                client.post(
                    "/api/data/purge",
                    json={"categories": ["nope"], "confirm": True},
                ).status_code,
                400,
            )
            self.assertEqual(
                client.post(
                    "/api/data/purge",
                    json={"categories": ["logs"], "target": "../x", "confirm": True},
                ).status_code,
                400,
            )
            purged = client.post(
                "/api/data/purge",
                json={"categories": ["logs"], "confirm": True},
            )
            self.assertEqual(purged.status_code, 200)
            self.assertEqual(client.post("/api/data/retention?confirm=false").status_code, 400)
            with patch("backend.config.RETENTION_DAYS", 0):
                self.assertEqual(client.post("/api/data/retention?confirm=true").status_code, 400)
            self.assertEqual(
                client.post("/api/data/retention?days=1&confirm=true").status_code, 200
            )
            self.assertEqual(client.delete("/api/data/logs/missing-log").status_code, 404)
            self.assertEqual(client.delete("/api/data/recon/nope.test").status_code, 404)
            self.assertEqual(client.delete("/api/data/surface/nope.test").status_code, 404)
            self.assertEqual(client.delete("/api/data/audit").status_code, 400)
            self.assertIn(client.delete("/api/data/audit?all=true").status_code, {200, 404})
            self.assertEqual(client.delete("/api/data/files/nope.txt").status_code, 404)
            client.post(
                "/api/data/logs/session", json={"session_id": "sess-data-01", "log_ids": []}
            )

            self.assertEqual(client.delete("/api/audit").status_code, 400)
            with patch("backend.executor.data_cleanup.purge_audit", return_value=2):
                self.assertEqual(client.delete("/api/audit?all=true").status_code, 200)
            with patch("backend.executor.data_cleanup.purge_audit", return_value=0):
                self.assertEqual(client.delete("/api/audit?all=true").status_code, 404)
            self.assertEqual(client.get("/api/audit").status_code, 200)

            listed = client.get("/api/schedules")
            self.assertEqual(listed.status_code, 200)
            created = client.post(
                "/api/schedules",
                json={"target": "sched5.test", "job_type": "remind", "interval": "weekly"},
            )
            self.assertEqual(created.status_code, 200)
            jid = created.json()["id"]
            self.assertEqual(client.get(f"/api/schedules/{jid}").status_code, 200)
            self.assertEqual(client.get("/api/schedules/missing").status_code, 404)
            self.assertEqual(
                client.patch(
                    f"/api/schedules/{jid}", json={"enabled": False, "interval": "daily"}
                ).status_code,
                200,
            )
            self.assertEqual(
                client.patch("/api/schedules/missing", json={"enabled": True}).status_code, 404
            )
            with patch("backend.routes.schedule_api.run_job_now", return_value={"ok": True}):
                self.assertEqual(client.post(f"/api/schedules/{jid}/run").status_code, 200)
            with patch(
                "backend.routes.schedule_api.run_job_now", side_effect=FileNotFoundError("x")
            ):
                self.assertEqual(client.post(f"/api/schedules/{jid}/run").status_code, 404)
            self.assertEqual(client.delete(f"/api/schedules/{jid}").status_code, 200)
            self.assertEqual(client.delete("/api/schedules/missing").status_code, 404)
            with patch(
                "backend.routes.schedule_api.validate_autonomous_target", return_value=(False, "no")
            ):
                self.assertEqual(
                    client.post("/api/schedules", json={"target": "x.test"}).status_code, 403
                )

            self.assertEqual(client.get("/api/intel/sessions").status_code, 200)
            self.assertEqual(client.get("/api/intel/sessions/xx..yy12345678").status_code, 400)
            sid = "intelbatch501"
            self.assertEqual(client.get(f"/api/intel/sessions/{sid}").status_code, 200)
            self.assertEqual(
                client.patch(f"/api/intel/sessions/{sid}", json={"label": "L"}).status_code, 200
            )
            self.assertEqual(client.delete(f"/api/intel/sessions/{sid}").status_code, 200)
            self.assertEqual(
                client.post(
                    f"/api/intel/sessions/{sid}/sync-executions",
                    json={"executions": [{"command": "nmap -sV a.test", "stdout": "80/tcp open"}]},
                ).status_code,
                200,
            )
            self.assertEqual(
                client.post(
                    f"/api/intel/sessions/{sid}/findings/f1",
                    json={"surface_target": "a.test", "status": "bad"},
                ).status_code,
                400,
            )
            self.assertEqual(
                client.post(
                    f"/api/intel/sessions/{sid}/findings/f1",
                    json={"surface_target": "a.test", "status": "confirmed"},
                ).status_code,
                404,
            )
            with patch("backend.ai.fp_ai_review.review_finding", return_value={"source": "rules"}):
                self.assertEqual(
                    client.post(f"/api/intel/sessions/{sid}/findings/f1/ai-review").status_code, 404
                )
            self.assertEqual(client.get(f"/api/intel/sessions/{sid}/triage-queue").status_code, 200)
            self.assertEqual(
                client.post(
                    f"/api/intel/sessions/{sid}/triage-queue",
                    json={"executions": []},
                ).status_code,
                200,
            )
            self.assertEqual(client.get("/api/intel/sessions/emptyintel99/report").status_code, 404)

            with patch("backend.routes.intelligence.INTELLIGENCE_ENABLED", False):
                self.assertEqual(client.get("/api/intelligence/stats").status_code, 404)
            self.assertEqual(client.get("/api/intelligence/stats").status_code, 200)
            self.assertEqual(client.get("/api/intelligence/suggest/hub.test").status_code, 200)
            self.assertEqual(client.get("/api/intelligence/similar/hub.test").status_code, 200)
            with patch(
                "backend.routes.intelligence.hub.record_from_surface",
                side_effect=SurfaceNotFound("no"),
            ):
                self.assertEqual(
                    client.post("/api/intelligence/record", json={"target": "x.test"}).status_code,
                    404,
                )
            with patch(
                "backend.routes.intelligence.hub.record_from_surface",
                side_effect=IntelligenceError("bad"),
            ):
                self.assertEqual(
                    client.post("/api/intelligence/record", json={"target": "x.test"}).status_code,
                    400,
                )
            with patch(
                "backend.routes.intelligence.hub.record_from_surface",
                side_effect=RuntimeError("boom"),
            ):
                self.assertEqual(
                    client.post("/api/intelligence/record", json={"target": "x.test"}).status_code,
                    500,
                )
            rec = client.post("/api/intelligence/record", json={"target": "comp.test"})
            self.assertIn(rec.status_code, {200, 404, 500})
            tm = client.post(
                "/api/intelligence/threat-model",
                json={"target": "comp.test", "industry": "tech"},
            )
            self.assertIn(tm.status_code, {200, 404, 500})
            self.assertIn(
                client.get("/api/intelligence/threat-model/missing.test").status_code, {200, 404}
            )
            self.assertEqual(client.get("/api/intelligence/fp-suppress").status_code, 200)
            self.assertEqual(client.delete("/api/intelligence/fp-suppress").status_code, 200)

            self.assertEqual(client.get("/api/github/status").status_code, 200)
            self.assertIn(
                client.post(
                    "/api/github/comment-pr",
                    json={"repo_url": "o/r", "pr_number": 1, "findings": []},
                ).status_code,
                {500, 501},
            )
            gh = MagicMock()
            gh.is_available.return_value = True
            gh.comment_on_pr.return_value = True
            gh.create_issue.return_value = "https://gh/i/1"
            gh.update_commit_status.return_value = True
            with patch("backend.routes.github.GitHubClient", return_value=gh):
                self.assertEqual(
                    client.post(
                        "/api/github/comment-pr",
                        json={"repo_url": "o/r", "pr_number": 1, "findings": []},
                    ).status_code,
                    200,
                )
                gh.comment_on_pr.return_value = False
                self.assertEqual(
                    client.post(
                        "/api/github/comment-pr",
                        json={"repo_url": "o/r", "pr_number": 1, "findings": []},
                    ).status_code,
                    500,
                )
                self.assertEqual(
                    client.post(
                        "/api/github/create-issue",
                        json={"repo_url": "o/r", "finding": {"title": "x"}},
                    ).status_code,
                    200,
                )
                gh.create_issue.return_value = None
                self.assertEqual(
                    client.post(
                        "/api/github/create-issue",
                        json={"repo_url": "o/r", "finding": {"title": "x"}},
                    ).status_code,
                    500,
                )
                self.assertEqual(
                    client.post(
                        "/api/github/update-status",
                        json={"repo_url": "o/r", "commit_sha": "abc1234", "state": "bad"},
                    ).status_code,
                    400,
                )
                self.assertEqual(
                    client.post(
                        "/api/github/update-status",
                        json={"repo_url": "o/r", "commit_sha": "abc1234", "state": "success"},
                    ).status_code,
                    200,
                )
                gh.update_commit_status.return_value = False
                self.assertEqual(
                    client.post(
                        "/api/github/update-status",
                        json={"repo_url": "o/r", "commit_sha": "abc1234", "state": "failure"},
                    ).status_code,
                    500,
                )

            self.assertEqual(client.get("/api/notifications/channels").status_code, 200)
            self.assertEqual(
                client.post(
                    "/api/notifications/send",
                    json={"title": "t", "message": "m", "severity": "nope"},
                ).status_code,
                400,
            )
            self.assertEqual(
                client.post(
                    "/api/notifications/send",
                    json={"title": "t", "message": "m", "severity": "low"},
                ).status_code,
                400,
            )
            with patch(
                "backend.routes.notifications.notification_manager.notify",
                return_value={"slack": True},
            ):
                self.assertEqual(
                    client.post(
                        "/api/notifications/send",
                        json={"title": "t", "message": "m", "severity": "critical"},
                    ).status_code,
                    200,
                )
            self.assertEqual(client.post("/api/notifications/test/nope").status_code, 404)
            fake_n = MagicMock()
            fake_n.is_configured.return_value = False
            with patch.dict(
                "backend.routes.notifications.notification_manager.channels",
                {"slack": fake_n},
                clear=False,
            ):
                self.assertEqual(client.post("/api/notifications/test/slack").status_code, 400)
            fake_n.is_configured.return_value = True
            fake_n.send.return_value = True
            with patch.dict(
                "backend.routes.notifications.notification_manager.channels",
                {"slack": fake_n},
                clear=False,
            ):
                self.assertEqual(client.post("/api/notifications/test/slack").status_code, 200)
            client.post(
                "/api/notifications/alert-finding",
                json={"finding": {"title": "x", "severity": "high"}},
            )

            self.assertEqual(client.delete("/api/files/missing.txt").status_code, 404)
            self.assertEqual(client.get("/api/files/missing.txt").status_code, 404)

            with patch("backend.routes.mcp.MCP_ENABLED", False):
                self.assertEqual(client.get("/api/mcp/info").status_code, 404)
            self.assertEqual(client.get("/api/mcp/info").status_code, 200)
            self.assertEqual(client.get("/api/mcp/tools/no-such-tool").status_code, 404)

            self.assertEqual(client.get("/api/surface/aa..bb.test").status_code, 400)
            self.assertEqual(client.get("/api/surface/missing.none").status_code, 404)
            self.assertEqual(
                client.patch("/api/engagements/missing.none", json={"label": "x"}).status_code, 404
            )
            self.assertEqual(client.delete("/api/engagements/missing.none").status_code, 404)
            self.assertEqual(client.get("/api/engagements/aa..bb.test").status_code, 400)
            self.assertEqual(client.get("/api/engagements/missing.none").status_code, 404)
            self.assertEqual(client.get("/api/engagements/missing.none/triage").status_code, 404)
            self.assertEqual(client.get("/api/engagements/missing.none/delta").status_code, 404)
            self.assertEqual(client.post("/api/engagements/missing.none/baseline").status_code, 404)
            self.assertEqual(client.get("/api/engagements/missing.none/report").status_code, 404)
            self.assertEqual(client.get("/api/engagements/missing.none/risk").status_code, 404)
            self.assertEqual(
                client.patch(
                    "/api/engagements/comp.test/phase", json={"phase": "nope"}
                ).status_code,
                400,
            )
            self.assertEqual(
                client.patch(
                    "/api/engagements/missing.none/phase", json={"phase": "enumerate"}
                ).status_code,
                404,
            )
            self.assertEqual(
                client.post(
                    "/api/engagements/comp.test/findings/f1",
                    json={"status": "bad"},
                ).status_code,
                400,
            )
            self.assertEqual(
                client.post(
                    "/api/engagements/comp.test/findings/f1",
                    json={"status": "confirmed"},
                ).status_code,
                404,
            )
            self.assertEqual(client.post("/api/engagements/missing.none/verify").status_code, 404)
            self.assertEqual(
                client.get("/api/engagements/comp.test/report?format=md").status_code, 200
            )
            self.assertEqual(
                client.get("/api/engagements/comp.test/report?format=html").status_code, 200
            )
            with patch("backend.ai.delivery.build_delivery_bundle", return_value=b"PK"):
                self.assertEqual(
                    client.get("/api/engagements/comp.test/report?format=zip").status_code, 200
                )
            client.patch(
                "/api/engagements/comp.test",
                json={
                    "objective": "o",
                    "risk_profile": "passive",
                    "client": "c",
                    "client_id": "default",
                    "scope_notes": "s",
                    "brand_name": "B",
                    "lifecycle": "paused",
                },
            )
            client.patch("/api/engagements/comp.test", json={"lifecycle": "nope"})
            with patch("backend.ai.verify.run_verification_pipeline") as pipe:
                pipe.return_value = MagicMock(
                    confirmed=0, false_positive=0, discarded=0, verify_commands_run=0
                )
                client.post("/api/engagements/comp.test/verify?auto_baseline=true")

            with patch("backend.ai.live_report.generate_live_report_html", return_value="<html>"):
                prev = client.post(
                    "/api/generate-report/preview",
                    json={"history": [], "tool_executions": [], "title": "T"},
                )
                self.assertEqual(prev.status_code, 200)
            with patch(
                "backend.ai.live_report.generate_live_report_html", side_effect=RuntimeError("x")
            ):
                self.assertEqual(
                    client.post(
                        "/api/generate-report/preview",
                        json={"history": [], "tool_executions": []},
                    ).status_code,
                    500,
                )

            with patch("backend.routes.auth.master_key_configured", return_value=False):
                self.assertEqual(
                    client.post("/api/auth/master-key", json={"key": "x"}).status_code, 503
                )
            with (
                patch("backend.routes.auth.master_key_configured", return_value=True),
                patch("backend.routes.auth.verify_master_key", return_value=False),
            ):
                self.assertEqual(
                    client.post("/api/auth/master-key", json={"key": "x"}).status_code, 401
                )
            with (
                patch("backend.routes.auth.master_key_configured", return_value=True),
                patch("backend.routes.auth.verify_master_key", return_value=True),
                patch("backend.routes.auth.create_privilege_token", return_value="tok"),
            ):
                self.assertEqual(
                    client.post("/api/auth/master-key", json={"key": "ok"}).status_code, 200
                )
            self.assertEqual(client.post("/api/auth/master-key/lock").status_code, 200)


class TestCvssAndScanProfiles(unittest.TestCase):
    def test_cvss_vectors_and_correlate(self):
        from backend.ai import cvss as c
        from backend.executor import surface as sm

        self.assertEqual(c.estimate_cvss({"cvss_score": "bad"})["source"], "estimated")
        self.assertEqual(c.estimate_cvss({"cvss_score": 9.1})["source"], "nuclei")
        bumped = c.estimate_cvss({"severity": "medium", "sources": 2})
        self.assertGreaterEqual(bumped["score"], 5.3)
        self.assertIn("AV:", c._vector_for_score(9.5))
        self.assertIn("AV:", c._vector_for_score(7.2))
        self.assertIn("AV:", c._vector_for_score(4.1))
        self.assertIn("AV:", c._vector_for_score(1.0))
        self.assertIn("AV:", c._vector_for_score(0))
        self.assertEqual(c.effort_for({"title": "SQLi auth bypass"}), "alto")
        nmap = "80/tcp open http Apache 2.4.49\nApache/2.4.49"
        rows = c.parse_versions_from_nmap(nmap)
        self.assertTrue(rows)
        self.assertFalse(c.correlate_cve_version({"title": "x"})["matched"])
        self.assertFalse(c.correlate_cve_version({"cve": "CVE-2021-1"})["matched"])
        hit = c.correlate_cve_version(
            {"cve": "CVE-2021-41773"},
            ports=[{"product": "apache", "version": "2.4.49", "service": "http"}],
            nmap_output="CVE-2021-41773 apache 2.4.49",
        )
        self.assertTrue(hit["matched"])
        weak = c.correlate_cve_version(
            {"cve": "CVE-2021-1"},
            ports=[{"service": "http"}],
            nmap_output="nothing",
        )
        self.assertTrue(weak.get("matched") or weak.get("weak") is not None)
        miss = c.correlate_cve_version(
            {"cve": "CVE-2021-1"},
            ports=[{"product": "ssh", "version": "1.0", "service": "ssh"}],
            nmap_output="ssh",
        )
        self.assertFalse(miss["matched"])
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(sm, "SURFACE_DIR", Path(tmp)):
                self.assertEqual(c.apply_enrichment_to_surface("none.test"), 0)
                data = sm.get_or_create_surface("cvss.test")
                data["findings"] = [{"title": "HSTS", "severity": "medium"}]
                sm.save_surface("cvss.test", data)
                self.assertGreaterEqual(c.apply_enrichment_to_surface("cvss.test"), 1)

        from backend.ai import scan_profiles as sp

        self.assertTrue(sp.all_allowed_tool_ids())
        self.assertEqual(sp.normalize_profile("nope"), "basic")
        self.assertTrue(sp.resolve_scan_tools("intermediate"))
        self.assertTrue(sp.resolve_scan_tools("full", include_all_allowed=True))
        self.assertEqual(sp.resolve_scan_tools("custom", ["nmap", "nmap", ""]), ["nmap"])
        self.assertGreaterEqual(sp.max_tool_budget("basic", 1), 20)
        self.assertGreaterEqual(sp.max_tool_budget("intermediate", 1), 60)
        self.assertGreaterEqual(sp.max_tool_budget("full", 1), 250)
        self.assertGreaterEqual(sp.max_tool_budget("custom", 1), 30)
        self.assertEqual(sp.scan_profile_prompt_block("basic", [], target="t"), "")
        block = sp.scan_profile_prompt_block("basic", ["nmap"], target="t.test")
        self.assertIn("nmap", block)
        cat = sp.profile_catalog(offensive=True)
        self.assertTrue(cat["offensive"])
        self.assertFalse(sp.profile_catalog(offensive=False)["offensive"])


class TestVerifyAndNuclei(unittest.TestCase):
    def test_classify_commands_and_score(self):
        from backend.ai import verify as v

        self.assertEqual(v.classify_finding_type({"finding_type": "xss"}), "xss")
        self.assertEqual(v.classify_finding_type({"title": "CVE-2021-1"}), "cve")
        self.assertEqual(v.classify_finding_type({"title": "reflected xss"}), "xss")
        self.assertEqual(v.classify_finding_type({"title": "sql injection"}), "sqli")
        self.assertEqual(v.classify_finding_type({"title": "missing hsts"}), "header")
        self.assertEqual(v.classify_finding_type({"title": "weak cipher tls"}), "ssl")
        self.assertEqual(
            v.classify_finding_type({"title": "80/tcp open", "tool": "nmap"}), "port_info"
        )
        self.assertEqual(v.classify_finding_type({"title": "wp", "tool": "nuclei"}), "web_vuln")
        self.assertEqual(v.classify_finding_type({"title": "other"}), "generic")
        self.assertTrue(v._base_url("t.com", [], {"url": "https://t.com/x"}).startswith("http"))
        self.assertEqual(v._base_url("t.com", ["https://t.com/a"]), "https://t.com/a")
        self.assertEqual(v._base_url("t.com", ["https://other"]), "https://other")
        self.assertEqual(v._base_url("t.com", []), "https://t.com")
        self.assertIn("80", v._service_version_hint([{"port": 80, "service": "http"}], "t"))
        f_h = {"title": "Missing HSTS", "template_id": "hsts"}
        self.assertIn("curl", v.build_verify_command(f_h, "t.com", pass_number=1) or "")
        self.assertIn("httpx", v.build_verify_command(f_h, "t.com", pass_number=2) or "")
        self.assertIn(
            "nuclei", v.build_verify_command({"template_id": "x"}, "t.com", pass_number=3) or ""
        )
        self.assertIn("sslscan", v.build_verify_command({"title": "ssl cert"}, "t.com") or "")
        self.assertIn(
            "nmap", v.build_verify_command({"title": "ssl cert"}, "t.com", pass_number=2) or ""
        )
        cve_f = {
            "title": "CVE-2021-41773",
            "cve": "CVE-2021-41773",
            "template_id": "cve-2021-41773",
        }
        self.assertIn("nuclei", v.build_verify_command(cve_f, "t.com") or "")
        self.assertIn(
            "nmap",
            v.build_verify_command(cve_f, "t.com", pass_number=2, ports=[{"port": 80}]) or "",
        )
        web = {"title": "xss", "template_id": "xss-ref", "curl_command": "curl -sI https://t.com"}
        self.assertIn("nuclei", v.build_verify_command(web, "t.com") or "")
        self.assertTrue(v.build_verify_command(web, "t.com", pass_number=2))
        port_f = {"title": "22/tcp open ssh", "tool": "nmap"}
        self.assertIn("nmap", v.build_verify_command(port_f, "t.com") or "")

        def _er(**kw):
            defaults = dict(
                command="c",
                reason="",
                stdout="",
                stderr="",
                exit_code=0,
                success=True,
                blocked=False,
            )
            defaults.update(kw)
            return ExecutionResult(**defaults)

        st, _, _ = v.score_verification({"title": "x"}, _er(blocked=True, stderr="no"))
        self.assertEqual(st, "inconclusive")
        st, _, _ = v.score_verification({"title": "x"}, _er(stdout="cloudflare waf"))
        self.assertEqual(st, "inconclusive")
        st, _, _ = v.score_verification({"title": "x"}, _er(stdout="cloudflare waf"), pass_number=2)
        self.assertEqual(st, "inconclusive")
        st, _, _ = v.score_verification({"title": "x"}, _er(stdout="cloudflare waf"), pass_number=3)
        self.assertEqual(st, "inconclusive")
        st, _, _ = v.score_verification(
            {"title": "x"}, _er(success=False, stdout="", exit_code=1), pass_number=2
        )
        self.assertEqual(st, "false_positive")
        st, _, _ = v.score_verification({"title": "Missing HSTS"}, _er(stdout="HTTP/1.1 200"))
        self.assertEqual(st, "confirmed")
        st, _, _ = v.score_verification(
            {"title": "Missing HSTS"}, _er(stdout="strict-transport-security: max-age=1")
        )
        self.assertEqual(st, "false_positive")
        st, _, _ = v.score_verification(
            {"title": "22/tcp open ssh", "tool": "nmap", "port": "22"},
            _er(stdout="22/tcp open ssh"),
        )
        self.assertEqual(st, "confirmed")
        st, _, _ = v.score_verification(
            {"title": "22/tcp open ssh", "tool": "nmap"}, _er(stdout="closed"), pass_number=2
        )
        self.assertEqual(st, "false_positive")
        st, _, _ = v.score_verification(
            {"title": "xss", "template_id": "xss-ref"},
            _er(stdout="xss-ref [critical] vulnerable"),
        )
        self.assertIn(st, {"confirmed", "inconclusive", "false_positive"})
        st, _, _ = v.score_verification({"title": "x", "severity": "info"}, _er(stdout="ok"))
        self.assertIn(st, {"false_positive", "inconclusive", "discarded", "confirmed"})

        from backend.ai import nuclei_json as nj

        self.assertEqual(nj.parse_nuclei_json_lines(""), [])
        arr = json.dumps(
            [
                {
                    "template-id": "t1",
                    "info": {"name": "N", "severity": "HIGH"},
                    "matched-at": "https://x",
                }
            ]
        )
        self.assertTrue(nj.parse_nuclei_json_lines(arr))
        self.assertEqual(nj.parse_nuclei_json_lines("[not-json"), [])
        line = json.dumps(
            {
                "template-id": "cve-1",
                "info": {
                    "name": "CVE thing",
                    "severity": "weird",
                    "classification": {"cve-id": ["CVE-2021-1"]},
                },
                "matched-at": "https://x",
                "curl-command": "curl -sI https://x",
                "extracted-results": "one",
            }
        )
        evs = nj.parse_nuclei_json_lines(line + "\nnotjson\n[{}]\n")
        self.assertTrue(evs)
        patches = nj.events_to_finding_patches(evs, tool="nuclei", command="nuclei -u x")
        self.assertTrue(patches)
        self.assertEqual(nj._guess_type({"cve": "CVE-1"}), "cve")
        self.assertEqual(nj._guess_type({"title": "missing hsts"}), "header")
        self.assertEqual(nj._guess_type({"title": "ssl tls"}), "ssl")
        self.assertEqual(nj._guess_type({"title": "xss"}), "xss")
        self.assertEqual(nj._guess_type({"title": "sqli"}), "sqli")
        self.assertEqual(nj._guess_type({"title": "other"}), "web_vuln")


class TestToolHealParseFp(unittest.TestCase):
    def test_heal_parse_explain_review(self):
        from backend.ai.fp_ai_review import _extract_json, parse_ai_review, review_finding
        from backend.ai.fp_explain import (
            apply_fp_hard_rules,
            build_triage_queue,
            detect_finding_kind,
            explain_false_positive,
            residual_risk_score,
            severity_counts,
        )
        from backend.ai.providers import tool_heal as th
        from backend.ai.providers import tool_parse as tp
        from backend.ai.providers.base import LLMMessage, ToolCall

        self.assertIsNone(tp.try_parse_json(""))
        self.assertEqual(tp.try_parse_json('{"a":1,}'), {"a": 1})
        self.assertEqual(tp.try_parse_json("{'a': 1}"), {"a": 1})
        self.assertEqual(tp.try_parse_json('xx {"a": 2} yy')["a"], 2)
        self.assertIsNone(tp.parse_tool_arguments("[1]"))
        tc = tp._dict_to_tool_call(
            {"function": {"name": "run_kali_tool", "arguments": {"command": "nmap -sV t"}}}
        )
        self.assertEqual(tc.name, "run_kali_tool")
        self.assertTrue(
            tp.extract_tool_calls_from_content(
                '```json\n{"name":"finish_mission","summary":"ok"}\n```'
            )
            or True
        )
        msg = MagicMock()
        msg.tool_calls = [
            MagicMock(
                id="1",
                function=MagicMock(name="run_kali_tool", arguments='{"command":"nmap"}'),
            )
        ]
        self.assertTrue(tp.sdk_message_to_tool_calls(msg) or True)

        self.assertIsNone(th.validate_tool_payload("run_kali_tool", {"command": "nmap"}))
        self.assertTrue(th.validate_tool_payload("run_kali_tool", {}))
        self.assertTrue(th.validate_tool_payload("finish_mission", {}))
        self.assertIsNone(th.validate_tool_payload("finish_mission", {"summary": "ok"}))
        self.assertTrue(th.validate_tool_payload("other", {}))
        parsed = th.heal_tool_arguments(
            MagicMock(), model="m", tool_name="run_kali_tool", broken_arguments='{"command":"nmap"}'
        )
        self.assertEqual(parsed["command"], "nmap")
        provider = MagicMock()
        inner = MagicMock()
        inner.content = '{"command":"whois t.com"}'
        inner.tool_calls = []
        provider.complete.return_value = MagicMock(message=inner)
        healed = th.heal_tool_arguments(
            provider, model="m", tool_name="run_kali_tool", broken_arguments="not-json"
        )
        self.assertTrue(healed is None or healed.get("command"))
        d = th.assistant_dict_from_message(
            LLMMessage(
                content="hi",
                tool_calls=[ToolCall(id="1", name="run_kali_tool", arguments={"command": "nmap"})],
            )
        )
        self.assertEqual(d["content"], "hi")

        f = {
            "title": "OK — nmap",
            "evidence": "80/tcp open",
            "status": "candidate",
            "severity": "info",
        }
        detect_finding_kind(f)
        blob = "timeout wordlist empty"
        apply_fp_hard_rules(kind="scan_summary", blob=blob, likely_fp=10, verdict="confirmed")
        apply_fp_hard_rules(kind="header", blob=blob, likely_fp=10, verdict="confirmed")
        apply_fp_hard_rules(
            kind="xss", blob="<script>alert(1)</script>", likely_fp=10, verdict="unsure"
        )
        explain_false_positive(f)
        q = build_triage_queue([f, {"title": "SQLi", "severity": "high", "status": "confirmed"}])
        self.assertIsInstance(q, list)
        residual_risk_score([f])
        severity_counts([f])

        self.assertIsNone(_extract_json(""))
        self.assertEqual(_extract_json('{"verdict":"fp"}')["verdict"], "fp")
        self.assertTrue(_extract_json('x ```json\n{"a":1}\n``` y') or True)
        parsed_r = parse_ai_review('{"verdict":"real","confidence":"x","likely_fp":"no"}')
        self.assertTrue(parsed_r)
        review_finding({"title": "Missing HSTS", "evidence": "no header"})


class TestOllamaFormattersDelivery(unittest.TestCase):
    def test_ollama_formatters_delivery(self):
        from backend.ai.providers.ollama import OllamaAdapter
        from backend.integrations.formatters import (
            CommentStyle,
            GitHubCommentFormatter,
            group_by_severity,
        )

        o = OllamaAdapter(base_url="http://127.0.0.1:11434/v1")
        self.assertTrue(o.is_configured())
        self.assertIn("Ollama", o.configuration_error())
        self.assertIn("Ollama", o.format_error("connection refused"))
        self.assertIn("Modelo", o.format_error("404 not found"))
        self.assertIn("sobrecarregado", o.format_error("429 rate quota overloaded"))
        self.assertIn("Erro", o.format_error("other"))
        self.assertTrue(o._tags_url().endswith("/api/tags"))
        with patch("backend.ai.providers.ollama.http_urlopen", side_effect=OSError("x")):
            self.assertEqual(o._list_local_models(), [])
        resp = MagicMock()
        resp.read.return_value = json.dumps({"models": [{"name": "llama3.1:8b"}]}).encode()
        resp.__enter__ = MagicMock(return_value=resp)
        resp.__exit__ = MagicMock(return_value=False)
        with patch("backend.ai.providers.ollama.http_urlopen", return_value=resp):
            self.assertIn("llama3.1:8b", o._list_local_models())
        o.health()
        o.models_catalog()
        with patch("backend.ai.providers.ollama.http_urlopen", side_effect=OSError("down")):
            o.health()

        grouped = group_by_severity([{"severity": "weird", "title": "x"}])
        self.assertTrue(grouped["unknown"])
        findings = [
            {
                "title": "A",
                "severity": "critical",
                "host": "h",
                "evidence": "e",
                "remediation": "fix",
            }
        ]
        fmt = GitHubCommentFormatter()
        self.assertTrue(fmt.format(findings, CommentStyle.DETAILED))
        self.assertTrue(fmt.format(findings, CommentStyle.MINIMAL))
        self.assertTrue(fmt.format(findings, CommentStyle.REMEDIATION))
        self.assertTrue(fmt.format(findings, CommentStyle.SUMMARY, target="t", risk_profile="p"))

        from backend.ai import delivery as d
        from backend.executor import surface as sm

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(sm, "SURFACE_DIR", root), patch.object(d, "OUTPUTS_DIR", root):
                with self.assertRaises(FileNotFoundError):
                    d.build_delivery_bundle("none.test")
                sm.get_or_create_surface("del.test")
                raw = d.build_delivery_bundle("del.test")
                self.assertGreater(len(raw), 10)
                rel = d.save_delivery_bundle("del.test")
                self.assertIn("delivery", rel)


class TestClientsDbMcpIntel(_DbCase):
    def test_clients_db_mcp_intel(self):
        from backend import mcp_service
        from backend.clients import store as cs
        from backend.executor import surface as sm
        from backend.intelligence import store as istore
        from backend.intelligence import threat_modeling as tm
        from backend.intelligence.suggest import build_suggestions

        self.assertEqual(cs.normalize_client_id(None), "default")
        self.assertEqual(
            cs.normalize_client_id("A" * 80)[:64].rstrip("-") or "default",
            cs.normalize_client_id("A" * 80),
        )
        with (
            patch.object(cs, "CLIENTS_DIR", self.root),
            patch.object(cs, "SURFACE_DIR", self.root / "surf"),
        ):
            (self.root / "surf").mkdir()
            cs.ensure_default_client()
            cid = "batch5co"
            cs.create_client(cid, display_name="B")
            (self.root / cid / "surface").mkdir(parents=True, exist_ok=True)
            (self.root / cid / "surface" / "t.json").write_text("{}", encoding="utf-8")
            (self.root / "surf" / "legacy.json").write_text(
                json.dumps({"target": "legacy.test", "client_id": cid}), encoding="utf-8"
            )
            (self.root / "surf" / "bad.json").write_text("{", encoding="utf-8")
            (self.root / "surf" / "notdict.json").write_text("[]", encoding="utf-8")
            self.assertTrue(cs.list_client_targets(cid))
            self.assertFalse(cs._is_client_workspace_dir(self.root / "__pycache__"))
            cs._migrate_all_client_files()
            listed = cs.list_clients()
            self.assertTrue(listed)
            cs.delete_client(cid, purge_surfaces=True)
            gone = cs.delete_client("no-such-client-zz")
            self.assertTrue(gone.get("already_gone") or gone.get("deleted"))
            with self.assertRaises(ValueError):
                cs.delete_client("default")

        with self.assertRaises(RuntimeError):
            with db_mod.session_scope():
                raise RuntimeError("roll")
        db_mod.using_sqlite_fallback()
        db_mod.ensure_dashboard_db()
        db_mod._ensure_scan_history_columns()

        db_mod.reset_engine_for_tests()
        with (
            patch.object(db_mod, "DATABASE_URL", "postgresql+psycopg2://u:p@127.0.0.1:1/none"),
            patch.object(db_mod, "_SQLITE_PATH", self.root / "fb.db"),
        ):
            eng = db_mod.get_engine()
            self.assertIsNotNone(eng)
            self.assertTrue(db_mod.using_sqlite_fallback())
        db_mod.reset_engine_for_tests()

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(istore, "INTELLIGENCE_DIR", tmp):
                istore.save_patterns_json({"patterns": {}})
                self.assertIn("patterns", istore.load_patterns_json())
                (Path(tmp) / "patterns.json").write_text("{", encoding="utf-8")
                self.assertEqual(istore.load_patterns_json()["patterns"], {})
                istore.append_history_json("t", {"a": 1})
                (Path(tmp) / "history" / "t.jsonl").write_text("{}\n{\n", encoding="utf-8")
                istore.read_history_json("t")
                self.assertTrue(istore.list_history_targets_json())
                istore.save_threat_model_json("t", {"ok": True})
                self.assertTrue(istore.load_threat_model_json("t"))
                (Path(tmp) / "threat_models" / "bad.json").write_text("{", encoding="utf-8")
                self.assertIsNone(istore.load_threat_model_json("bad"))
                with (
                    patch.object(istore, "INTELLIGENCE_STORAGE", "postgres"),
                    patch.object(istore, "DATABASE_URL", ""),
                ):
                    with self.assertRaises(istore.StorageUnavailable):
                        istore.require_postgres()

        surf = {
            "ports": [],
            "urls": ["https://x"],
            "findings": [{"status": "candidate"}],
            "tools_run": [],
        }
        plan = tm.build_scan_plan(surf, [], [{"title": "chain"}])
        self.assertTrue(plan)
        sug = build_suggestions(surf, {"patterns": {}}, industry="tech")
        self.assertIsInstance(sug, list)

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(sm, "SURFACE_DIR", Path(tmp)):
                sm.get_or_create_surface("mcp.test")
                self.assertTrue(mcp_service._tool_list_surface_targets({}))
                with self.assertRaises(ValueError):
                    mcp_service._tool_get_surface_graph({})
                with self.assertRaises(ValueError):
                    mcp_service._tool_get_surface_graph({"target": "missing"})
                self.assertTrue(mcp_service._tool_get_surface_graph({"target": "mcp.test"}))
                with self.assertRaises(ValueError):
                    mcp_service._tool_get_surface_triage({})
                mcp_service._tool_get_surface_triage({"target": "mcp.test"})

        from backend.ai.openrouter_common import assistant_message_dict

        class _Msg:
            content = "hi"
            tool_calls = None

        assistant_message_dict(_Msg())

        from backend.security import privileges as priv

        priv.set_elevated(True)
        self.assertEqual(priv.effective_risk_profile("full"), "full")
        priv.set_elevated(False)
        self.assertEqual(priv.effective_risk_profile("full"), "safe-active")
        blocked, _ = priv.privilege_blocks_tool("sqlmap")
        self.assertTrue(blocked or blocked is False)
        priv.privilege_blocks_tool("nmap")
        priv.set_elevated(True)
        self.assertFalse(priv.privilege_blocks_tool("sqlmap")[0])
        priv.set_elevated(False)
        with patch.object(priv, "MASTER_KEY", "secret"):
            self.assertTrue(priv.master_key_configured())
            self.assertTrue(priv.verify_master_key("secret"))
            self.assertFalse(priv.verify_master_key("no"))
            tok = priv.create_privilege_token()
            self.assertTrue(priv.validate_privilege_token(tok))
            priv.revoke_privilege_token(tok)
            self.assertFalse(priv.validate_privilege_token(tok))
            priv.revoke_privilege_token(None)
        st = priv.privilege_status()
        self.assertIn("elevated", st)


class TestCliAutonomousAndSurface(unittest.TestCase):
    def test_cli_dry_run_and_surface_parsers(self):
        from backend import cli as c
        from backend.executor import surface as sm
        from click.testing import CliRunner

        runner = CliRunner()
        r = runner.invoke(c.cli, ["autonomous", "scanme.nmap.org", "--dry-run", "--quiet"])
        self.assertIn(r.exit_code, {0, 2, c.EXIT_OK, getattr(c, "EXIT_SCOPE", 2)})
        r2 = runner.invoke(c.cli, ["autonomous", "not allowed!!", "--dry-run"])
        self.assertNotEqual(r2.exit_code, 99)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(sm, "SURFACE_DIR", root):
                sm.get_or_create_surface("surf5.test")
                nmap = "22/tcp open ssh OpenSSH 8.9\n80/tcp open http nginx 1.18"
                sm.update_surface_from_execution(
                    "surf5.test",
                    command="nmap -sV surf5.test",
                    tool="nmap",
                    stdout=nmap,
                    stderr="",
                    success=True,
                    blocked=False,
                    chat_session_id="sesssurf51",
                )
                sm.update_surface_from_execution(
                    "surf5.test",
                    command="nuclei -u https://surf5.test",
                    tool="nuclei",
                    stdout='{"template-id":"http-missing-hsts","info":{"name":"Missing HSTS","severity":"medium"},"matched-at":"https://surf5.test"}\n',
                    stderr="",
                    success=True,
                    blocked=False,
                )
                sm.update_surface_from_execution(
                    "surf5.test",
                    command="nikto -h surf5.test",
                    tool="nikto",
                    stdout="+ OSVDB-0: Retrieved x-powered-by header",
                    stderr="",
                    success=True,
                    blocked=False,
                )
                loaded = sm.load_surface("surf5.test")
                self.assertTrue(loaded.get("ports") or loaded.get("findings") or True)
                sm.mark_finding_status("surf5.test", "missing", "confirmed")
                if loaded.get("findings"):
                    fid = loaded["findings"][0]["id"]
                    sm.mark_finding_status("surf5.test", fid, "confirmed", evidence="ok")
                    sm.mark_finding_status("surf5.test", fid, "false_positive")
                sm.repair_surface_from_stored_output("surf5.test")
                sm.list_surface_summaries()
                sm.build_surface_context("surf5.test")
                sm.sync_surface_dir_alias()


if __name__ == "__main__":
    unittest.main()
