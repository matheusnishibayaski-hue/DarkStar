"""Lote 3–4: notificações, github, scheduler, CLI, PDF, dashboard export, engagements."""

from __future__ import annotations

import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

from backend.database import db as db_mod
from click.testing import CliRunner
from fastapi.testclient import TestClient

from tests.auth_patch import patch_chat_api_token


class TestNotificationChannels(unittest.TestCase):
    def test_all_channels_send_mocked(self):
        from backend.integrations import notifications as n

        resp = MagicMock()
        resp.status = 200
        resp.__enter__ = MagicMock(return_value=resp)
        resp.__exit__ = MagicMock(return_value=False)
        with (
            patch.object(n, "SLACK_WEBHOOK_URL", "https://hooks.slack/x"),
            patch.object(n, "ALERT_WEBHOOK_URL", ""),
            patch.object(n, "DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/x"),
            patch.object(n, "TELEGRAM_BOT_TOKEN", "tok"),
            patch.object(n, "TELEGRAM_CHAT_ID", "1"),
            patch.object(n, "http_urlopen", return_value=resp),
        ):
            self.assertTrue(n.SlackNotifier().send("t", "m", "critical"))
            self.assertTrue(n.DiscordNotifier().send("t", "m", "high"))
            self.assertTrue(n.TelegramNotifier().send("t", "m", "medium"))
        with patch.object(n, "http_urlopen", side_effect=urllib.error.URLError("x")):
            slack = n.SlackNotifier()
            slack.webhook_url = "https://x"
            self.assertFalse(slack.send("t", "m"))
        email = n.EmailNotifier()
        email.smtp_server = "s"
        email.smtp_user = "u"
        email.smtp_pass = "p"
        email.from_email = "a@b.c"
        email.to_email = "c@d.e"
        with patch("smtplib.SMTP") as smtp:
            ctx = MagicMock()
            smtp.return_value.__enter__.return_value = ctx
            self.assertTrue(email.send("t", "m", "info"))
        with patch("smtplib.SMTP", side_effect=OSError("no smtp")):
            self.assertFalse(email.send("t", "m"))
        self.assertFalse(n.EmailNotifier().send("t", "m"))
        jira = n.JiraNotifier()
        jira.url = "https://jira.example"
        jira.user = "u"
        jira.token = "t"
        with patch.object(n, "http_urlopen", return_value=resp):
            self.assertTrue(jira.send("t", "m", "critical"))
        with patch.object(n, "http_urlopen", side_effect=urllib.error.URLError("x")):
            self.assertFalse(jira.send("t", "m"))
        self.assertFalse(n.JiraNotifier().send("t", "m"))
        mgr = n.NotificationManager()
        fake = MagicMock()
        fake.is_configured.return_value = True
        fake.send.side_effect = [True, RuntimeError("boom")]
        mgr.channels = {"slack": fake, "x": fake}
        mgr.notify("t", "m", severity="high", channels=["slack", "missing", "x"])
        mgr.alert_finding({"title": "XSS", "severity": "high", "target": "t", "tool": "n"})
        slack2 = n.SlackNotifier()
        slack2.webhook_url = ""
        self.assertFalse(slack2.send("t", "m"))
        disc = n.DiscordNotifier()
        disc.webhook_url = ""
        self.assertFalse(disc.send("t", "m"))
        tg = n.TelegramNotifier()
        self.assertFalse(tg.send("t", "m"))


class TestGitHubClientMore(unittest.TestCase):
    def test_client_methods_mocked(self):
        from backend.integrations.github import GitHubClient

        c = GitHubClient(token="")
        self.assertFalse(c.is_available())
        self.assertIsNone(c.get_repo("owner/repo"))
        self.assertFalse(c.comment_on_pr("owner/repo", 1, []))
        self.assertIsNone(c.create_issue("owner/repo", {"title": "x"}))
        self.assertFalse(c.update_commit_status("o/r", "abc", "bad", "d"))
        self.assertFalse(c.update_commit_status("o/r", "abc", "success", "d"))

        repo = MagicMock()
        pr = MagicMock()
        repo.get_pull.return_value = pr
        issue = MagicMock(html_url="https://github.com/o/r/issues/1")
        repo.create_issue.return_value = issue
        commit = MagicMock()
        repo.get_commit.return_value = commit
        c._client = MagicMock()
        c._client.get_repo.return_value = repo
        self.assertTrue(c.comment_on_pr("https://github.com/o/r", 2, [{"severity": "critical"}]))
        pr.add_to_labels.side_effect = RuntimeError("no labels")
        c.comment_on_pr("o/r", 2, [{"severity": "high"}])
        self.assertTrue(
            c.create_issue("o/r", {"title": "t", "severity": "low", "tool": "nmap"}, assignee="me")
        )
        c._client.get_repo.side_effect = RuntimeError("gone")
        self.assertIsNone(c.create_issue("o/r", {"title": "t"}))
        c._client.get_repo.side_effect = None
        c._client.get_repo.return_value = repo
        self.assertTrue(c.update_commit_status("o/r", "deadbeef", "success", "ok"))
        repo.get_commit.side_effect = RuntimeError("no")
        self.assertFalse(c.update_commit_status("o/r", "deadbeef", "error", "x"))
        c._format_issue_body({"title": "t"})
        c._group_by_severity([])
        c._format_pr_comment([], "t")
        c._format_finding_block({"title": "t"})
        c._get_issue_labels({"severity": "medium", "tool": "nikto"})
        with patch("github.Github", create=True), patch("github.Auth", create=True):
            GitHubClient(token="tok")


class TestScheduleRunner(unittest.TestCase):
    def test_execute_jobs_and_scheduler_lifecycle(self):
        from backend.executor.result import ExecutionResult
        from backend.schedule import runner as rn
        from backend.schedule import store as st

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(st, "SCHEDULE_DIR", root):
                job = st.create_job(target="sched.test", job_type="remind")
                with (
                    patch("backend.alerts.webhook.send_webhook", return_value=True),
                    patch("backend.alerts.webhook.maybe_alert_delta", return_value=[]),
                    patch("backend.ai.risk_score.risk_score_for_target", return_value={"score": 1}),
                    patch("backend.ai.risk_history.previous_score", return_value=0),
                    patch("backend.ai.risk_history.record_risk_snapshot"),
                    patch("backend.ai.delta.compute_delta", return_value={"new": []}),
                    patch("backend.database.db.record_scan_from_target"),
                ):
                    out = rn.execute_job(job)
                    self.assertTrue(out.get("ok") or out.get("action") == "remind")
                job2 = st.create_job(target="full.test", job_type="full")
                with (
                    patch("backend.alerts.webhook.send_webhook", return_value=True),
                    patch("backend.alerts.webhook.maybe_alert_delta", return_value=[]),
                ):
                    rn.execute_job(job2)
                job3 = st.create_job(target="mon.test", job_type="monitor")
                fake = ExecutionResult("nmap", "r", "80/tcp open http", "", 0, True)
                with (
                    patch("backend.executor.kali.execute_in_kali", return_value=fake),
                    patch("backend.alerts.webhook.maybe_alert_delta", return_value=[]),
                    patch("backend.executor.surface.get_or_create_surface", return_value={}),
                    patch("backend.executor.surface.update_surface_from_execution"),
                ):
                    mon = rn.run_light_monitor("mon.test")
                    self.assertIn("ok", mon)
                    rn.execute_job(job3)
                job4 = st.create_job(target="rep.test", job_type="repeat")
                with patch("backend.ai.autopilot.run_autonomous"), patch("threading.Thread") as th:
                    th.return_value.start = MagicMock()
                    rn.execute_job(job4)
                    th.assert_called()
                with patch("backend.alerts.webhook.send_webhook", side_effect=RuntimeError("x")):
                    bad = st.create_job(target="err.test", job_type="remind")
                    err = rn.execute_job(bad)
                    self.assertFalse(err.get("ok"))

        with patch.object(rn, "SCHEDULE_ENABLED", False):
            rn.start_scheduler()
        with (
            patch.object(rn, "SCHEDULE_ENABLED", True),
            patch.object(rn, "_thread", None),
            patch("threading.Thread") as th,
        ):
            th.return_value.is_alive.return_value = False
            th.return_value.start = MagicMock()
            rn._thread = None
            rn.start_scheduler()
        alive = MagicMock()
        alive.is_alive.return_value = True
        with patch.object(rn, "SCHEDULE_ENABLED", True), patch.object(rn, "_thread", alive):
            rn.start_scheduler()
        rn.stop_scheduler()
        with patch.object(rn, "_stop") as stop:
            stop.wait.side_effect = [False, True]
            with (
                patch.object(rn, "SCHEDULE_ENABLED", True),
                patch.object(rn, "due_jobs", return_value=[]),
            ):
                rn._tick()
        with patch.object(rn, "_stop") as stop:
            stop.wait.side_effect = [False, True]
            with (
                patch.object(rn, "SCHEDULE_ENABLED", False),
            ):
                rn._tick()
        with patch.object(rn, "_stop") as stop:
            stop.wait.side_effect = [False, True]
            with (
                patch.object(rn, "SCHEDULE_ENABLED", True),
                patch.object(rn, "due_jobs", side_effect=RuntimeError("tick")),
            ):
                rn._tick()


class TestCliMore(unittest.TestCase):
    def test_health_docker_kali_ai_chat_tools(self):
        from backend import cli as c

        runner = CliRunner()
        proc_ok = MagicMock(returncode=0, stdout="kali-tools\n", stderr="")
        with patch.object(c.subprocess, "run", return_value=proc_ok):
            r = runner.invoke(c.cli, ["health", "--check", "docker", "--output", "json"])
            self.assertIn(r.exit_code, {0, 1})
            r2 = runner.invoke(c.cli, ["health", "--check", "kali"])
            self.assertIn(r2.exit_code, {0, 1})
        with patch.object(c.subprocess, "run", side_effect=FileNotFoundError):
            self.assertEqual(c._check_docker()["status"], "error")
            self.assertEqual(c._check_kali()["status"], "error")
        with patch.object(c.subprocess, "run", side_effect=RuntimeError("x")):
            c._check_docker()
            c._check_kali()
        proc_fail = MagicMock(returncode=1, stdout="", stderr="fail")
        with patch.object(c.subprocess, "run", return_value=proc_fail):
            c._check_docker()
            c._check_kali()
        proc_empty = MagicMock(returncode=0, stdout="", stderr="")
        with patch.object(c.subprocess, "run", return_value=proc_empty):
            c._check_kali()
        c._check_ai()
        c._check_config()
        r3 = runner.invoke(c.cli, ["list-tools", "--output", "json", "--pattern", "nmap"])
        self.assertEqual(r3.exit_code, 0)
        r4 = runner.invoke(c.cli, ["list-tools", "--category", "nope"])
        self.assertEqual(r4.exit_code, 1)
        fake_chat = MagicMock(message="hi", tool_executions=[], stopped_reason="done")
        with patch("backend.ai.agent.chat", return_value=fake_chat):
            r5 = runner.invoke(c.cli, ["chat", "-m", "ola", "--output", "json"])
            self.assertEqual(r5.exit_code, 0)
            r6 = runner.invoke(c.cli, ["chat", "-m", "ola"])
            self.assertEqual(r6.exit_code, 0)
        with patch("backend.ai.agent.chat", side_effect=RuntimeError("no")):
            r7 = runner.invoke(c.cli, ["chat", "-m", "ola"])
            self.assertEqual(r7.exit_code, c.EXIT_ERROR)
        c._maybe_comment_pr("o/r", 1, {"findings": []}, quiet=True)
        with patch("backend.integrations.github.GitHubClient") as gh:
            inst = MagicMock()
            inst.is_available.return_value = False
            gh.return_value = inst
            c._maybe_comment_pr("o/r", 1, {}, quiet=False)
            inst.is_available.return_value = True
            inst.comment_on_pr.return_value = True
            c._maybe_comment_pr("o/r", 1, {"findings": [{}]}, quiet=False)
            inst.comment_on_pr.return_value = False
            c._maybe_comment_pr("o/r", 1, {}, quiet=False)
        with patch("backend.integrations.github.GitHubClient", side_effect=RuntimeError("x")):
            c._maybe_comment_pr("o/r", 1, {}, quiet=False)
        report = {"critical": 0, "high": 0, "findings": []}
        with patch("click.echo"):
            c._emit_report(report, "json", None, True)
            c._emit_report(report, "sarif", None, True)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            c._emit_report(report, "json", f.name, False)
        runner.invoke(c.cli, [])
        import runpy
        import sys

        with patch.object(sys, "argv", ["cli.py", "--help"]):
            with self.assertRaises(SystemExit):
                runpy.run_path(str(Path(c.__file__)), run_name="__main__")


class TestPdfReport(unittest.TestCase):
    def test_generate_pdf_from_surface(self):
        from backend.ai.pdf_report import generate_report_pdf
        from backend.executor import surface as sm

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(sm, "SURFACE_DIR", root):
                data = sm.get_or_create_surface("pdf.test")
                data["findings"] = [
                    {
                        "id": "1",
                        "title": "Missing HSTS",
                        "severity": "medium",
                        "status": "confirmed",
                        "evidence": "no header",
                    }
                ]
                data["label"] = "Lab"
                sm.save_surface("pdf.test", data)
                raw = generate_report_pdf(surface_target="pdf.test", title="T")
                self.assertGreater(len(raw), 100)
                self.assertTrue(raw.startswith(b"%PDF") or raw[:8])

    def test_export_json_csv_pdf_and_empty_session(self):
        from backend.main import app

        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        url = f"sqlite:///{(root / 't.db').as_posix()}"
        db_mod.reset_engine_for_tests()
        patches = [
            patch.object(db_mod, "DATABASE_URL", ""),
            patch.object(db_mod, "_SQLITE_PATH", root / "t.db"),
            patch.object(db_mod, "resolve_database_url", return_value=url),
        ]
        for p in patches:
            p.start()
        try:
            db_mod.reset_engine_for_tests()
            db_mod.init_db()
            sid = "dashexport01"
            db_mod.save_scan_result(
                {
                    "scan_id": "s1",
                    "target": "a.test",
                    "chat_session_id": sid,
                    "findings": [{"id": "1", "title": "HSTS", "severity": "medium"}],
                    "vulnerability_count": 1,
                    "critical": 0,
                    "high": 0,
                    "medium": 1,
                    "low": 0,
                    "status": "completed",
                }
            )
            with patch_chat_api_token(""):
                client = TestClient(app)
                q = f"days=30&session_id={sid}"
                self.assertEqual(client.get(f"/api/dashboard/metrics?{q}").status_code, 200)
                self.assertEqual(
                    client.get(f"/api/dashboard/vulnerability-trend?{q}").status_code, 200
                )
                self.assertEqual(
                    client.get(f"/api/dashboard/top-issues?session_id={sid}").status_code, 200
                )
                self.assertEqual(client.get(f"/api/dashboard/summary?{q}").status_code, 200)
                r = client.get(f"/api/dashboard/export?format=json&{q}")
                self.assertEqual(r.status_code, 200)
                csv_r = client.get(f"/api/dashboard/export?format=csv&{q}")
                self.assertEqual(csv_r.status_code, 200)
                pdf_r = client.get(f"/api/dashboard/export?format=pdf&{q}")
                self.assertEqual(pdf_r.status_code, 200)
                self.assertEqual(client.delete(f"/api/dashboard/session/{sid}").status_code, 200)
                missing = client.get("/api/dashboard/metrics?days=30")
                self.assertEqual(missing.status_code, 422)
        finally:
            for p in patches:
                p.stop()
            db_mod.reset_engine_for_tests()
            tmp.cleanup()


class TestEngagementsMore(unittest.TestCase):
    def test_engagement_routes_roundtrip(self):
        from backend.executor import surface as sm
        from backend.main import app

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(sm, "SURFACE_DIR", root), patch_chat_api_token(""):
                client = TestClient(app)
                created = client.post(
                    "/api/engagements",
                    json={"target": "eng.test", "objective": "map", "risk_profile": "passive"},
                )
                self.assertIn(created.status_code, {200, 201})
                self.assertEqual(client.get("/api/surface").status_code, 200)
                self.assertEqual(client.get("/api/surface/eng.test").status_code, 200)
                self.assertEqual(client.get("/api/engagements/eng.test").status_code, 200)
                self.assertEqual(client.get("/api/engagements/eng.test/triage").status_code, 200)
                self.assertEqual(client.get("/api/engagements/eng.test/delta").status_code, 200)
                self.assertEqual(client.post("/api/engagements/eng.test/baseline").status_code, 200)
                self.assertEqual(client.get("/api/engagements/eng.test/risk").status_code, 200)
                client.patch("/api/engagements/eng.test", json={"label": "L"})
                client.patch("/api/engagements/eng.test/phase", json={"phase": "enumerate"})
                data = sm.load_surface("eng.test")
                if data.get("findings"):
                    fid = data["findings"][0]["id"]
                    client.post(
                        f"/api/engagements/eng.test/findings/{fid}",
                        json={"status": "confirmed"},
                    )
                client.post(
                    "/api/engagements/eng.test/import",
                    json={"content": "Plugin Name,Severity\nX,High\n", "format": "nessus"},
                )
                client.get("/api/engagements/eng.test/report")
                client.delete("/api/engagements/eng.test")


class TestIntelligenceHubMore(unittest.TestCase):
    def test_record_and_try(self):
        from backend.executor import surface as sm
        from backend.intelligence import hub

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with (
                patch.object(sm, "SURFACE_DIR", root),
                patch.object(hub, "INTELLIGENCE_ENABLED", True),
            ):
                sm.get_or_create_surface("hub.test")
                hub.try_record_from_surface("hub.test")
                hub.record_from_surface("hub.test", industry="tech")
                hub.suggest("hub.test")
                hub.stats()
                hub.similar_targets("hub.test")


if __name__ == "__main__":
    unittest.main()
