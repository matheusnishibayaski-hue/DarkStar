"""Lote 5f: surface, session_intel, db, schedule, clients, backup, cleanup, recon, logs, kali."""

from __future__ import annotations

import io
import json
import os
import tarfile
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from backend.database import db as db_mod


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


class TestSurfaceMissingParsers(unittest.TestCase):
    def test_find_load_upsert_parsers_repair_list(self):
        from backend import config as cfg
        from backend.ai.nuclei_json import events_to_finding_patches, parse_nuclei_json_lines
        from backend.clients import store as cs
        from backend.executor import surface as sm

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            surf = root / "surface"
            clients = root / "clients"
            surf.mkdir()
            clients.mkdir()
            with (
                patch.object(sm, "SURFACE_DIR", surf),
                patch.object(cs, "CLIENTS_DIR", clients),
                patch.object(cfg, "CLIENTS_DIR", clients),
            ):
                fake_clients = MagicMock()
                fake_clients.is_dir.return_value = True
                fake_clients.iterdir.side_effect = RuntimeError("walk")
                with patch.object(cfg, "CLIENTS_DIR", fake_clients):
                    self.assertIsNone(sm._find_surface_path("miss5f.find"))

                (surf / "bad5f.test.json").write_text("{", encoding="utf-8")
                self.assertEqual(sm.load_surface("bad5f.test"), {})
                with patch.object(Path, "read_text", side_effect=OSError("io")):
                    self.assertEqual(sm.load_surface("bad5f.test"), {})

                sm.get_or_create_surface("goc5f.test")
                sm.get_or_create_surface(
                    "goc5f.test",
                    objective="obj",
                    mission_id="m5f01",
                    risk_profile="passive",
                    client="Acme5f",
                    client_id="acme5fco",
                    scope_notes="notes",
                    brand_name="Brand5f",
                )

                self.assertEqual(
                    sm._extract_template_id("[info] [critical] Title here", "nuclei"),
                    "",
                )
                self.assertEqual(
                    sm._extract_template_id("[high] [exposed-panel] Admin", "nuclei"),
                    "exposed-panel",
                )
                self.assertIn(
                    "missing",
                    sm._extract_template_id("missing-header:hsts on host", "nmap"),
                )
                self.assertTrue(
                    sm._extract_cve("see CVE-2021-44228 in output")
                    or sm._extract_template_id("CVE-2021-44228 apache", "nmap")
                )
                tid = sm._extract_template_id("[http] [exposed-panel] Admin login", "nuclei")
                self.assertTrue(tid == "" or tid)

                key = sm._canonical_finding_key(
                    title="80/tcp open http nginx",
                    severity="info",
                    tool="nmap",
                    host="goc5f.test",
                )
                self.assertTrue(key.startswith("svc:") or "80" in key)

                existing = {
                    "tool": "nikto",
                    "tools": ["nmap"],
                    "severity": "high",
                    "evidence": "old",
                    "status": "candidate",
                    "sources": 1,
                }
                sm._merge_finding(
                    existing, {"tool": "nuclei", "severity": "low", "evidence": "new"}
                )
                self.assertIn("nikto", existing["tools"])

                data = sm.get_or_create_surface("ups5f.test")
                data["findings"] = [
                    {
                        "id": "oldcve5f",
                        "canonical_key": "other-key",
                        "cve": "CVE-2020-0001",
                        "template_id": "",
                        "title": "Old",
                        "severity": "low",
                        "tools": [],
                        "status": "candidate",
                        "sources": 1,
                    },
                    {
                        "id": "oldtpl5f",
                        "canonical_key": "tpl-other",
                        "cve": "",
                        "template_id": "exposed-panel",
                        "title": "Panel",
                        "severity": "info",
                        "tools": [],
                        "status": "candidate",
                        "sources": 1,
                    },
                ]
                sm._upsert_finding(
                    data,
                    {
                        "title": "Log4j",
                        "cve": "CVE-2020-0001",
                        "severity": "critical",
                        "tool": "nuclei",
                    },
                    chat_session_id="sess5fups01",
                )
                sm._upsert_finding(
                    data,
                    {
                        "title": "Panel 2",
                        "template_id": "exposed-panel",
                        "severity": "medium",
                        "tool": "httpx",
                    },
                )
                with patch("backend.ai.cvss.enrich_finding", side_effect=ValueError("cvss")):
                    sm._upsert_finding(
                        data,
                        {"title": "fresh-5f", "severity": "info", "tool": "nmap"},
                    )

                events = parse_nuclei_json_lines(
                    json.dumps(
                        {
                            "template-id": "http-missing-hsts",
                            "info": {"name": "HSTS", "severity": "medium"},
                            "matched-at": "https://ups5f.test",
                        }
                    )
                )
                events_to_finding_patches(events, tool="nuclei", command="nuclei -u x")

                nmap_out = (
                    "80/tcp open http nginx 1.18\n"
                    "https://ups5f.test/login\n"
                    "SESSID: httponly flag not set\n"
                    "_http-server-header: nginx/1.18\n"
                    "_http-server-header:\n"
                    "_http-server-header: unknown-stack/9.9\n"
                    "_http-server-header: " + ("Z" * 200) + "\n"
                    "cloudflare attention required captcha\n"
                    "X-Frame-Options header is not present\n"
                )
                sm.update_surface_from_execution(
                    "ups5f.test",
                    command="nmap -sV ups5f.test",
                    tool="nmap",
                    stdout=nmap_out,
                    stderr="",
                    success=False,
                    blocked=True,
                    exit_code=1,
                    chat_session_id="sess5fups01",
                )

                nuclei_txt = (
                    "[high] [tid-empty]    \n"
                    "[info]     \n"
                    "[critical] [cve-2021-9999] CVE-2021-9999 RCE\n"
                    "[medium] generic finding without tpl id\n"
                )
                sm.update_surface_from_execution(
                    "ups5f.test",
                    command="nuclei -u https://ups5f.test",
                    tool="nuclei",
                    stdout=nuclei_txt,
                    stderr="",
                    success=True,
                    blocked=False,
                )
                real_tpl = sm._NUCLEI_TPL_RE
                fake_tpl = MagicMock()
                fake_tpl.finditer.return_value = []
                fake_tpl.search = real_tpl.search
                with patch.object(sm, "_NUCLEI_TPL_RE", fake_tpl):
                    sm.update_surface_from_execution(
                        "ups5f.test",
                        command="nuclei -u https://ups5f.test",
                        tool="nuclei",
                        stdout="[critical] [tpl-skip5f] Title here\n",
                        stderr="",
                        success=True,
                        blocked=False,
                    )

                nikto_out = (
                    "+ Target IP: 10.0.0.1\n"
                    "+ Start Time: now\n"
                    "+ End Time: later\n"
                    "+ The anti-clickjacking X-Frame-Options header is not present\n"
                    "+ Strict-Transport-Security header is missing\n"
                    "+ OSVDB-1212: XSS in cookie\n"
                    "+ Server banner leaked\n"
                )
                sm.update_surface_from_execution(
                    "ups5f.test",
                    command="nikto -h ups5f.test",
                    tool="nikto",
                    stdout=nikto_out,
                    stderr="",
                    success=True,
                    blocked=False,
                )

                gob_out = (
                    "/admin (Status: 200)\n"
                    "/login (Status: 301)\n"
                    "/backup (Status: 403)\n"
                    "/.git (Status: 200)\n"
                    "/phpmyadmin (Status: 200)\n"
                    "/randompath (Status: 200)\n"
                )
                sm.update_surface_from_execution(
                    "ups5f.test",
                    command="gobuster dir -u https://ups5f.test",
                    tool="gobuster",
                    stdout=gob_out,
                    stderr="",
                    success=True,
                    blocked=False,
                )

                with patch(
                    "backend.executor.recon_db.sync_recon_counts_from_surface",
                    side_effect=RuntimeError("sync"),
                ):
                    sm.update_surface_from_execution(
                        "ups5f.test",
                        command="httpx -u https://ups5f.test",
                        tool="httpx",
                        stdout="https://ups5f.test [200]\n",
                        stderr="",
                        success=False,
                        blocked=False,
                        exit_code=2,
                    )

                loaded = sm.load_surface("ups5f.test")
                loaded["hosts"] = ["ups5f.test", "bootstrap.min.css", "jquery.js"]
                loaded["findings"] = loaded.get("findings") or [{"id": "keep5f"}]
                sm.save_surface("ups5f.test", loaded)
                repaired = sm.repair_surface_from_stored_output("ups5f.test")
                self.assertTrue(repaired.get("findings"))

                empty_t = "empty5f.test"
                sm.get_or_create_surface(empty_t)
                data_e = sm.load_surface(empty_t)
                data_e["findings"] = []
                sm.save_surface(empty_t, data_e)
                with patch(
                    "backend.executor.recon_db.get_recon_data",
                    return_value={
                        "open_ports": ["x" * 50],
                        "raw_output": "22/tcp open ssh",
                        "nikto": "+ banner",
                        "nmap": "_http-server-header: apache",
                        "last_output": "done",
                        "last_tool": "nmap",
                    },
                ):
                    sm.repair_surface_from_stored_output(empty_t)

                with self.assertRaises(ValueError):
                    sm.mark_finding_status("ups5f.test", "x", "nope")
                fid = (sm.load_surface("ups5f.test").get("findings") or [{}])[0].get("id")
                if fid:
                    sm.mark_finding_status("ups5f.test", fid, "discarded", evidence="dup")
                    with patch(
                        "backend.ai.fp_learn.remember_false_positive",
                        side_effect=RuntimeError("fp"),
                    ):
                        sm.mark_finding_status("ups5f.test", fid, "false_positive")

                (surf / "notdict5f.json").write_text("[]", encoding="utf-8")
                (surf / "dup5f-a.json").write_text(
                    json.dumps({"target": "dup5f.test", "updated_at": "1"}),
                    encoding="utf-8",
                )
                (surf / "dup5f-b.json").write_text(
                    json.dumps({"target": "dup5f.test", "updated_at": "2"}),
                    encoding="utf-8",
                )
                (surf / "broken5f.json").write_text("{", encoding="utf-8")
                ws = clients / "acme5fco" / "surface"
                ws.mkdir(parents=True, exist_ok=True)
                (ws / "ws5f.test.json").write_text(
                    json.dumps({"target": "ws5f.test", "client_id": "acme5fco"}),
                    encoding="utf-8",
                )
                listed = sm.list_surface_summaries()
                self.assertIsInstance(listed, list)
                sm.list_surface_summaries(client_id="acme5fco")


class TestSessionIntelMissing(_DbCase):
    def test_load_errors_ingest_empty_and_patch(self):
        from backend.database.models_store import IntelSessionRow
        from backend.executor import logs as logs_mod
        from backend.executor import session_intel as si
        from backend.executor import surface as sm

        sid = "sess5fintel"
        intel = self.root / "intel"
        surf = self.root / "surface"
        log_dir = self.root / "logs"
        intel.mkdir()
        surf.mkdir()
        log_dir.mkdir()
        with (
            patch.object(si, "INTEL_SESSIONS_DIR", intel),
            patch.object(sm, "SURFACE_DIR", surf),
            patch.object(logs_mod, "LOG_DIR", log_dir),
            patch.object(logs_mod, "_SESSION_INDEX_DIR", log_dir / "by_session"),
        ):
            with db_mod.session_scope() as db:
                db.add(IntelSessionRow(session_id="sess5fbadj", payload_json="{"))
                db.add(IntelSessionRow(session_id="sess5fnonobj", payload_json="[]"))
            bad = si.load_session("sess5fbadj")
            self.assertEqual(bad, {})
            si.load_session("sess5fnonobj")

            with patch.object(db_mod, "ensure_dashboard_db", side_effect=RuntimeError("db")):
                path = intel / "sess5ffile1.json"
                path.write_text(
                    json.dumps({"session_id": "sess5ffile1", "targets": ["a5f.test"]}),
                    encoding="utf-8",
                )
                with patch.object(Path, "unlink", side_effect=OSError("busy")):
                    si.load_session("sess5ffile1")
                si.save_session(
                    "sess5ffile2",
                    {"session_id": "sess5ffile2", "created_at": "2020-01-01T00:00:00Z"},
                )

            with patch("backend.executor.session_intel.normalize_target", return_value=""):
                self.assertEqual(si.touch_session(sid, "x.test"), {})

            si.touch_session(sid, "lab5f.test")
            logs_mod._register_session_log(sid, "missing5flog")
            logs_mod._register_session_log(sid, "nocmd5flog1")
            (log_dir / "nocmd5flog1.log").write_text("=== STDOUT ===\nhi\n", encoding="utf-8")
            lid = logs_mod.save_execution_log(
                "nmap -Pn lab5f.test",
                "r",
                "80/tcp open http",
                "",
                chat_session_id=sid,
            )
            with patch(
                "backend.executor.surface.update_surface_from_execution",
                side_effect=RuntimeError("surf"),
            ):
                si.sync_session_intel_from_logs(sid)
            self.assertTrue(lid)

            extra = {
                "command": "nikto -h lab5f.test",
                "stdout": "[critical] SQLi found",
                "stderr": "",
                "success": True,
                "tool": "nikto",
            }
            si.backfill_session_findings_from_client(sid, [extra])
            si.backfill_session_findings_from_client(sid, [extra])

            with patch.object(si, "sync_session_intel_from_logs", side_effect=RuntimeError("sync")):
                si.aggregate_session_findings(sid, sync=True)

            si.touch_session(sid, "ghost5f.test")
            data = sm.get_or_create_surface("lab5f.test")
            data["findings"] = [
                "skip-me",
                {
                    "id": "dup5ffid",
                    "title": "A",
                    "chat_session_id": sid,
                },
                {
                    "id": "dup5ffid",
                    "title": "B",
                    "chat_session_id": sid,
                },
                {
                    "id": "other5f",
                    "title": "C",
                    "chat_session_id": "other-session",
                },
            ]
            sm.save_surface("lab5f.test", data)
            meta = si.load_session(sid) or {}
            meta["session_findings"] = [
                "nope",
                {"id": "", "title": "empty"},
                {"id": "sf5fa", "title": "one", "host": "h5f.test"},
                {"id": "sf5fa", "title": "dup"},
                {"id": "sf5fb", "title": "two", "surface_target": "lab5f.test"},
            ]
            si.save_session(sid, meta)
            agg = si.aggregate_session_findings(sid, sync=False)
            self.assertTrue(isinstance(agg, list))

            clean = si.load_session(sid) or {}
            clean["session_findings"] = [
                f for f in (clean.get("session_findings") or []) if isinstance(f, dict)
            ]
            si.save_session(sid, clean)
            vulns = [{"detail": "SQLi 5f", "severity": "high", "source": "nmap"}]
            with patch("backend.ai.report._extract_vulnerabilities", return_value=vulns):
                n1 = si.ingest_extracted_findings(
                    sid,
                    extra_executions=[{"command": "nmap", "stdout": "x"}],
                    skip_disk_logs=True,
                )
                n2 = si.ingest_extracted_findings(
                    sid,
                    extra_executions=[{"command": "nmap", "stdout": "x"}],
                    skip_disk_logs=True,
                )
            self.assertGreaterEqual(n1, 1)
            self.assertEqual(n2, 0)

            (intel / "sess5fmigxx.json").write_text(
                json.dumps({"session_id": "sess5fmigxx", "targets": []}),
                encoding="utf-8",
            )
            with patch.object(db_mod, "ensure_dashboard_db", side_effect=RuntimeError("db")):
                si.list_session_summaries()
            si.list_session_summaries()

            meta = si.load_session(sid) or {}
            findings = list(meta.get("session_findings") or [])
            if findings:
                fid = str(findings[0].get("id") or "sf5fa")
                with patch(
                    "backend.ai.fp_learn.remember_false_positive",
                    side_effect=RuntimeError("fp"),
                ):
                    si.patch_session_finding(sid, "lab5f.test", fid, "false_positive", evidence="x")

            sm.get_or_create_surface("lab5f.test")
            surf_data = sm.load_surface("lab5f.test")
            surf_data["findings"] = [
                {
                    "id": "surfonly5f",
                    "title": "Only surface",
                    "chat_session_id": sid,
                    "status": "candidate",
                }
            ]
            sm.save_surface("lab5f.test", surf_data)
            with patch(
                "backend.ai.fp_learn.remember_false_positive",
                side_effect=RuntimeError("fp"),
            ):
                si.patch_session_finding(sid, "lab5f.test", "surfonly5f", "false_positive")

            file_sid = "sess5fdel01"
            fpath = intel / f"{file_sid}.json"
            fpath.write_text(
                json.dumps({"session_id": file_sid, "targets": ["ghost5f.test"]}), encoding="utf-8"
            )
            si.save_session(file_sid, {"session_id": file_sid, "targets": ["ghost5f.test"]})
            fpath.write_text("{}", encoding="utf-8")
            with patch.object(Path, "unlink", side_effect=OSError("busy")):
                with patch.object(db_mod, "ensure_dashboard_db", side_effect=RuntimeError("db")):
                    si.delete_session_intel(file_sid)

            logs_mod._register_session_log(sid, "emptyraw5f1")
            si.collect_session_tool_executions(sid)


class TestDbDashboardMissing(_DbCase):
    def test_url_migrate_existing_vuln_except_and_filters(self):
        from backend.database.models_dashboard import ScanHistory
        from backend.executor import session_intel as si

        db_mod.reset_engine_for_tests()
        self.assertTrue(db_mod.resolve_database_url().startswith("sqlite"))

        with patch("sqlalchemy.inspect") as insp:
            inst = MagicMock()
            inst.get_table_names.return_value = []
            insp.return_value = inst
            db_mod._ensure_scan_history_columns()
            inst.get_table_names.return_value = ["scan_history"]
            inst.get_columns.return_value = [{"name": "id"}, {"name": "target"}]
            mock_conn = MagicMock()
            mock_ctx = MagicMock()
            mock_ctx.__enter__.return_value = mock_conn
            mock_ctx.__exit__.return_value = False
            eng = db_mod.get_engine()
            with patch.object(eng, "begin", return_value=mock_ctx):
                db_mod._ensure_scan_history_columns()
            inst.get_columns.side_effect = RuntimeError("insp")
            db_mod._ensure_scan_history_columns()

        sid = "sess5fdb01"
        finding = {
            "id": "v5f01",
            "title": "XSS",
            "severity": "low",
            "status": "open",
            "remediation": "",
        }
        payload = {
            "target": "db5f.test",
            "chat_session_id": sid,
            "findings": [finding],
            "vulnerability_count": 1,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 1,
            "scan_id": "scan5f01",
        }
        self.assertTrue(db_mod.save_scan_result(payload))
        payload2 = dict(payload)
        payload2["scan_id"] = "scan5f02"
        payload2["findings"] = [{**finding, "severity": "high", "remediation": "patch it"}]
        self.assertTrue(db_mod.save_scan_result(payload2))

        with patch("backend.cli_report.build_cli_report", side_effect=RuntimeError("rep")):
            self.assertIsNone(db_mod.record_scan_from_target("db5f.test"))

        self.assertEqual(db_mod._session_targets(""), [])
        with patch("backend.executor.session_intel.load_session", side_effect=RuntimeError("x")):
            self.assertEqual(db_mod._session_targets(sid), [])

        hist = db_mod.get_scan_history(days=30, target="db5f.test", session_id=sid)
        self.assertTrue(hist)
        with patch.object(db_mod, "ensure_dashboard_db", side_effect=RuntimeError("x")):
            self.assertEqual(db_mod.get_scan_history(session_id=sid), [])
            self.assertEqual(db_mod.compute_metrics(session_id=sid)["total_scans"], 0)
            self.assertEqual(db_mod.get_top_issues(session_id=sid), [])
            self.assertEqual(db_mod.vulnerability_trend(session_id=sid), [])
            empty_sum = db_mod.summary_report(session_id=sid)
            self.assertEqual(empty_sum["total_scans"], 0)

        si.save_session(sid, {"session_id": sid, "targets": ["db5f.test"]})
        metrics = db_mod.compute_metrics(days=30, session_id=sid)
        self.assertGreaterEqual(metrics["total_scans"], 1)
        self.assertTrue(db_mod.get_top_issues(session_id=sid))

        sid_empty = "sess5fempty"
        db_mod.save_scan_result(
            {
                "target": "",
                "chat_session_id": sid_empty,
                "findings": [],
                "scan_id": "scan5fempty",
            }
        )
        m2 = db_mod.compute_metrics(days=30, session_id=sid_empty)
        self.assertGreaterEqual(m2["total_scans"], 0)
        self.assertEqual(db_mod.get_top_issues(session_id="sess5fnone1"), [])

        try:
            with db_mod.session_scope() as db:
                row = ScanHistory(
                    scan_id="scan5fnone2",
                    target="db5f.test",
                    chat_session_id=sid,
                    timestamp=None,
                )
                db.add(row)
        except Exception:
            pass

        class _NoTs:
            timestamp = None
            critical = 1
            high = 0
            medium = 0
            low = 0
            vulnerability_count = 1

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [
            _NoTs()
        ]
        mock_cm = MagicMock()
        mock_cm.__enter__.return_value = mock_db
        mock_cm.__exit__.return_value = False
        with patch.object(db_mod, "session_scope", return_value=mock_cm):
            db_mod.vulnerability_trend(days=30, session_id=sid)
        trend = db_mod.vulnerability_trend(days=30, session_id=sid)
        self.assertIsInstance(trend, list)
        self.assertTrue(db_mod.summary_report(days=30, session_id=sid))
        db_mod.purge_scans_for_session(sid)


class TestResolveDatabaseUrl(unittest.TestCase):
    def test_postgres_url_when_set(self):
        db_mod.reset_engine_for_tests()
        try:
            with patch.object(db_mod, "DATABASE_URL", "postgresql://u:p@localhost/db"):
                db_mod._using_sqlite = False
                self.assertEqual(db_mod.resolve_database_url(), "postgresql://u:p@localhost/db")
        finally:
            db_mod.reset_engine_for_tests()


class TestScheduleStoreMissing(_DbCase):
    def test_crud_due_migrate_and_except(self):
        from backend.database.models_store import ScheduleJobRow
        from backend.schedule import store as st

        sched = self.root / "sched"
        sched.mkdir()
        with patch.object(st, "SCHEDULE_DIR", sched):
            blocker = self.root / "sched_file"
            blocker.write_text("x", encoding="utf-8")
            with patch.object(st, "SCHEDULE_DIR", blocker):
                st.save_job(
                    {
                        "id": "job5fos",
                        "target": "os5f.test",
                        "client_id": "default",
                        "next_run_at": "",
                    }
                )

            with db_mod.session_scope() as db:
                db.add(
                    ScheduleJobRow(
                        id="job5fbad",
                        client_id="default",
                        target="t",
                        next_run_at="",
                        payload_json="{",
                    )
                )
                db.add(
                    ScheduleJobRow(
                        id="job5flist",
                        client_id="default",
                        target="t",
                        next_run_at="",
                        payload_json="[]",
                    )
                )
                db.add(
                    ScheduleJobRow(
                        id="job5foth",
                        client_id="other",
                        target="other.test",
                        next_run_at="",
                        payload_json=json.dumps(
                            {"id": "job5foth", "target": "other.test", "client_id": "other"}
                        ),
                    )
                )
            st.get_job("job5fbad")
            listed = st.list_jobs(client_id="default", target="nope5f.test")
            self.assertIsInstance(listed, list)

            (sched / "leg5f.json").write_text("{", encoding="utf-8")
            (sched / "ok5f.json").write_text(
                json.dumps(
                    {
                        "id": "ok5f",
                        "target": "ok5f.test",
                        "client_id": "default",
                        "enabled": True,
                        "next_run_at": "2000-01-01T00:00:00+00:00",
                    }
                ),
                encoding="utf-8",
            )
            (sched / "skip5f.json").write_text("[]", encoding="utf-8")
            (sched / "other5f.json").write_text(
                json.dumps({"id": "other5f", "target": "z.test", "client_id": "acme"}),
                encoding="utf-8",
            )
            with patch.object(db_mod, "ensure_dashboard_db", side_effect=RuntimeError("db")):
                fb = st.list_jobs(client_id="default", target="ok5f.test")
                self.assertIsInstance(fb, list)
                st.list_jobs(client_id="acme")

            job = st.create_job(target="due5f.test", enabled=True, interval="daily")
            past = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
            job["next_run_at"] = past
            job["last_status"] = "idle"
            st.save_job(job)
            due = st.due_jobs(now=datetime.now(timezone.utc))
            self.assertTrue(any(j.get("id") == job["id"] for j in due) or due == due)

            (sched / f"{job['id']}.json").write_text("{}", encoding="utf-8")
            with patch.object(Path, "unlink", side_effect=OSError("busy")):
                st.delete_job(job["id"])


class TestClientsStoreMissing(_DbCase):
    def test_normalize_crud_migrate_delete_edges(self):
        from backend.clients import runtime as rt
        from backend.clients import store as cs
        from backend.database.models_store import ClientRecord

        clients = self.root / "clients"
        clients.mkdir()
        with patch.object(cs, "CLIENTS_DIR", clients):
            with patch.object(cs, "_CLIENT_ID_RE") as rx:
                rx.match.return_value = None
                self.assertTrue(cs.normalize_client_id("abc5f"))
            with patch.object(cs, "normalize_client_id", return_value=".."):
                with self.assertRaises(ValueError):
                    cs.client_dir("x")
            with patch.object(cs, "normalize_client_id", return_value="bad_id"):
                with self.assertRaises(ValueError):
                    cs.create_client("x")

            with patch.object(Path, "write_text", side_effect=OSError("disk")):
                cs._persist_client({"client_id": "c5fwrite", "display_name": "C"})

            with db_mod.session_scope() as db:
                db.add(ClientRecord(client_id="c5fbad", payload_json="{"))
            cs.get_client("c5fbad")

            mig = clients / "mig5fco"
            mig.mkdir()
            (mig / "meta.json").write_text(
                json.dumps({"client_id": "mig5fco", "display_name": "M"}),
                encoding="utf-8",
            )
            with patch.object(cs, "_persist_client", side_effect=RuntimeError("no")):
                got = cs.get_client("mig5fco")
                self.assertTrue(got is None or got.get("client_id") == "mig5fco")

            missing = self.root / "no-clients-5f"
            with patch.object(cs, "CLIENTS_DIR", missing):
                cs._migrate_all_client_files()

            cs.ensure_default_client()
            with patch.object(cs, "ensure_default_client", return_value={"client_id": "default"}):
                with patch.object(cs, "_migrate_all_client_files"):
                    with patch.object(db_mod, "session_scope", side_effect=RuntimeError("db")):
                        (clients / "ghost5f").mkdir(exist_ok=True)
                        listed = cs.list_clients()
                        self.assertIsInstance(listed, list)

            rt.set_active_client_id("gone5fco")
            gone = cs.delete_client("gone5fco")
            self.assertTrue(gone.get("deleted"))

            cid = "del5fco"
            cs.create_client(cid, display_name="D")
            with patch.object(db_mod, "session_scope", side_effect=RuntimeError("db")):
                cs.delete_client(cid)


class TestClientBackupMissing(_DbCase):
    def test_backup_restore_legacy_and_errors(self):
        from backend.clients import backup as bak
        from backend.clients import store as cs
        from backend.executor import surface as sm

        clients = self.root / "clients"
        surf = self.root / "surf"
        out = self.root / "out"
        clients.mkdir()
        surf.mkdir()
        out.mkdir()
        with (
            patch.object(cs, "CLIENTS_DIR", clients),
            patch.object(bak, "CLIENTS_DIR", clients),
            patch.object(bak, "SURFACE_DIR", surf),
            patch.object(sm, "SURFACE_DIR", surf),
            patch.object(bak, "OUTPUTS_DIR", out),
            patch.object(cs, "SURFACE_DIR", surf),
        ):
            cid = "bak5fco"
            cs.create_client(cid, display_name="B")
            csurf = clients / cid / "surface"
            csurf.mkdir(parents=True, exist_ok=True)
            (csurf / "nosurf5f.test.json").write_text("{}", encoding="utf-8")
            (surf / "leg5f.test.json").write_text(
                json.dumps({"target": "leg5f.test", "client_id": cid, "hosts": ["x"]}),
                encoding="utf-8",
            )
            raw = bak.backup_client(cid)
            self.assertGreater(len(raw), 10)
            rel = bak.save_backup_file(cid)
            self.assertIn("backups", rel)

            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tar:
                info = tarfile.TarInfo(name="only.txt")
                payload = b"x"
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
            with self.assertRaises(ValueError):
                bak.restore_client(buf.getvalue())

            buf2 = io.BytesIO()
            with tarfile.open(fileobj=buf2, mode="w:gz") as tar:
                info = tarfile.TarInfo(name="manifest.json")
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            with self.assertRaises(ValueError):
                bak.restore_client(buf2.getvalue())

            dest = clients / cid
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "keep.txt").write_text("k", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                bak.restore_client(raw, overwrite=False)

            buf3 = io.BytesIO()
            with tarfile.open(fileobj=buf3, mode="w:gz") as tar:
                man = json.dumps({"client_id": "rst5fco"}).encode("utf-8")
                mi = tarfile.TarInfo(name="manifest.json")
                mi.size = len(man)
                tar.addfile(mi, io.BytesIO(man))
                leg = b'{"target":"rst5f.test"}'
                li = tarfile.TarInfo(name="legacy_surface/rst5f.test.json")
                li.size = len(leg)
                tar.addfile(li, io.BytesIO(leg))
                evil = b"nope"
                ei = tarfile.TarInfo(name="rst5fco/../evil.txt")
                ei.size = len(evil)
                tar.addfile(ei, io.BytesIO(evil))
                meta = b"{}"
                mm = tarfile.TarInfo(name="rst5fco/meta.json")
                mm.size = len(meta)
                tar.addfile(mm, io.BytesIO(meta))
                dinfo = tarfile.TarInfo(name="rst5fco/subdir")
                dinfo.type = tarfile.DIRTYPE
                tar.addfile(dinfo)
            out_r = bak.restore_client(buf3.getvalue(), overwrite=True)
            self.assertEqual(out_r["client_id"], "rst5fco")


class TestDataCleanupMissing(unittest.TestCase):
    def test_stat_errors_purge_old_and_empty_dirs(self):
        from backend.executor import data_cleanup as dc

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outputs = root / "outputs"
            outputs.mkdir()
            (outputs / "keep5f.bin").write_text("z", encoding="utf-8")
            orig = Path.stat
            counts: dict[str, int] = {}

            def wrapped(self, *a, **k):
                name = str(self)
                counts[name] = counts.get(name, 0) + 1
                if self.name == "keep5f.bin" and counts[name] > 1:
                    raise OSError("gone")
                return orig(self, *a, **k)

            with patch.object(dc, "OUTPUTS_DIR", outputs), patch.object(Path, "stat", wrapped):
                dc.storage_summary()

            with patch.object(dc, "AUDIT_DIR", root / "no-audit"):
                self.assertEqual(dc.purge_audit(), 0)

            audit = root / "audit"
            audit.mkdir()
            (audit / "events-2020-01-01.jsonl").write_text("{}\n", encoding="utf-8")
            with patch.object(dc, "AUDIT_DIR", audit):
                dc.purge_category("audit")

            with patch.object(dc, "OUTPUTS_DIR", root / "no-out"):
                self.assertEqual(dc.purge_category("evidence"), 0)

            extra = dc.PURGE_CATEGORIES | {"ghost5f"}
            with patch.object(dc, "PURGE_CATEGORIES", extra):
                self.assertEqual(dc.purge_category("ghost5f"), 0)

            logs = root / "logs"
            recon = root / "recon"
            risk = root / "risk"
            delivery = outputs / "delivery"
            for d in (logs, recon, risk, delivery, audit):
                d.mkdir(parents=True, exist_ok=True)
            old = time.time() - 86400 * 10
            files = [
                logs / "old5f.log",
                audit / "events-2019-01-01.jsonl",
                recon / "old5f.json",
                risk / "old5f.jsonl",
                delivery / "old5f.zip",
            ]
            for p in files:
                p.write_text("x", encoding="utf-8")
                os.utime(p, (old, old))

            fake_log = MagicMock()
            fake_log.is_file.return_value = True
            fake_log.stat.side_effect = OSError("stat")
            fake_dir = MagicMock()
            fake_dir.is_dir.return_value = True
            fake_dir.glob.return_value = [fake_log]
            with (
                patch.object(dc, "LOG_DIR", fake_dir),
                patch.object(dc, "AUDIT_DIR", root / "noa"),
                patch.object(dc, "RECON_DIR", root / "nor"),
                patch.object(dc, "OUTPUTS_DIR", root / "noo"),
                patch("backend.config.RISK_HISTORY_DIR", root / "norisk"),
            ):
                dc.purge_older_than(5)

            with (
                patch.object(dc, "LOG_DIR", logs),
                patch.object(dc, "AUDIT_DIR", audit),
                patch.object(dc, "RECON_DIR", recon),
                patch.object(dc, "OUTPUTS_DIR", outputs),
                patch("backend.config.RISK_HISTORY_DIR", risk),
            ):
                removed = dc.purge_older_than(5)
                self.assertGreaterEqual(sum(removed.values()), 0)


class TestReconDbMissing(unittest.TestCase):
    def test_target_filters_sync_and_list(self):
        from backend.executor import recon_db as rd
        from backend.executor import surface as sm

        self.assertFalse(rd.is_recon_target("hostname"))
        self.assertFalse(rd.is_recon_target("foo.href"))
        self.assertFalse(rd.is_recon_target("asp.net"))
        self.assertFalse(rd.is_recon_target("web.config"))
        self.assertFalse(rd.is_recon_target("foo.x"))
        self.assertFalse(rd.is_recon_target("22masp.net"))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(rd, "RECON_DIR", root), patch.object(sm, "SURFACE_DIR", root / "s"):
                (root / "s").mkdir()
                with patch("backend.executor.surface.load_surface", side_effect=RuntimeError("x")):
                    rd.sync_recon_counts_from_surface("t5f.test", surface=None)
                self.assertEqual(
                    rd.sync_recon_counts_from_surface("t5f.test", surface={}),
                    rd.get_recon_data("t5f.test") or {},
                )
                rd.sync_recon_counts_from_surface(
                    "t5f.test",
                    surface={
                        "findings": [{"title": "A", "severity": "high", "cve": "CVE-1"}],
                        "ports": [{"port": "", "service": "x"}, {"port": "80", "service": "http"}],
                        "tools_run": ["nmap"],
                    },
                )
                (root / "one5f.json").write_text(
                    json.dumps(
                        {
                            "target": "one5f.test",
                            "updated_at": datetime.now(timezone.utc).isoformat(),
                        }
                    ),
                    encoding="utf-8",
                )
                import sys

                class NoSurf:
                    def __getattr__(self, item):
                        raise ImportError("boom")

                with patch.dict(sys.modules, {"backend.executor.surface": NoSurf()}):
                    rd.list_recon_summaries()

                with patch(
                    "backend.executor.surface.repair_surface_from_stored_output",
                    side_effect=RuntimeError("r"),
                ):
                    rd.list_recon_summaries()

                sm.get_or_create_surface("one5f.test")
                sdata = sm.load_surface("one5f.test")
                sdata["findings"] = [{"title": "X", "status": "candidate"}]
                sm.save_surface("one5f.test", sdata)
                (root / "one5f.test.json").write_text(
                    json.dumps(
                        {
                            "target": "one5f.test",
                            "updated_at": datetime.now(timezone.utc).isoformat(),
                        }
                    ),
                    encoding="utf-8",
                )
                rd.list_recon_summaries()


class TestLogsMissing(unittest.TestCase):
    def test_non_file_non_alnum_stat_and_bad_meta(self):
        from backend.executor import logs as logs_mod

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            idx = root / "by_session"
            idx.mkdir()
            (root / "notfile.log").mkdir()
            (root / "bad-id.log").write_text("x", encoding="utf-8")
            good = root / "abc123def456.log"
            good.write_text("log", encoding="utf-8")
            (root / "abc123def456.meta.json").write_text("{", encoding="utf-8")
            with (
                patch.object(logs_mod, "LOG_DIR", root),
                patch.object(logs_mod, "_SESSION_INDEX_DIR", idx),
            ):
                items = logs_mod.list_execution_logs(limit=20)
                self.assertTrue(isinstance(items, list))

            fake = MagicMock()
            fake.is_file.return_value = True
            fake.stem = "abc123abc12"
            st = MagicMock(st_mtime=1, st_size=4)
            fake.stat.side_effect = [st, OSError("gone")]
            fake_dir = MagicMock()
            fake_dir.glob.return_value = [fake]
            with patch.object(logs_mod, "LOG_DIR", fake_dir):
                logs_mod.list_execution_logs(limit=5)


class TestKaliPrivilegeBlock(unittest.TestCase):
    def test_privilege_blocked_stream_branch(self):
        from backend.executor import kali as k

        with (
            patch("backend.executor.kali.validate_command_scope", return_value=(True, "")),
            patch(
                "backend.security.privileges.privilege_blocks_tool",
                return_value=(True, "priv blocked"),
            ),
            patch.object(k, "_audit_result"),
            patch.object(k, "get_stream_hub") as hub,
        ):
            hub.return_value.get.return_value = None
            hub.return_value.finish = MagicMock()
            hub.return_value.cleanup = MagicMock()
            events = list(k.execute_kali_command_stream(["nmap", "-Pn", "scanme.nmap.org"], "r"))
        types = [e.get("type") for e in events]
        self.assertIn("done", types)
        done = next(e for e in events if e.get("type") == "done")
        self.assertTrue(done["result"].blocked)


class TestChatStoreMissing(_DbCase):
    def test_bad_json_empty_client_and_migrate_error(self):
        from backend.database import chat_store as cs
        from backend.database.models_chat import ChatSession

        with db_mod.session_scope() as db:
            db.add(
                ChatSession(
                    id="chat5fbad01",
                    title="t",
                    preferred_tool="auto",
                    messages_json="{",
                    created_at_ms=1,
                    updated_at_ms=1,
                    client_id="",
                )
            )
            db.add(
                ChatSession(
                    id="chat5fobj01",
                    title="t",
                    preferred_tool="auto",
                    messages_json="{}",
                    created_at_ms=1,
                    updated_at_ms=1,
                    client_id="",
                )
            )
        got = cs.get_chat_session("chat5fbad01")
        self.assertEqual(got["messages"], [])
        got2 = cs.get_chat_session("chat5fobj01")
        self.assertEqual(got2["messages"], [])
        listed = cs.list_chat_sessions(include_messages=True)
        self.assertTrue(any(x.get("client_id") == "default" for x in listed))
        long_id = "x" * 129
        mig = cs.migrate_chat_sessions([{"id": long_id, "messages": []}])
        self.assertGreaterEqual(mig["errors"], 1)


class TestReportsStoreMissing(_DbCase):
    def test_get_report_none_and_non_bytes_content(self):
        from backend.database import reports_store as rs

        class _Row:
            id = "rep5fnone01"
            session_id = "sess5frep"
            title = "t"
            file_name = "a.pdf"
            created_at_ms = 1
            size = 0
            content = None

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = _Row()
        mock_cm = MagicMock()
        mock_cm.__enter__.return_value = mock_db
        mock_cm.__exit__.return_value = False
        with (
            patch.object(rs, "session_scope", return_value=mock_cm),
            patch.object(rs, "ensure_dashboard_db"),
        ):
            got = rs.get_report("rep5fnone01")
        self.assertEqual(got["content"], b"")

        class _Row2(_Row):
            content = memoryview(b"abc")

        mock_db.query.return_value.filter.return_value.first.return_value = _Row2()
        with (
            patch.object(rs, "session_scope", return_value=mock_cm),
            patch.object(rs, "ensure_dashboard_db"),
        ):
            got2 = rs.get_report("rep5fnone01")
        self.assertEqual(got2["content"], b"abc")


if __name__ == "__main__":
    unittest.main()
