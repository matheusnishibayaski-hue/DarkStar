"""MSSP restante: schedule, FP learn, import, portfolio, roles, retention."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.ai import fp_learn
from backend.ai.fp_learn import is_suppressed, list_suppressed, remember_false_positive
from backend.ai.risk_history import load_risk_history, previous_score, record_risk_snapshot
from backend.ai.scanner_import import import_nessus_csv
from backend.clients import backup as backup_mod
from backend.clients import store as clients_store
from backend.database import db as db_mod
from backend.executor import surface as surface_mod
from backend.executor.data_cleanup import purge_older_than
from backend.executor.surface import get_or_create_surface, save_surface
from backend.schedule import store as schedule_store
from backend.security.roles import method_allowed


class TestFpLearn(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        db_mod.reset_engine_for_tests()
        fp_learn.reset_for_tests()
        self._url = f"sqlite:///{(self.root / 'fp.db').as_posix()}"
        self.patches = [
            patch.object(db_mod, "DATABASE_URL", ""),
            patch.object(db_mod, "_SQLITE_PATH", self.root / "fp.db"),
            patch.object(db_mod, "resolve_database_url", return_value=self._url),
            patch.object(fp_learn, "FP_SUPPRESS_PATH", self.root / "missing-fp.json"),
        ]
        for p in self.patches:
            p.start()
        db_mod.reset_engine_for_tests()
        db_mod.init_db()
        fp_learn._migrated = True

    def tearDown(self):
        for p in self.patches:
            p.stop()
        db_mod.reset_engine_for_tests()
        fp_learn.reset_for_tests()
        self.tmp.cleanup()

    def test_remember_and_suppress(self):
        f = {
            "title": "Missing HSTS",
            "cve": "",
            "template_id": "http-missing-hsts",
            "severity": "medium",
        }
        remember_false_positive(f, target="t.com")
        self.assertTrue(is_suppressed(f))
        self.assertGreaterEqual(len(list_suppressed()), 1)

    def test_legacy_json_import_once(self):
        path = self.root / "legacy.json"
        path.write_text(
            json.dumps(
                {
                    "patterns": {
                        "title:ok-nmap": {
                            "pattern_key": "title:ok-nmap",
                            "finding_type": "title",
                            "title": "OK — nmap",
                            "hits": 2,
                            "targets": ["lab.test"],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        self.patches[-1].stop()
        json_patch = patch.object(fp_learn, "FP_SUPPRESS_PATH", path)
        json_patch.start()
        self.patches[-1] = json_patch
        fp_learn.reset_for_tests()
        f = {"title": "OK — nmap"}
        self.assertTrue(is_suppressed(f))
        items = list_suppressed()
        self.assertTrue(any(str(i.get("title") or "").startswith("OK") for i in items))
        self.assertFalse(path.is_file())
        self.assertTrue(is_suppressed(f))


class TestRiskHistory(unittest.TestCase):
    def test_record_and_previous(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch("backend.ai.risk_history.RISK_HISTORY_DIR", root):
                record_risk_snapshot("hist.test", {"score": 10, "band": "low", "label": "Baixo"})
                record_risk_snapshot("hist.test", {"score": 40, "band": "medium", "label": "Médio"})
                hist = load_risk_history("hist.test")
                self.assertEqual(len(hist), 2)
                self.assertEqual(previous_score("hist.test"), 10.0)


class TestScheduleStore(unittest.TestCase):
    def test_create_list_advance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            url = f"sqlite:///{(root / 't.db').as_posix()}"
            db_mod.reset_engine_for_tests()
            patches = [
                patch.object(db_mod, "DATABASE_URL", ""),
                patch.object(db_mod, "_SQLITE_PATH", root / "t.db"),
                patch.object(db_mod, "resolve_database_url", return_value=url),
                patch.object(schedule_store, "SCHEDULE_DIR", root),
            ]
            for p in patches:
                p.start()
            try:
                db_mod.reset_engine_for_tests()
                db_mod.init_db()
                job = schedule_store.create_job(
                    target="sched.test",
                    interval="weekly",
                    job_type="remind",
                )
                self.assertTrue(job["id"])
                items = schedule_store.list_jobs(target="sched.test")
                self.assertEqual(len(items), 1)
                advanced = schedule_store.advance_job(job, status="ok")
                self.assertEqual(advanced["last_status"], "ok")
                self.assertTrue(schedule_store.delete_job(job["id"]))
            finally:
                for p in patches:
                    p.stop()
                db_mod.reset_engine_for_tests()

    def test_custom_interval_days_repeat(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            url = f"sqlite:///{(root / 't.db').as_posix()}"
            db_mod.reset_engine_for_tests()
            patches = [
                patch.object(db_mod, "DATABASE_URL", ""),
                patch.object(db_mod, "_SQLITE_PATH", root / "t.db"),
                patch.object(db_mod, "resolve_database_url", return_value=url),
                patch.object(schedule_store, "SCHEDULE_DIR", root),
            ]
            for p in patches:
                p.start()
            try:
                db_mod.reset_engine_for_tests()
                db_mod.init_db()
                job = schedule_store.create_job(
                    target="repeat.test",
                    job_type="repeat",
                    interval_days=15,
                    scan_profile="basic",
                    chat_session_id="sess-abc12345",
                )
                self.assertEqual(job["job_type"], "repeat")
                self.assertEqual(job["interval"], "custom")
                self.assertEqual(job["interval_days"], 15)
                nxt = schedule_store._parse_iso(job["next_run_at"])
                delta = (nxt - schedule_store._now()).total_seconds()
                self.assertGreater(delta, 14 * 86400 - 60)
                self.assertLess(delta, 16 * 86400)
                self.assertEqual(job["chat_session_id"], "sess-abc12345")
            finally:
                for p in patches:
                    p.stop()
                db_mod.reset_engine_for_tests()


class TestScannerImport(unittest.TestCase):
    def test_nessus_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(surface_mod, "SURFACE_DIR", root):
                with patch.object(fp_learn, "_migrated", True):
                    get_or_create_surface("import.test")
                    csv_body = (
                        "Plugin Name,Severity,CVE,Host,Port\n"
                        "SSL Certificate Expired,High,CVE-2020-1234,import.test,443\n"
                    )
                    result = import_nessus_csv("import.test", csv_body)
                    self.assertEqual(result["imported"], 1)
                    data = surface_mod.load_surface("import.test")
                    self.assertTrue(data.get("findings"))


class TestBackup(unittest.TestCase):
    def test_backup_restore_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            url = f"sqlite:///{(root / 't.db').as_posix()}"
            db_mod.reset_engine_for_tests()
            patches = [
                patch.object(db_mod, "DATABASE_URL", ""),
                patch.object(db_mod, "_SQLITE_PATH", root / "t.db"),
                patch.object(db_mod, "resolve_database_url", return_value=url),
                patch.object(clients_store, "CLIENTS_DIR", root),
                patch("backend.clients.store.CLIENTS_DIR", root),
                patch("backend.clients.backup.CLIENTS_DIR", root),
                patch("backend.clients.backup.SURFACE_DIR", root / "surface"),
            ]
            for p in patches:
                p.start()
            try:
                db_mod.reset_engine_for_tests()
                db_mod.init_db()
                (root / "surface").mkdir()
                clients_store.create_client("bak-co", display_name="Bak")
                raw = backup_mod.backup_client("bak-co")
                self.assertGreater(len(raw), 20)
                import shutil

                shutil.rmtree(root / "bak-co", ignore_errors=True)
                out = backup_mod.restore_client(raw, overwrite=True)
                self.assertEqual(out["client_id"], "bak-co")
            finally:
                for p in patches:
                    p.stop()
                db_mod.reset_engine_for_tests()


class TestRoles(unittest.TestCase):
    def test_viewer_blocks_write(self):
        import backend.security.roles as roles_mod

        with patch.object(roles_mod, "OPERATOR_ROLE", "viewer"):
            self.assertTrue(method_allowed("GET", "/api/portfolio"))
            self.assertFalse(method_allowed("POST", "/api/engagements"))


class TestRetention(unittest.TestCase):
    def test_purge_older_skips_when_zero(self):
        result = purge_older_than(0)
        self.assertEqual(result.get("skipped"), 1)


class TestLifecycle(unittest.TestCase):
    def test_surface_lifecycle_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(surface_mod, "SURFACE_DIR", root):
                data = get_or_create_surface("life.test")
                self.assertEqual(data.get("lifecycle"), "active")
                data["lifecycle"] = "paused"
                save_surface("life.test", data)
                again = surface_mod.load_surface("life.test")
                self.assertEqual(again.get("lifecycle"), "paused")


if __name__ == "__main__":
    unittest.main()
