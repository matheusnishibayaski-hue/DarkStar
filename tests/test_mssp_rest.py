"""MSSP restante: schedule, FP learn, import, portfolio, roles, retention."""

from __future__ import annotations

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
from backend.executor import surface as surface_mod
from backend.executor.data_cleanup import purge_older_than
from backend.executor.surface import get_or_create_surface, save_surface
from backend.schedule import store as schedule_store
from backend.security.roles import method_allowed


class TestFpLearn(unittest.TestCase):
    def test_remember_and_suppress(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fp.json"
            with patch.object(fp_learn, "FP_SUPPRESS_PATH", path):
                f = {
                    "title": "Missing HSTS",
                    "cve": "",
                    "template_id": "http-missing-hsts",
                    "severity": "medium",
                }
                remember_false_positive(f, target="t.com")
                self.assertTrue(is_suppressed(f))
                self.assertGreaterEqual(len(list_suppressed()), 1)


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
            with patch.object(schedule_store, "SCHEDULE_DIR", root):
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


class TestScannerImport(unittest.TestCase):
    def test_nessus_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(surface_mod, "SURFACE_DIR", root):
                with patch("backend.ai.fp_learn.FP_SUPPRESS_PATH", Path(tmp) / "fp.json"):
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
            with patch.object(clients_store, "CLIENTS_DIR", root):
                with patch("backend.clients.store.CLIENTS_DIR", root):
                    with patch("backend.clients.backup.CLIENTS_DIR", root):
                        with patch("backend.clients.backup.SURFACE_DIR", root / "surface"):
                            (root / "surface").mkdir()
                            clients_store.create_client("bak-co", display_name="Bak")
                            raw = backup_mod.backup_client("bak-co")
                            self.assertGreater(len(raw), 20)
                            # limpa e restaura
                            import shutil

                            shutil.rmtree(root / "bak-co", ignore_errors=True)
                            out = backup_mod.restore_client(raw, overwrite=True)
                            self.assertEqual(out["client_id"], "bak-co")


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
