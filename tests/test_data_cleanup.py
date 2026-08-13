"""Testes de exclusão de dados gerados automaticamente."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.executor import data_cleanup as dc
from backend.executor import files_store
from backend.main import app
from fastapi.testclient import TestClient


class TestDataCleanup(unittest.TestCase):
    def test_storage_summary_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with (
                patch.object(dc, "LOG_DIR", root / "logs"),
                patch.object(dc, "RECON_DIR", root / "recon"),
                patch.object(dc, "AUDIT_DIR", root / "audit"),
                patch.object(dc, "SURFACE_DIR", root / "surface"),
                patch.object(dc, "OUTPUTS_DIR", root / "outputs"),
            ):
                (root / "logs").mkdir()
                (root / "recon").mkdir()
                summary = dc.storage_summary()
                self.assertIn("logs", summary["categories"])
                self.assertEqual(summary["categories"]["logs"]["count"], 0)

    def test_delete_log_recon_surface_and_purge(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log_dir = root / "logs"
            recon_dir = root / "recon"
            surface_dir = root / "surface"
            outputs = root / "outputs"
            audit_dir = root / "audit"
            for d in (log_dir, recon_dir, surface_dir, outputs, audit_dir):
                d.mkdir(parents=True)

            (log_dir / "abc123.log").write_text("log", encoding="utf-8")
            (recon_dir / "scanme.nmap.org.json").write_text("{}", encoding="utf-8")
            (surface_dir / "scanme.nmap.org.json").write_text(
                json.dumps({"target": "scanme.nmap.org", "findings": []}),
                encoding="utf-8",
            )
            ev = outputs / "evidence" / "scanme.nmap.org"
            ev.mkdir(parents=True)
            (ev / "f1.txt").write_text("ev", encoding="utf-8")
            (outputs / "scan.txt").write_text("out", encoding="utf-8")
            (audit_dir / "events-2026-07-16.jsonl").write_text("{}\n", encoding="utf-8")

            with (
                patch.object(dc, "LOG_DIR", log_dir),
                patch.object(dc, "RECON_DIR", recon_dir),
                patch.object(dc, "SURFACE_DIR", surface_dir),
                patch.object(dc, "OUTPUTS_DIR", outputs),
                patch.object(dc, "AUDIT_DIR", audit_dir),
                patch.object(files_store, "OUTPUTS_DIR", outputs),
            ):
                self.assertTrue(dc.delete_execution_log("abc123")["ok"])
                self.assertFalse(dc.delete_execution_log("abc123")["ok"])
                self.assertTrue(dc.delete_recon("scanme.nmap.org"))
                self.assertTrue(dc.delete_surface("scanme.nmap.org"))
                self.assertFalse((ev).exists())
                self.assertTrue(dc.delete_output_file("scan.txt"))
                self.assertEqual(dc.purge_audit(), 1)
                removed = dc.purge_categories(["logs", "recon", "surface"])
                self.assertIn("logs", removed)

    def test_delete_audit_only_log_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log_dir = root / "logs"
            audit_dir = root / "audit"
            log_dir.mkdir()
            audit_dir.mkdir()
            audit_file = audit_dir / "events-2026-07-16.jsonl"
            audit_file.write_text(
                json.dumps(
                    {
                        "ts": "2026-07-16T12:00:00+00:00",
                        "event": "tool_execution",
                        "log_file_id": "travtest1",
                        "tool": "nmap",
                        "command": "nmap test",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            with (
                patch.object(dc, "LOG_DIR", log_dir),
                patch("backend.security.audit.AUDIT_DIR", audit_dir),
            ):
                result = dc.delete_execution_log("travtest1")
                self.assertTrue(result["ok"])
                self.assertFalse(result["file_deleted"])
                self.assertEqual(result["audit_removed"], 1)
                self.assertEqual(audit_file.read_text(encoding="utf-8").strip(), "")

    def test_api_data_routes(self):
        client = TestClient(app)
        res = client.get("/api/data/summary")
        self.assertEqual(res.status_code, 200)
        self.assertIn("categories", res.json())

        res = client.get("/api/data/logs")
        self.assertEqual(res.status_code, 200)
        self.assertIn("logs", res.json())

        res = client.post("/api/data/purge", json={"categories": ["logs"], "confirm": False})
        self.assertEqual(res.status_code, 400)

        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp) / "logs"
            log_dir.mkdir()
            (log_dir / "deadbeef.log").write_text("x", encoding="utf-8")
            with patch.object(dc, "LOG_DIR", log_dir):
                res = client.delete("/api/data/logs/deadbeef")
                self.assertEqual(res.status_code, 200)
                self.assertFalse((log_dir / "deadbeef.log").exists())


if __name__ == "__main__":
    unittest.main()
