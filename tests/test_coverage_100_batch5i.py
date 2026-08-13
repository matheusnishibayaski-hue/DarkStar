"""Lote 5i: fechar os últimos statements (Miss) até 100%."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from backend.database import db as db_mod
from fastapi import HTTPException

from tests.auth_patch import patch_chat_api_token


class TestLastMisses(unittest.TestCase):
    def test_tool_parse_default_name_and_scanner_multiline(self):
        from backend.ai.providers import tool_parse as tp
        from backend.ai.scanner_import import import_scanner_payload

        call = tp._dict_to_tool_call({"command": "nmap -sV t.test", "reason": "recon"})
        self.assertIsNotNone(call)
        self.assertEqual(call.name, "run_kali_tool")

        with patch("backend.ai.scanner_import.import_nuclei_jsonl", return_value={"ok": True}):
            out = import_scanner_payload("t.test", '{\n"template-id": "x"\n}', format="auto")
            self.assertEqual(out, {"ok": True})
            out2 = import_scanner_payload("t.test", '[{"template-id": "x"}]', format="auto")
        self.assertEqual(out2, {"ok": True})
        with patch("backend.ai.scanner_import.import_nessus_csv", return_value={"nessus": True}):
            nessus = import_scanner_payload(
                "t.test", "Plugin Name,Risk Factor\nSSL,High\n", format="auto"
            )
        self.assertEqual(nessus, {"nessus": True})

    def test_remediation_invalid_json_no_fence(self):
        from backend.ai.remediation_ai import _extract_json_object

        self.assertIsNone(_extract_json_object("{not json}"))

    def test_cli_openrouter_and_scope_lock(self):
        from backend import cli as c
        from backend.cli_report import _sarif_level

        self.assertEqual(_sarif_level("high"), "error")
        self.assertEqual(_sarif_level("HIGH"), "error")

        with (
            patch(
                "backend.ai.providers.runtime.get_active_provider_name", return_value="openrouter"
            ),
            patch.object(c, "OPENROUTER_API_KEY", ""),
        ):
            ai = c._check_ai()
        self.assertEqual(ai["status"], "error")
        self.assertIn("OPENROUTER", ai["message"])

        with (
            patch.object(c, "scope_lock_enabled", return_value=True),
            patch.object(c, "ALLOWED_TARGETS", ["a.test"]),
        ):
            cfg = c._check_config()
        self.assertEqual(cfg["status"], "ok")
        self.assertIn("ON", cfg["message"])

    def test_backup_skip_duplicate_surface(self):
        from backend.clients import backup as bk
        from backend.clients import store as cs
        from backend.executor import surface as sm

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cid = "bak5i"
            cdir = root / cid
            surf_dir = cdir / "surface"
            surf_dir.mkdir(parents=True)
            (surf_dir / "dup.test.json").write_text("{}", encoding="utf-8")
            with (
                patch.object(bk, "CLIENTS_DIR", root),
                patch.object(bk, "SURFACE_DIR", root / "legacy"),
                patch.object(bk, "get_client", return_value={"id": cid}),
                patch.object(bk, "client_dir", return_value=cdir),
                patch.object(cs, "list_client_targets", return_value=["dup.test"]),
                patch.object(sm, "load_surface", return_value={"target": "dup.test"}),
            ):
                raw = bk.backup_client(cid)
            self.assertGreater(len(raw), 20)

    def test_db_postgres_url_and_cleanup_stat(self):
        from backend.executor import data_cleanup as dc

        prev_url = db_mod.DATABASE_URL
        prev_flag = db_mod._using_sqlite
        try:
            db_mod.DATABASE_URL = "postgresql://u:p@127.0.0.1/db"
            db_mod._using_sqlite = False
            self.assertEqual(db_mod.resolve_database_url(), "postgresql://u:p@127.0.0.1/db")
            db_mod.DATABASE_URL = ""
            db_mod._using_sqlite = False
            self.assertTrue(db_mod.resolve_database_url().startswith("sqlite:"))
            db_mod.DATABASE_URL = "postgresql://u:p@127.0.0.1/db"
            db_mod._using_sqlite = True
            self.assertTrue(db_mod.resolve_database_url().startswith("sqlite:"))
        finally:
            db_mod.DATABASE_URL = prev_url
            db_mod._using_sqlite = prev_flag

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            other = root / "other.bin"
            other.write_text("z", encoding="utf-8")
            orig = Path.stat
            stat_counts: dict[str, int] = {}

            def _stat(self, *a, **kw):
                if self.name == "other.bin":
                    key = str(self)
                    n = stat_counts.get(key, 0)
                    stat_counts[key] = n + 1
                    if n >= 1:
                        raise OSError("stat")
                return orig(self, *a, **kw)

            with patch.object(dc, "OUTPUTS_DIR", root), patch.object(Path, "stat", _stat):
                summary = dc.storage_summary()
            self.assertIn("categories", summary)

    def test_session_intel_skip_empty_surface(self):
        from backend.executor import session_intel as si

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            url = f"sqlite:///{(root / 't.db').as_posix()}"
            patches = [
                patch.object(db_mod, "DATABASE_URL", ""),
                patch.object(db_mod, "_SQLITE_PATH", root / "t.db"),
                patch.object(db_mod, "resolve_database_url", return_value=url),
                patch.object(si, "INTEL_SESSIONS_DIR", root / "intel"),
            ]
            for p in patches:
                p.start()
            try:
                db_mod.reset_engine_for_tests()
                db_mod.init_db()
                with (
                    patch.object(si, "load_session", return_value={"targets": ["gone.test"]}),
                    patch.object(si, "load_surface", return_value=None),
                    patch.object(si, "_session_path", return_value=None),
                    patch("backend.database.db.ensure_dashboard_db"),
                ):
                    si.delete_session_intel("del5i")
            finally:
                for p in patches:
                    p.stop()
                db_mod.reset_engine_for_tests()

    def test_surface_empty_title_and_duplicate_nuclei(self):
        from backend.executor import surface as sm

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(sm, "SURFACE_DIR", root):
                sm.update_surface_from_execution(
                    "surf5iws.test",
                    command="httpx -silent",
                    tool="httpx",
                    stdout="[critical] [tid-ws]\t",
                    stderr="",
                    success=True,
                    blocked=False,
                )
                dup = "[critical] [tid-dup] Missing HSTS\n[critical] [tid-dup] Missing HSTS\n"
                sm.update_surface_from_execution(
                    "surf5idup.test",
                    command="httpx -silent",
                    tool="httpx",
                    stdout=dup,
                    stderr="",
                    success=True,
                    blocked=False,
                )
                sm.update_surface_from_execution(
                    "surf5iinfo.test",
                    command="httpx -silent",
                    tool="httpx",
                    stdout="[info]\t",
                    stderr="",
                    success=True,
                    blocked=False,
                )

    def test_suggest_dup_text_and_threat_non_dict(self):
        import inspect

        from backend.intelligence import threat_modeling as tm
        from backend.intelligence.suggest import build_suggestions

        pats = [
            {"pattern_key": "dup-a", "frequency": 9, "title_sample": "same-check"},
            {"pattern_key": "dup-b", "frequency": 8, "title_sample": "same-check"},
        ]
        sg_mod = inspect.getmodule(build_suggestions)
        with patch.object(sg_mod, "top_patterns", return_value=pats):
            out = build_suggestions(
                {
                    "urls": [],
                    "ports": [{"port": "22"}],
                    "findings": [],
                    "tools_run": ["nuclei", "nmap"],
                },
                {},
                limit=10,
            )
        texts = [s.get("suggestion") for s in out]
        self.assertEqual(texts.count("Checar padrão recorrente: same-check"), 1)

        row = MagicMock()
        row.threat_model_json = "[1, 2]"
        session = MagicMock()
        session.query.return_value.filter_by.return_value.one_or_none.return_value = row
        cm = MagicMock()
        cm.__enter__.return_value = session
        cm.__exit__.return_value = False
        with (
            patch.object(tm.store, "use_postgres", return_value=False),
            patch.object(tm.store, "load_threat_model_json", return_value={"from": "json"}),
        ):
            self.assertEqual(tm.get_threat_model("json-only.test"), {"from": "json"})
        with (
            patch.object(tm.store, "use_postgres", return_value=True),
            patch("backend.intelligence.store.use_postgres", return_value=True),
            patch("backend.database.db.init_db"),
            patch("backend.database.db.session_scope", return_value=cm),
        ):
            session.query.return_value.filter_by.return_value.one_or_none.return_value = row
            self.assertIsNone(tm.get_threat_model("tm5i.test"))
            row_ok = MagicMock()
            row_ok.threat_model_json = '{"ok": true}'
            session.query.return_value.filter_by.return_value.one_or_none.return_value = row_ok
            self.assertEqual(tm.get_threat_model("tm5i-dict.test"), {"ok": True})

    def test_route_direct_remaining_branches(self):
        from backend.routes import compliance as comp_rt
        from backend.routes import data as data_rt
        from backend.routes import engagements as eng
        from backend.routes import intelligence as intel_rt
        from backend.routes import portfolio as port
        from backend.routes import system as sys_rt
        from backend.schedule import store as st

        with (
            patch.object(comp_rt, "COMPLIANCE_ENABLED", True),
            patch.object(comp_rt, "_ensure_enabled"),
            patch.object(comp_rt, "get_framework", return_value={"id": "LGPD"}),
            patch.object(comp_rt, "generate_compliance_report", return_value={"ok": True}),
        ):
            self.assertEqual(comp_rt.api_report_get("comp.test", "json"), {"ok": True})
            md = comp_rt.api_report_get("comp.test", "md")
            self.assertEqual(md.media_type, "text/markdown")
            with self.assertRaises(HTTPException) as ctx:
                comp_rt.api_report_get("comp.test", "xml")
            self.assertEqual(ctx.exception.status_code, 400)
            self.assertIn("format", str(ctx.exception.detail))

        with patch.object(data_rt, "purge_audit", return_value=0):
            with self.assertRaises(HTTPException) as ctx:
                data_rt.api_delete_audit(date="2020-01-01", all=False)
            self.assertEqual(ctx.exception.status_code, 404)

        req = eng.FindingStatusRequest(status="confirmed")
        with patch.object(eng, "mark_finding_status", side_effect=lambda *a, **k: None):
            with self.assertRaises(HTTPException) as ctx:
                eng.api_finding_status("eng5i.test", "fid", req)
            self.assertEqual(ctx.exception.status_code, 404)
            self.assertIn("Finding", str(ctx.exception.detail))
        with patch.object(
            eng, "mark_finding_status", return_value={"id": "fid", "status": "confirmed"}
        ):
            self.assertEqual(eng.api_finding_status("ok.test", "fid", req)["id"], "fid")
        bad = eng.FindingStatusRequest(status="nope")
        with self.assertRaises(HTTPException) as ctx:
            eng.api_finding_status("ok.test", "fid", bad)
        self.assertEqual(ctx.exception.status_code, 400)

        with (
            patch.object(intel_rt, "INTELLIGENCE_ENABLED", True),
            patch.object(intel_rt, "get_threat_model", return_value={"target": "ok"}),
        ):
            self.assertEqual(intel_rt.api_threat_model_get("ok.test")["target"], "ok")

        self.assertEqual(port._host("unknown"), "")
        with patch.object(
            port,
            "risk_score_for_target",
            return_value={"count": 2, "score": 10},
        ):
            risk = port._risk_payload("r.test", [])
        self.assertEqual(risk["count"], 2)

        with (
            patch("backend.executor.surface.repair_surface_from_stored_output"),
            patch("backend.executor.surface.load_surface", return_value={"findings": []}),
            patch("backend.executor.recon_db.sync_recon_counts_from_surface"),
            patch.object(sys_rt, "get_recon_data", return_value=None),
        ):
            body = sys_rt.api_recon_detail("recon5i.test")
        self.assertEqual(body["target"], "recon5i.test")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "job.json").write_text(
                json.dumps({"id": "j1", "target": "other.test", "client_id": "default"}),
                encoding="utf-8",
            )
            with (
                patch.object(st, "SCHEDULE_DIR", root),
                patch("backend.database.db.session_scope", side_effect=RuntimeError("db")),
            ):
                jobs = st.list_jobs(target="wanted.test")
            self.assertEqual(jobs, [])


class TestDashboardPageBreak(unittest.TestCase):
    def test_pdf_page_break_with_many_rows(self):
        from backend.main import app
        from fastapi.testclient import TestClient

        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        url = f"sqlite:///{(root / 't.db').as_posix()}"
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
            sid = "dash5ipage"
            hist = [
                {
                    "target": f"t{i}.test",
                    "vulnerability_count": 1,
                    "critical": 0,
                    "timestamp": "2026-01-01",
                }
                for i in range(50)
            ]
            from backend.routes import dashboard as dash

            with (
                patch_chat_api_token(""),
                patch.object(dash, "get_scan_history", return_value=hist),
                patch.object(dash, "compute_metrics", return_value={"total_scans": 50}),
            ):
                client = TestClient(app)
                r = client.get(f"/api/dashboard/export?format=pdf&days=30&session_id={sid}")
                self.assertEqual(r.status_code, 200)
        finally:
            for p in patches:
                p.stop()
            db_mod.reset_engine_for_tests()
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
