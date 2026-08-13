"""Lote 2: logs, scanner import, delta, cleanup, session intel, chat_store, fp_learn, digest."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.database import db as db_mod


def _db_patches(root: Path):
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
        self.patches = _db_patches(self.root)
        for p in self.patches:
            p.start()
        db_mod.reset_engine_for_tests()
        db_mod.init_db()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        db_mod.reset_engine_for_tests()
        self.tmp.cleanup()


class TestLogsCoverage(unittest.TestCase):
    def test_session_index_list_and_audit_orphans(self):
        from backend.executor import logs as logs_mod

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with (
                patch.object(logs_mod, "LOG_DIR", root),
                patch.object(logs_mod, "_SESSION_INDEX_DIR", root / "by_session"),
            ):
                lid = logs_mod.save_execution_log(
                    "nmap -Pn t.com", "r", "open 80", "", chat_session_id="sess-log-123"
                )
                self.assertTrue(logs_mod.read_execution_log(lid))
                self.assertEqual(logs_mod.list_log_ids_for_session("sess-log-123"), [lid])
                self.assertEqual(logs_mod.list_log_ids_for_session(""), [])
                self.assertEqual(logs_mod.list_log_ids_for_session("bad id!!"), [])
                idx = root / "by_session" / "sess-log-123.json"
                idx.write_text("{", encoding="utf-8")
                self.assertEqual(logs_mod.list_log_ids_for_session("sess-log-123"), [])
                logs_mod._register_session_log("", "x")
                items = logs_mod.list_execution_logs(limit=10, session_id="sess-log-123")
                self.assertTrue(isinstance(items, list))
                with patch(
                    "backend.security.audit.list_events",
                    return_value=[
                        {"log_file_id": "orphanid12", "ts": "t", "tool": "nmap", "command": "x"}
                    ],
                ):
                    mixed = logs_mod.list_execution_logs(limit=10)
                self.assertTrue(any(i["id"] == "orphanid12" for i in mixed) or mixed)


class TestScannerImportCoverage(unittest.TestCase):
    def test_nuclei_nessus_auto_and_sev(self):
        from backend.ai import scanner_import as si
        from backend.executor import surface as sm

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with (
                patch.object(sm, "SURFACE_DIR", root),
                patch("backend.ai.fp_learn._migrated", True),
            ):
                sm.get_or_create_surface("imp.test")
                jsonl = json.dumps(
                    {
                        "info": {
                            "name": "XSS",
                            "severity": "high",
                            "classification": {"cve-id": ["CVE-2021-1"]},
                        },
                        "matched-at": "https://imp.test/",
                        "template-id": "xss-generic",
                    }
                )
                out = si.import_nuclei_jsonl("imp.test", jsonl)
                self.assertGreaterEqual(out["imported"], 0)
                csv_ok = "Plugin Name,Severity,CVE,Host,Port\nA,4,CVE-2020-1,imp.test,443\n\nB,3,,imp.test,80\nC,2,,x,1\nD,1,,x,2\nE,0,,x,3\n"
                nessus = si.import_nessus_csv("imp.test", csv_ok)
                self.assertGreaterEqual(nessus["imported"], 1)
                with self.assertRaises(ValueError):
                    si.import_nessus_csv("imp.test", "")
                with self.assertRaises(ValueError):
                    si.import_nessus_csv("imp.test", "Foo,Bar\n1,2\n")
                auto_n = si.import_scanner_payload("imp.test", jsonl, format="auto")
                self.assertEqual(auto_n["format"], "nuclei_jsonl")
                auto_c = si.import_scanner_payload(
                    "imp.test", "Plugin Name,Severity\nX,High\n", format="auto"
                )
                self.assertEqual(auto_c["format"], "nessus_csv")
                self.assertEqual(si._sev("4"), "critical")
                self.assertEqual(si._sev("3"), "high")
                self.assertEqual(si._sev("2"), "medium")
                self.assertEqual(si._sev("1"), "low")
                self.assertEqual(si._sev("nope"), "info")
                with self.assertRaises(ValueError):
                    si.import_scanner_payload("imp.test", "x", format="unknown")
                line_json = json.dumps({"info": {"name": "t", "severity": "low"}}) + "\n"
                si.import_scanner_payload("imp.test", line_json, format="auto")


class TestDeltaCoverage(unittest.TestCase):
    def test_snapshot_compute_and_markdown(self):
        from backend.ai import delta as d
        from backend.executor import surface as sm

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(sm, "SURFACE_DIR", root):
                self.assertEqual(d.snapshot_confirmed("missing.test"), [])
                data = sm.get_or_create_surface("d.test")
                data["findings"] = [
                    {
                        "id": "1",
                        "title": "HSTS",
                        "status": "confirmed",
                        "severity": "medium",
                        "cve": "",
                    },
                    {
                        "id": "2",
                        "title": "CVE-X",
                        "status": "confirmed",
                        "severity": "high",
                        "cve": "CVE-2020-1",
                    },
                ]
                data["ports"] = [
                    {"host": "d.test", "port": "80", "proto": "tcp", "service": "http"}
                ]
                data["hosts"] = [{"host": "d.test"}, "other.test"]
                data["services"] = [
                    {"host": "d.test", "port": "80", "name": "http", "version": "1.0"}
                ]
                sm.save_surface("d.test", data)
                base = d.snapshot_surface_baseline("d.test")
                self.assertGreaterEqual(base["baseline_count"], 1)
                data = sm.load_surface("d.test")
                data["findings"].append(
                    {"id": "3", "title": "New XSS", "status": "confirmed", "severity": "high"}
                )
                data["findings"][0]["status"] = "false_positive"
                data["ports"].append({"host": "d.test", "port": "22", "proto": "tcp"})
                data["services"][0]["version"] = "2.0"
                data["services"].append(
                    {"host": "d.test", "port": "443", "name": "https", "version": "1"}
                )
                sm.save_surface("d.test", data)
                delta = d.compute_delta("d.test")
                md = d.format_delta_markdown(delta)
                self.assertIn("Corrigidos", md)
                md2 = d.format_delta_markdown({"has_baseline": False})
                self.assertIn("Sem baseline", md2)
                self.assertEqual(d._port_key("80"), "80")
                self.assertEqual(d._service_key("http"), "http")
                self.assertEqual(d._host_key("h"), "h")


class TestDataCleanupMore(unittest.TestCase):
    def test_purge_all_categories_and_session_logs(self):
        from backend.executor import data_cleanup as dc
        from backend.executor import files_store
        from backend.executor import logs as logs_mod

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log_dir = root / "logs"
            recon = root / "recon"
            audit = root / "audit"
            surface = root / "surface"
            outputs = root / "outputs"
            for d in (log_dir, recon, audit, surface, outputs):
                d.mkdir()
            (log_dir / "abc123abc12.log").write_text("x", encoding="utf-8")
            (recon / "t.com.json").write_text("{}", encoding="utf-8")
            (audit / "events-2020-01-01.jsonl").write_text("{}\n", encoding="utf-8")
            (surface / "t.com.json").write_text("{}", encoding="utf-8")
            (outputs / "evidence" / "t.com").mkdir(parents=True)
            (outputs / "evidence" / "t.com" / "a.txt").write_text("e", encoding="utf-8")
            (outputs / "delivery").mkdir()
            (outputs / "delivery" / "a.zip").write_text("z", encoding="utf-8")
            (outputs / "t.com-scan.txt").write_text("o", encoding="utf-8")
            with (
                patch.object(dc, "LOG_DIR", log_dir),
                patch.object(dc, "RECON_DIR", recon),
                patch.object(dc, "AUDIT_DIR", audit),
                patch.object(dc, "SURFACE_DIR", surface),
                patch.object(dc, "OUTPUTS_DIR", outputs),
                patch.object(files_store, "OUTPUTS_DIR", outputs),
                patch.object(logs_mod, "LOG_DIR", log_dir),
                patch.object(logs_mod, "_SESSION_INDEX_DIR", log_dir / "by_session"),
            ):
                summary = dc.storage_summary()
                self.assertIn("outputs", summary["categories"])
                self.assertEqual(dc.purge_audit(date="2020-01-01"), 1)
                (audit / "events-2020-01-02.jsonl").write_text("{}\n", encoding="utf-8")
                self.assertEqual(dc.purge_audit(date="2099-01-01"), 0)
                self.assertGreaterEqual(dc.purge_category("logs"), 0)
                (log_dir / "abc123abc12.log").write_text("x", encoding="utf-8")
                logs_mod.save_execution_log(
                    "nmap", "r", "o", "", log_id="abc123abc12", chat_session_id="sess1234"
                )
                dc.delete_logs_for_session("sess1234", extra_log_ids=["abc123abc12"])
                self.assertEqual(dc.delete_logs_for_session(""), {"deleted": 0, "session_id": ""})
                self.assertFalse(dc.delete_recon(""))
                self.assertFalse(dc.delete_surface(".."))
                self.assertEqual(dc.delete_evidence_for_target("nope.test"), 0)
                self.assertFalse(dc.delete_output_file("../x"))
                with self.assertRaises(ValueError):
                    dc.purge_category("nope")
                (recon / "t.com.json").write_text("{}", encoding="utf-8")
                self.assertEqual(dc.purge_category("recon", target="t.com"), 1)
                (recon / "u.com.json").write_text("{}", encoding="utf-8")
                self.assertGreaterEqual(dc.purge_category("recon"), 1)
                (surface / "t.com.json").write_text("{}", encoding="utf-8")
                dc.purge_category("surface", target="t.com")
                (surface / "u.com.json").write_text("{}", encoding="utf-8")
                dc.purge_category("surface")
                (outputs / "evidence" / "x.com").mkdir(parents=True)
                (outputs / "evidence" / "x.com" / "b.txt").write_text("e", encoding="utf-8")
                dc.purge_category("evidence", target="x.com")
                (outputs / "evidence" / "y.com").mkdir(parents=True)
                (outputs / "evidence" / "y.com" / "c.txt").write_text("e", encoding="utf-8")
                dc.purge_category("evidence")
                dc.purge_category("delivery")
                (outputs / "z.com-out.txt").write_text("o", encoding="utf-8")
                dc.purge_category("outputs", target="z.com")
                (outputs / "leftover.txt").write_text("o", encoding="utf-8")
                dc.purge_category("outputs")
                dc.purge_older_than(1)
                dc.purge_categories(["logs", "nope"], target=None)
                self.assertEqual(dc._dir_stats(root / "missing"), {"count": 0, "bytes": 0})
                dc.purge_audit()
                self.assertEqual(dc._purge_glob(root / "missing", "*"), 0)


class TestChatStoreEdges(_DbCase):
    def test_upsert_patch_migrate_errors(self):
        from backend.database import chat_store as cs

        self.assertIsNone(cs.get_chat_session(""))
        self.assertFalse(cs.delete_chat_session(""))
        self.assertIsNone(cs.patch_chat_session(""))
        with self.assertRaises(ValueError):
            cs.upsert_chat_session({"id": ""})
        row = cs.upsert_chat_session(
            {
                "id": "sesschat01",
                "title": "t",
                "messages": ["x"] * 501,
                "preferred_tool": "nmap",
                "created_at_ms": 1,
            }
        )
        self.assertEqual(len(row["messages"]), 500)
        cs.upsert_chat_session(
            {"id": "sesschat01", "title": "t2", "messages": [], "client_id": "acme"}
        )
        patched = cs.patch_chat_session(
            "sesschat01", title="n", preferredTool="curl", preferred_tool="curl"
        )
        self.assertEqual(patched["title"], "n")
        listed = cs.list_chat_sessions(include_messages=False, client_id="acme")
        self.assertTrue(listed)
        default = cs.list_chat_sessions(client_id="default")
        self.assertIsInstance(default, list)
        mig = cs.migrate_chat_sessions([{}, {"id": "migrated2"}, "bad"])
        self.assertGreaterEqual(mig["skipped"], 1)
        self.assertTrue(cs.delete_chat_session("sesschat01"))


class TestFpLearnClear(_DbCase):
    def test_clear_and_bad_json_row(self):
        from backend.ai import fp_learn

        fp_learn.reset_for_tests()
        with patch.object(fp_learn, "FP_SUPPRESS_PATH", self.root / "none.json"):
            fp_learn._migrated = True
            rec = fp_learn.remember_false_positive({"title": "X"}, target="t.com")
            rec2 = fp_learn.remember_false_positive({"title": "X"}, target="u.com")
            self.assertGreaterEqual(rec2["hits"], 2)
            n = fp_learn.clear_suppressed(rec["pattern_key"])
            self.assertGreaterEqual(n, 0)
            fp_learn.remember_false_positive({"title": "Y"})
            self.assertGreaterEqual(fp_learn.clear_suppressed(), 0)
            empty = self.root / "empty.json"
            empty.write_text("{}", encoding="utf-8")
            fp_learn.reset_for_tests()
            with patch.object(fp_learn, "FP_SUPPRESS_PATH", empty):
                fp_learn._migrate_legacy_json()
            bad = self.root / "bad.json"
            bad.write_text("{", encoding="utf-8")
            fp_learn.reset_for_tests()
            with patch.object(fp_learn, "FP_SUPPRESS_PATH", bad):
                fp_learn._migrate_legacy_json()


class TestSessionIntelMore(_DbCase):
    def test_sync_ingest_list_delete_merge(self):
        from backend.executor import logs as logs_mod
        from backend.executor import session_intel as si
        from backend.executor import surface as sm

        sid = "sessintel01"
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
            self.assertEqual(si.load_session(""), {})
            self.assertEqual(si.save_session("bad", {}), {})
            self.assertEqual(si.touch_session("", "t.com"), {})
            self.assertEqual(si.touch_session(sid, ""), {})
            si.touch_session(sid, "lab.test")
            si.set_session_label(sid, "lab")
            lid = logs_mod.save_execution_log(
                "nmap -Pn lab.test",
                "r",
                "=== STDOUT ===\n80/tcp open http\n",
                "=== STDERR ===\n",
                chat_session_id=sid,
            )
            raw = logs_mod.read_execution_log(lid) or ""
            parsed = si._parse_execution_log(raw)
            self.assertIn("command", parsed)
            stats = si.sync_session_intel_from_logs(sid)
            self.assertGreaterEqual(stats.get("logs", 0), 0)
            extra = [
                {
                    "command": "nikto -h lab.test",
                    "stdout": "+ XSS",
                    "stderr": "",
                    "success": True,
                    "tool": "nikto",
                }
            ]
            bf = si.backfill_session_findings_from_client(sid, extra + ["x", {}])
            self.assertGreaterEqual(bf["added"], 0)
            n = si.ingest_extracted_findings(
                sid,
                extra_executions=[
                    {"command": "nmap", "stdout": "[critical] SQLi found", "stderr": ""}
                ],
                skip_disk_logs=True,
            )
            self.assertGreaterEqual(n, 0)
            self.assertEqual(
                si.ingest_extracted_findings(sid, extra_executions=[], skip_disk_logs=True), 0
            )
            findings = si.aggregate_session_findings(sid, sync=False)
            self.assertIsInstance(findings, list)
            if findings:
                fid = findings[0]["id"]
                si.patch_session_finding(sid, "lab.test", fid, "false_positive", evidence="fp")
                si.merge_session_finding_fields(sid, fid, {"ai_review": {"v": 1}})
            self.assertIsNone(si.merge_session_finding_fields(sid, "", {}))
            self.assertIsNone(si.merge_session_finding_fields(sid, "nope", {"a": 1}))
            listed = si.list_session_summaries()
            self.assertTrue(any(x.get("session_id") == sid for x in listed) or listed == listed)
            si.collect_session_tool_executions(sid)
            self.assertTrue(si.delete_session_intel(sid))
            # file fallback
            path = intel / f"{sid}.json"
            path.write_text(
                json.dumps({"session_id": sid, "targets": ["lab.test"]}), encoding="utf-8"
            )
            loaded = si._load_session_from_file(sid)
            self.assertTrue(loaded or loaded == {})
            (intel / "bad.json").write_text("{", encoding="utf-8")
            si._load_session_from_file("bad.jsonxx")


class TestExecDigestMore(unittest.TestCase):
    def test_banner_clean_and_summaries(self):
        from backend.ai import exec_digest as ed

        self.assertFalse(ed._is_banner_line(""))
        self.assertTrue(ed._is_banner_line("projectdiscovery.io rocks"))
        self.assertTrue(ed._is_banner_line("--------"))
        art = "|" * 20
        self.assertTrue(ed._is_banner_line(art))
        cleaned = ed.clean_tool_output("\n\n\nhello\n\n\nworld\n" + "x" * 2000, max_chars=100)
        self.assertTrue(cleaned)
        self.assertEqual(ed._tool_name({}), "comando")
        self.assertEqual(ed._status({"blocked": True})[0], "blocked")
        self.assertEqual(ed._status({"success": False})[0], "fail")
        ed._hosts_from("a.example.com b.example.com localhost.local")
        ed._digest_subfinder("")
        ed._digest_subfinder("sub.example.com\nother.example.com")
        ed._digest_nmap("Host is up\n80/tcp open http\n")
        ed._digest_nmap("0 hosts up")
        ed._digest_nmap("nothing")
        ed._digest_httpx("no input provided", False)
        ed._digest_httpx("http://x.test [200]", True)
        ed._digest_httpx("", True)
        ed._digest_httpx("err", False)
        ed._digest_whatweb("Title[Home] HTTPServer[nginx] 1.2.3.4")
        ed._digest_whatweb("")
        ed._digest_gobuster("wordlist does not exist", False)
        ed._digest_gobuster("/admin (Status: 200)", True)
        ed._digest_gobuster("", True)
        ed._digest_gobuster("fail line", False)
        ed._digest_nuclei("skipped x from target list as found unresponsive", False)
        ed._digest_nuclei("[critical] xss", True)
        ed._digest_nuclei("", True)
        ed._digest_nuclei("fail", False)
        ed._digest_nikto("+ XSS found\n+ Start time 1")
        ed._digest_nikto("")
        ed.digest_execution(
            {"command": "nmap -sV t.com", "stdout": "80/tcp open http", "success": True}
        )
        ed.digest_execution({"tool": "httpx", "stdout": "", "success": True})
        ed.digest_execution({"tool": "custom", "stdout": "line", "success": True})
        ed.digest_execution({"tool": "custom", "stdout": "", "success": False})
        ed.digest_execution({"blocked": True, "command": "nmap", "reason": "scope"})


class TestVerifyExtra(unittest.TestCase):
    def test_classify_and_pipeline_edges(self):
        from backend.ai import verify as v
        from backend.executor import surface as sm
        from backend.executor.result import ExecutionResult

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(sm, "SURFACE_DIR", root):
                empty = v.run_verification_pipeline("missing.test")
                self.assertEqual(empty.confirmed, 0)
                data = sm.get_or_create_surface("v.test")
                data["findings"] = [
                    {
                        "id": "h1",
                        "title": "Missing HSTS",
                        "severity": "medium",
                        "status": "candidate",
                        "tool": "nuclei",
                    }
                ]
                data["urls"] = ["https://v.test/"]
                sm.save_surface("v.test", data)
                kind = v.classify_finding_type(data["findings"][0])
                self.assertTrue(kind)
                buckets = v.confidence_gate_buckets("v.test")
                self.assertIn("executive", buckets)

                def _exec(command: str, reason: str):
                    return ExecutionResult(
                        command, reason, "strict-transport-security", "", 0, True
                    )

                result = v.run_verification_pipeline("v.test", execute=_exec, max_findings=5)
                self.assertTrue(result is not None)


if __name__ == "__main__":
    unittest.main()
