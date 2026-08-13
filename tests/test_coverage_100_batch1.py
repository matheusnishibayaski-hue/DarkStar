"""Lote 1: webhook, MCP stdio, __main__, reports/schedule stores, findings, rotas finas."""

from __future__ import annotations

import io
import json
import runpy
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

from backend.database import db as db_mod
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


class TestWebhook(unittest.TestCase):
    def test_send_webhook_no_url(self):
        from backend.alerts import webhook as wh

        with patch.object(wh, "ALERT_WEBHOOK_URL", ""):
            self.assertFalse(wh.send_webhook("hi"))

    def test_send_webhook_ok_and_payload(self):
        from backend.alerts import webhook as wh

        resp = MagicMock()
        resp.status = 200
        resp.__enter__ = MagicMock(return_value=resp)
        resp.__exit__ = MagicMock(return_value=False)
        with (
            patch.object(wh, "ALERT_WEBHOOK_URL", "https://hooks.example/x"),
            patch.object(wh, "http_urlopen", return_value=resp) as opener,
            patch.object(wh, "record_event") as rec,
        ):
            self.assertTrue(wh.send_webhook("alerta", payload={"k": 1}))
            opener.assert_called_once()
            rec.assert_called()

    def test_send_webhook_status_default_and_network_fail(self):
        from backend.alerts import webhook as wh

        resp = MagicMock(spec=["__enter__", "__exit__"])
        resp.__enter__ = MagicMock(return_value=resp)
        resp.__exit__ = MagicMock(return_value=False)
        with (
            patch.object(wh, "ALERT_WEBHOOK_URL", "https://hooks.example/x"),
            patch.object(wh, "http_urlopen", return_value=resp),
            patch.object(wh, "record_event"),
        ):
            self.assertTrue(wh.send_webhook("ok"))

        with (
            patch.object(wh, "ALERT_WEBHOOK_URL", "https://hooks.example/x"),
            patch.object(wh, "http_urlopen", side_effect=urllib.error.URLError("down")),
            patch.object(wh, "record_event") as rec,
        ):
            self.assertFalse(wh.send_webhook("fail"))
            rec.assert_called()

    def test_maybe_alert_delta_critical_port_jump(self):
        from backend.alerts import webhook as wh

        delta = {
            "new": [
                {"title": "RCE", "severity": "critical", "key": "rce"},
                {"title": "info", "severity": "info"},
            ],
            "fixed": [{}],
            "surface": {
                "ports_opened": [
                    {"port": 22},
                    80,
                    {"port": "3389"},
                ]
            },
        }
        risk = {"score": 40}
        with (
            patch.object(wh, "ALERT_ON_CRITICAL", True),
            patch.object(wh, "ALERT_RISK_JUMP", 15),
            patch.object(wh, "send_webhook", return_value=True) as send,
            patch(
                "backend.integrations.notifications.notification_manager.notify",
                side_effect=RuntimeError("no notify"),
            ),
        ):
            msgs = wh.maybe_alert_delta("lab.test", delta=delta, risk=risk, previous_score=10)
        self.assertGreaterEqual(len(msgs), 2)
        self.assertTrue(send.called)
        self.assertTrue(any("critical" in m.lower() or "achado" in m.lower() for m in msgs))
        self.assertTrue(any("porta" in m.lower() for m in msgs))
        self.assertTrue(any("risco" in m.lower() for m in msgs))

    def test_maybe_alert_delta_empty(self):
        from backend.alerts import webhook as wh

        with patch.object(wh, "ALERT_ON_CRITICAL", False):
            msgs = wh.maybe_alert_delta("t", delta={"new": [], "surface": {}}, risk={})
        self.assertEqual(msgs, [])


class TestMcpServerStdio(unittest.TestCase):
    def test_read_write_and_serve(self):
        from backend import mcp_server as ms

        ping = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode()
        framed = f"Content-Length: {len(ping)}\r\n\r\n".encode("ascii") + ping
        extra = b"Content-Length: 0\r\n\r\n"
        bad_len = b"Content-Length: abc\r\n\r\n{}"
        not_obj = b"Content-Length: 2\r\n\r\n[]"
        bad_json = b"Content-Length: 3\r\n\r\n{x"
        eof_after_headers = b"Content-Length: 10\r\n\r\n"
        stdin = io.BytesIO(framed + extra + bad_len + not_obj + bad_json + eof_after_headers)
        stdout = io.BytesIO()
        with patch.object(ms.mcp_service, "handle_rpc", return_value={"jsonrpc": "2.0", "id": 1}):
            ms.serve(stdin=stdin, stdout=stdout)
        self.assertIn(b"Content-Length:", stdout.getvalue())

        empty = io.BytesIO(b"")
        self.assertIsNone(ms._read_message(empty))
        no_colon = io.BytesIO(b"not-a-header\r\n\r\n")
        self.assertIsNone(ms._read_message(no_colon))

    def test_mcp_server_main(self):
        buf_in = io.BytesIO(b"")
        buf_out = io.BytesIO()
        stdin = MagicMock()
        stdin.buffer = buf_in
        stdout = MagicMock()
        stdout.buffer = buf_out
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            runpy.run_path(
                str(Path(__file__).resolve().parents[1] / "backend" / "mcp_server.py"),
                run_name="__main__",
            )


class TestBackendMain(unittest.TestCase):
    def test_import_binds_cli(self):
        import backend.__main__ as main_mod

        self.assertTrue(callable(main_mod.cli))

    def test_run_as_main(self):
        with patch("backend.cli.cli") as cli:
            runpy.run_path(
                str(Path(__file__).resolve().parents[1] / "backend" / "__main__.py"),
                run_name="__main__",
            )
            cli.assert_called()


class TestReportsStore(_DbCase):
    def test_crud_and_edges(self):
        from backend.database import reports_store as rs

        with self.assertRaises(ValueError):
            rs.save_report(content=b"")
        with self.assertRaises(ValueError):
            rs.save_report(content=b"x" * (rs.MAX_PDF_BYTES + 1))

        meta = rs.save_report(
            content=b"%PDF-1.4 test",
            session_id="sess-rep-1",
            title="Rel",
            file_name="a.pdf",
            report_id="repid1",
        )
        self.assertEqual(meta["id"], "repid1")
        listed = rs.list_reports(session_id="sess-rep-1")
        self.assertEqual(len(listed), 1)
        self.assertTrue(rs.list_reports())
        got = rs.get_report("repid1")
        self.assertEqual(got["content"], b"%PDF-1.4 test")
        self.assertIsNone(rs.get_report(""))
        self.assertIsNone(rs.get_report("missing"))
        self.assertFalse(rs.delete_report(""))
        self.assertEqual(rs.delete_reports_for_session(""), 0)
        self.assertTrue(rs.delete_report("repid1"))
        meta2 = rs.save_report(content=b"pdf2", session_id="s2")
        self.assertGreaterEqual(rs.delete_reports_for_session("s2"), 1)
        self.assertIsNone(rs.get_report(meta2["id"]))


class TestScheduleStoreGaps(_DbCase):
    def test_save_get_due_delete_and_legacy(self):
        from backend.schedule import store as st

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(st, "SCHEDULE_DIR", root):
                with self.assertRaises(ValueError):
                    st.save_job({})
                job = st.create_job(target="due.test", interval="daily", enabled=True)
                self.assertEqual(st.get_job(""), None)
                loaded = st.get_job(job["id"])
                self.assertEqual(loaded["target"], "due.test")
                listed = st.list_jobs(client_id="default", target="due.test")
                self.assertEqual(len(listed), 1)
                self.assertFalse(st.delete_job(""))
                disabled = st.create_job(target="off.test", enabled=False)
                due = st.due_jobs(now=st._now())
                ids = {j["id"] for j in due}
                self.assertNotIn(disabled["id"], ids)

                job["last_status"] = "running"
                st.save_job(job)
                due2 = st.due_jobs()
                self.assertFalse(any(j["id"] == job["id"] for j in due2))

                st.create_job(target="x.test", job_type="nope", interval="nope")
                st.create_job(target="y.test", interval_days="bad")

                legacy = root / "leg123.json"
                legacy.write_text(
                    json.dumps({"id": "leg123", "target": "leg.test"}), encoding="utf-8"
                )
                (root / "bad.json").write_text("{", encoding="utf-8")
                migrated = st.get_job("leg123")
                self.assertEqual(migrated["id"], "leg123")

                self.assertTrue(st.delete_job(job["id"]))
                self.assertTrue(st.delete_job(disabled["id"]))

                with patch.object(st, "execute_job", create=True):
                    pass
                with patch("backend.schedule.runner.execute_job", return_value={"ok": True}):
                    j2 = st.create_job(target="runnow.test")
                    out = st.run_job_now(j2["id"])
                    self.assertEqual(out["ok"], True)
                with self.assertRaises(FileNotFoundError):
                    st.run_job_now("missing-job")

                self.assertIsNone(st._parse_iso(None))
                self.assertIsNone(st._parse_iso("not-iso"))
                self.assertIsNone(st._read_file("no-such"))
                (root / "notdict.json").write_text("[]", encoding="utf-8")
                self.assertIsNone(st._read_file("notdict"))


class TestFindings(unittest.TestCase):
    def test_auto_verify_and_buckets(self):
        from backend.ai import findings as fd
        from backend.executor import surface as sm

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(sm, "SURFACE_DIR", root):
                self.assertEqual(
                    fd.auto_verify_from_execution(
                        "none.test", command="curl", tool="curl", stdout="", stderr="", success=True
                    ),
                    [],
                )
                self.assertEqual(fd.confirmed_findings("none.test"), [])
                buckets = fd.findings_for_report("none.test")
                self.assertEqual(buckets["confirmed"], [])
                self.assertIsNone(fd.set_phase("none.test", "exploit"))

                data = sm.get_or_create_surface("lab.test")
                data["findings"] = [
                    {
                        "id": "f1",
                        "title": "Missing HSTS header",
                        "status": "candidate",
                        "tool": "nuclei",
                    },
                    {
                        "id": "f2",
                        "title": "CVE-2024-9999 openssl",
                        "status": "candidate",
                        "tool": "nmap",
                    },
                    {
                        "id": "f3",
                        "title": "Open SSH",
                        "status": "confirmed",
                        "tool": "nmap",
                    },
                ]
                sm.save_surface("lab.test", data)
                updated = fd.auto_verify_from_execution(
                    "lab.test",
                    command="nuclei -t hsts",
                    tool="nuclei",
                    stdout="Missing HSTS header found",
                    stderr="",
                    success=True,
                )
                self.assertTrue(updated)
                updated2 = fd.auto_verify_from_execution(
                    "lab.test",
                    command="nmap",
                    tool="nmap",
                    stdout="cve-2024-9999 present",
                    stderr="",
                    success=True,
                )
                self.assertTrue(updated2)
                fd.auto_verify_from_execution(
                    "lab.test",
                    command="curl http://lab.test",
                    tool="curl",
                    stdout="ok",
                    stderr="",
                    success=True,
                )
                self.assertTrue(fd.confirmed_findings("lab.test"))
                buckets = fd.findings_for_report("lab.test")
                self.assertIn("confirmed", buckets)
                phased = fd.set_phase("lab.test", "exploit")
                self.assertEqual(phased.get("phase"), "exploit")
                with patch(
                    "backend.ai.verify.confidence_gate_buckets",
                    return_value={"executive": [{"id": "e1"}]},
                ):
                    self.assertEqual(len(fd.executive_findings("lab.test")), 1)


class TestReportsAndChatSessionRoutes(_DbCase):
    def test_reports_and_sessions_http(self):
        from backend.main import app

        with patch_chat_api_token(""):
            client = TestClient(app)
            empty = client.post(
                "/api/reports",
                files={"file": ("x.pdf", b"", "application/pdf")},
            )
            self.assertEqual(empty.status_code, 400)
            up = client.post(
                "/api/reports",
                data={"session_id": "sess-http-1", "title": "T"},
                files={"file": ("relatorio.pdf", b"%PDF-ok", "application/pdf")},
            )
            self.assertEqual(up.status_code, 200)
            rid = up.json()["report"]["id"]
            listed = client.get("/api/reports", params={"session_id": "sess-http-1"})
            self.assertEqual(listed.status_code, 200)
            meta = client.get(f"/api/reports/{rid}/meta")
            self.assertEqual(meta.status_code, 200)
            pdf = client.get(f"/api/reports/{rid}")
            self.assertEqual(pdf.status_code, 200)
            self.assertEqual(pdf.content, b"%PDF-ok")
            self.assertEqual(client.get("/api/reports/missing/meta").status_code, 404)
            self.assertEqual(client.get("/api/reports/missing").status_code, 404)

            sid = "sesshttp01"
            body = {
                "id": sid,
                "title": "chat",
                "preferredTool": "nmap",
                "messages": [{"role": "user", "content": "oi"}],
            }
            created = client.post("/api/chat-sessions", json=body)
            self.assertEqual(created.status_code, 200)
            self.assertEqual(client.get("/api/chat-sessions").status_code, 200)
            self.assertEqual(client.get(f"/api/chat-sessions/{sid}").status_code, 200)
            self.assertEqual(client.get("/api/chat-sessions/missing-xx").status_code, 404)
            put = client.put(f"/api/chat-sessions/{sid}", json={**body, "title": "novo"})
            self.assertEqual(put.status_code, 200)
            mismatch = client.put(f"/api/chat-sessions/{sid}", json={**body, "id": "otheridxx"})
            self.assertEqual(mismatch.status_code, 400)
            patched = client.patch(f"/api/chat-sessions/{sid}", json={"title": "p"})
            self.assertEqual(patched.status_code, 200)
            self.assertEqual(
                client.patch("/api/chat-sessions/no-such-1", json={"title": "x"}).status_code, 404
            )
            mig = client.post(
                "/api/chat-sessions/migrate",
                json={"sessions": [{"id": "migrated01", "title": "m"}]},
            )
            self.assertEqual(mig.status_code, 200)
            deleted = client.delete(f"/api/chat-sessions/{sid}")
            self.assertEqual(deleted.status_code, 200)
            self.assertEqual(client.delete(f"/api/reports/{rid}").status_code, 200)
            self.assertEqual(client.delete("/api/reports/gone").status_code, 404)
            self.assertEqual(client.delete("/api/reports/session/sess-http-1").status_code, 200)


class TestClientsRoutes(_DbCase):
    def test_clients_crud_activate_backup(self):
        import uuid

        from backend.clients import store as clients_store
        from backend.main import app

        cid = f"acme-{uuid.uuid4().hex[:8]}"
        surf = self.root / "surface"
        surf.mkdir()
        with (
            patch.object(clients_store, "CLIENTS_DIR", self.root),
            patch("backend.clients.store.CLIENTS_DIR", self.root),
            patch("backend.clients.backup.CLIENTS_DIR", self.root),
            patch("backend.clients.backup.SURFACE_DIR", surf),
            patch("backend.clients.store.SURFACE_DIR", surf),
            patch("backend.executor.surface.SURFACE_DIR", surf),
            patch_chat_api_token(""),
        ):
            client = TestClient(app)
            listed = client.get("/api/clients")
            self.assertEqual(listed.status_code, 200)
            created = client.post(
                "/api/clients",
                json={"client_id": cid, "display_name": "Acme"},
            )
            self.assertEqual(created.status_code, 200)
            dup = client.post(
                "/api/clients",
                json={"client_id": cid, "display_name": "Acme"},
            )
            self.assertEqual(dup.status_code, 409)
            bad = client.post("/api/clients", json={"client_id": ""})
            self.assertIn(bad.status_code, {400, 422})
            got = client.get(f"/api/clients/{cid}")
            self.assertEqual(got.status_code, 200)
            self.assertEqual(client.get("/api/clients/missing-co").status_code, 404)
            patched = client.patch(
                f"/api/clients/{cid}",
                json={"display_name": "Acme 2"},
            )
            self.assertEqual(patched.status_code, 200)
            self.assertEqual(
                client.patch("/api/clients/nope", json={"display_name": "x"}).status_code, 404
            )
            act = client.post(f"/api/clients/{cid}/activate")
            self.assertEqual(act.status_code, 200)
            self.assertEqual(client.post("/api/clients/nope/activate").status_code, 404)
            active = client.get("/api/clients/_active")
            self.assertEqual(active.status_code, 200)
            hdr = client.get("/api/clients/_active", headers={"X-Client-Id": cid})
            self.assertEqual(hdr.json().get("source"), "header")
            bak = client.get(f"/api/clients/{cid}/backup")
            self.assertEqual(bak.status_code, 200)
            bak2 = client.get(f"/api/clients/{cid}/backup", params={"save": True})
            self.assertEqual(bak2.status_code, 200)
            self.assertEqual(client.get("/api/clients/nope/backup").status_code, 404)
            restored = client.post(
                f"/api/clients/{cid}/restore",
                params={"overwrite": True},
                files={"file": ("b.tar.gz", bak.content, "application/gzip")},
            )
            self.assertEqual(restored.status_code, 200)
            deleted = client.delete(f"/api/clients/{cid}")
            self.assertEqual(deleted.status_code, 200)
            self.assertEqual(client.delete("/api/clients/default").status_code, 400)
            gone = client.delete("/api/clients/ghost")
            self.assertEqual(gone.status_code, 200)
            self.assertTrue(gone.json().get("already_gone") or gone.json().get("deleted"))


if __name__ == "__main__":
    unittest.main()
