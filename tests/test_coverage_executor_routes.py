"""Cobertura kali/recon/files/rotas/security restantes."""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from backend.executor.result import ExecutionResult
from backend.security.missions import get_mission_registry
from tests.auth_patch import patch_chat_api_token


class TestKaliCoverage(unittest.TestCase):
    def test_parse_and_flags(self):
        from backend.executor import kali as k

        self.assertEqual(k.parse_command_string(""), [])
        self.assertEqual(k.parse_command_string('echo "a b"'), ["echo", "a b"])
        with patch.object(k.shlex, "split", side_effect=ValueError):
            self.assertEqual(k.parse_command_string("a b"), ["a", "b"])
        self.assertEqual(k.apply_non_interactive_flags([]), [])
        flagged = k.apply_non_interactive_flags(["sqlmap", "-u", "http://x"])
        self.assertIn("--batch", flagged)
        self.assertFalse(k._is_wifi_tool([]))
        self.assertTrue(k._is_wifi_tool(["airodump-ng"]))

    def test_validate_length(self):
        from backend.executor import kali as k

        ok, err = k.validate_command([])
        self.assertFalse(ok)
        long_args = ["nmap", "x" * 600]
        ok, err = k.validate_command(long_args)
        self.assertFalse(ok)
        self.assertIn("500", err)

    def test_host_wifi_stream_path(self):
        from backend.executor import kali as k

        fake = ExecutionResult(
            command="wlan-scan",
            reason="r",
            stdout="nets",
            stderr="",
            exit_code=0,
            success=True,
            log_file_id="w",
            tool="wlan-scan",
        )
        with patch.object(k, "execute_host_wifi", return_value=fake), patch.object(
            k, "save_execution_log"
        ), patch.object(k, "record_tool_execution"):
            events = list(
                k.execute_kali_command_stream(
                    ["wlan-scan"], "reason", execution_id="wifi1"
                )
            )
        done = [e for e in events if e.get("type") == "done"]
        self.assertEqual(len(done), 1)
        self.assertTrue(done[0]["result"].success)

    def test_docker_success_timeout_notfound_exception(self):
        from backend.executor import kali as k

        with patch.object(k, "_run_docker_streaming", return_value=(0, "ok", "")), patch.object(
            k, "save_execution_log"
        ), patch.object(k, "record_tool_execution"):
            events = list(
                k.execute_kali_command_stream(["nmap", "-V"], "v", execution_id="d1")
            )
        self.assertTrue(any(e.get("type") == "done" and e["result"].success for e in events))

        with patch.object(
            k, "_run_docker_streaming", side_effect=subprocess_timeout()
        ), patch.object(k, "save_execution_log"), patch.object(k, "record_tool_execution"):
            events = list(
                k.execute_kali_command_stream(["nmap", "-V"], "v", execution_id="d2")
            )
        self.assertTrue(any("Timeout" in (e.get("result").stderr if e.get("type") == "done" else "") for e in events))

        with patch.object(
            k, "_run_docker_streaming", side_effect=FileNotFoundError
        ), patch.object(k, "record_tool_execution"):
            events = list(
                k.execute_kali_command_stream(["nmap", "-V"], "v", execution_id="d3")
            )
        self.assertTrue(
            any(
                e.get("type") == "done" and "Docker" in e["result"].stderr
                for e in events
            )
        )

        with patch.object(
            k, "_run_docker_streaming", side_effect=RuntimeError("boom")
        ), patch.object(k, "record_tool_execution"):
            events = list(
                k.execute_kali_command_stream(["nmap", "-V"], "v", execution_id="d4")
            )
        self.assertTrue(
            any(e.get("type") == "done" and e["result"].stderr == "boom" for e in events)
        )

    def test_interrupted_and_execute_in_kali(self):
        from backend.executor import kali as k

        with patch.object(
            k, "_run_docker_streaming", side_effect=InterruptedError("cancelado")
        ), patch.object(k, "save_execution_log"), patch.object(k, "record_tool_execution"):
            events = list(
                k.execute_kali_command_stream(["nmap", "-V"], "v", execution_id="d5")
            )
        self.assertTrue(
            any(e.get("type") == "done" and not e["result"].success for e in events)
        )

        with patch.object(
            k,
            "execute_kali_command_stream",
            return_value=iter(
                [
                    {
                        "type": "done",
                        "result": ExecutionResult("nmap", "r", "o", "", 0, True),
                    }
                ]
            ),
        ):
            r = k.execute_in_kali("nmap -V", "reason")
        self.assertTrue(r.success)

        with patch.object(k, "execute_kali_command_stream", return_value=iter([])):
            r2 = k.execute_in_kali("nmap -V", "reason")
        self.assertFalse(r2.success)

    def test_execute_kali_command_wrapper(self):
        from backend.executor import kali as k

        with patch.object(
            k,
            "execute_kali_command_stream",
            return_value=iter(
                [
                    {
                        "type": "done",
                        "result": ExecutionResult("nmap", "r", "", "", 0, True),
                    }
                ]
            ),
        ):
            r = k.execute_kali_command(["nmap", "-V"], "r")
        self.assertTrue(r.success)

    def test_emit_and_stream_text(self):
        from backend.executor import kali as k

        lines = list(k._stream_text_lines(None, "stdout", "a\nb"))
        self.assertEqual(len(lines), 2)
        with patch.object(k, "get_stream_hub") as hub:
            hub.return_value.push_line = MagicMock()
            k._emit_line("e1", "stdout", "x")
            hub.return_value.push_line.assert_called()


def subprocess_timeout():
    import subprocess

    return subprocess.TimeoutExpired(cmd="nmap", timeout=1)


class TestReconDbCoverage(unittest.TestCase):
    def test_merge_list_get_ttl(self):
        from backend.executor import recon_db as rd

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(rd, "RECON_DIR", Path(tmp)), patch.object(rd, "RECON_TTL_DAYS", 30):
                rd.merge_recon_update(
                    "lab.test",
                    {
                        "open_ports": ["80/tcp open http"],
                        "cves": ["CVE-2024-1"],
                        "vulnerabilities": ["[critical] x"],
                        "notes": ["n"],
                    },
                )
                data = rd.get_recon_data("lab.test")
                self.assertEqual(data["target"], "lab.test")
                summaries = rd.list_recon_summaries()
                self.assertTrue(summaries)
                ctx = rd.build_recon_context(["lab.test"])
                self.assertIn("lab.test", ctx)
                self.assertEqual(rd.build_recon_context([]), "")
                out = "80/tcp open http\nCVE-2024-1111\n[critical] issue"
                extracted = rd.extract_recon_from_output(out, "", tool="nmap")
                self.assertTrue(extracted.get("open_ports") or extracted.get("cves"))
                self.assertFalse(rd.is_recon_target("example.com"))
                self.assertFalse(rd.is_recon_target("foo.local"))
                path = rd._path_for("old.target")
                path.write_text(
                    '{"target":"old.target","updated_at":"2000-01-01T00:00:00+00:00",'
                    '"open_ports":[],"cves":[],"vulnerabilities":[],"notes":[]}',
                    encoding="utf-8",
                )
                self.assertEqual(rd.get_recon_data("old.target"), {})
                # invalid json
                bad = rd._path_for("bad.json.target")
                # path uses normalize — write invalid
                (Path(tmp) / "badjson.json").write_text("{", encoding="utf-8")
                self.assertEqual(rd.get_recon_data("badjson"), {})


class TestFilesStoreCoverage(unittest.TestCase):
    def test_kinds_list_media(self):
        from backend.executor import files_store as fs

        self.assertEqual(fs._file_kind(".pcap"), "pcap")
        self.assertEqual(fs._file_kind(".html"), "html")
        self.assertEqual(fs._file_kind(".json"), "json")
        self.assertEqual(fs._file_kind(".md"), "markdown")
        self.assertEqual(fs._file_kind(".zip"), "archive")
        self.assertEqual(fs._file_kind(".png"), "image")
        self.assertEqual(fs._file_kind(".nmap"), "scan")
        self.assertEqual(fs._file_kind(".log"), "text")
        self.assertEqual(fs._file_kind(".xyz"), "file")
        self.assertTrue(fs.is_allowed_extension(Path("report")))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.json").write_text("{}", encoding="utf-8")
            (root / "skip.binx").write_text("x", encoding="utf-8")
            (root / "sub").mkdir()
            (root / "sub" / "b.md").write_text("#", encoding="utf-8")
            with patch.object(fs, "OUTPUTS_DIR", root), patch.object(fs, "MAX_LIST_FILES", 1):
                files = fs.list_output_files()
                self.assertEqual(len(files), 1)
            self.assertEqual(fs.guess_media_type(Path("a.json")), "application/json")
            self.assertEqual(fs.resolve_output_file(""), None)
            self.assertEqual(fs.resolve_output_file("x" * 300), None)


class TestStreamHubCoverage(unittest.TestCase):
    def test_subscribe_missing_and_keepalive(self):
        from backend.executor.stream_hub import get_stream_hub

        hub = get_stream_hub()
        chunks = list(hub.subscribe_sse("nonexistent999"))
        self.assertTrue(any("error" in c for c in chunks))

        eid = "hubcov1"
        hub.create(eid, "cmd")
        hub.finish(eid, exit_code=0, success=True)
        # finish again when missing stream after cleanup forced
        hub.finish("missinghub", exit_code=1, success=False)

        # cleanup with zero delay
        hub.cleanup(eid, delay=0)
        time.sleep(0.05)


class TestScopeAndSessions(unittest.TestCase):
    def test_scope_subdomain_and_ip(self):
        from backend.security import scope as sc

        with patch.object(sc, "ALLOWED_TARGETS", frozenset({"example.com", "10.0.0.5"})):
            self.assertTrue(sc.is_target_allowed("sub.example.com"))
            self.assertTrue(sc.is_target_allowed("10.0.0.5"))
            self.assertFalse(sc.is_target_allowed("evil.com"))
            self.assertTrue(sc._looks_like_ip("1.2.3.4"))
            self.assertFalse(sc._looks_like_ip("1.2.3"))
            self.assertFalse(sc._looks_like_ip("a.b.c.d"))
            ok, _ = sc.validate_autonomous_target("")
            self.assertFalse(ok)
            ok, _ = sc.validate_command_scope(["wlan-scan"])
            self.assertTrue(ok)
            ok, msg = sc.validate_command_scope(["nmap", "evil.com"])
            self.assertFalse(ok)

    def test_sessions_edge(self):
        from backend.security import sessions as sess

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "s.json"
            with patch.object(sess, "SESSIONS_FILE", path):
                store = sess.SessionStore(ttl_seconds=60)
                sid = store.create()
                self.assertTrue(store.validate(sid))
                store.revoke(None)
                store.revoke(sid)
                self.assertFalse(store.validate(sid))
                self.assertFalse(store.validate(None))
                self.assertFalse(store.validate("nope"))
                sid2 = store.create()
                store._sessions[sid2] = time.time() - 10
                store._save()
                self.assertFalse(store.validate(sid2))
                # corrupt file load
                path.write_text("not-json", encoding="utf-8")
                store2 = sess.SessionStore(ttl_seconds=60)
                self.assertEqual(store2._sessions, {})


class TestRoutesCoverage(unittest.TestCase):
    def test_chat_report_auth_logout(self):
        from backend.main import app

        client = TestClient(app)
        with patch("backend.routes.chat.chat") as chat_mock:
            chat_mock.return_value = MagicMock(
                message="hi", tool_executions=[]
            )
            res = client.post("/api/chat", json={"message": "oi", "history": []})
            self.assertEqual(res.status_code, 200)

        with patch("backend.routes.chat.chat", side_effect=RuntimeError("x")):
            res = client.post("/api/chat", json={"message": "oi", "history": []})
            self.assertEqual(res.status_code, 500)

        with patch("backend.routes.chat.generate_report_pdf", return_value=b"%PDF-1.4 test"):
            res = client.post(
                "/api/generate-report",
                json={"history": [], "tool_executions": [], "title": "T"},
            )
            self.assertEqual(res.status_code, 200)
            self.assertIn("pdf", res.headers.get("content-type", ""))

        with patch("backend.routes.chat.generate_report_pdf", side_effect=RuntimeError("r")):
            res = client.post(
                "/api/generate-report",
                json={"history": [], "tool_executions": []},
            )
            self.assertEqual(res.status_code, 500)

        with patch_chat_api_token("tok"):
            c2 = TestClient(app)
            login = c2.post("/api/auth/login", json={"token": "tok"})
            self.assertEqual(login.status_code, 200)
            logout = c2.post("/api/auth/logout")
            self.assertEqual(logout.status_code, 200)
            bad = c2.post(
                "/api/missions/bad!!id/cancel",
                headers={"X-Chat-Token": "tok"},
            )
            self.assertEqual(bad.status_code, 400)

        # auth disabled paths
        with patch("backend.routes.auth.CHAT_API_TOKEN", ""):
            res = client.get("/api/auth/session")
            self.assertTrue(res.json()["authenticated"])
            res = client.post("/api/auth/login", json={"token": "x"})
            self.assertEqual(res.status_code, 200)

        bad2 = client.post("/api/missions/bad!!id/cancel")
        self.assertEqual(bad2.status_code, 400)

    def test_autonomous_and_system_extras(self):
        from backend.main import app

        client = TestClient(app)
        with patch("backend.routes.autonomous.run_autonomous") as run:
            run.return_value = MagicMock(
                message="done",
                tool_executions=[],
                report="",
                objective_met=True,
                rounds=1,
                tools_executed=0,
                stopped_reason="objective_met",
            )
            res = client.post(
                "/api/autonomous",
                json={"target": "scanme.nmap.org", "objective": "scan"},
            )
            self.assertEqual(res.status_code, 200)

        with patch("backend.routes.autonomous.run_autonomous", side_effect=RuntimeError("x")):
            res = client.post(
                "/api/autonomous",
                json={"target": "scanme.nmap.org", "objective": "scan"},
            )
            self.assertEqual(res.status_code, 500)

        with patch(
            "backend.routes.autonomous.validate_autonomous_target",
            return_value=(False, "bloqueado"),
        ):
            res = client.post(
                "/api/autonomous",
                json={"target": "evil.example", "objective": "scan ports"},
            )
            self.assertEqual(res.status_code, 403)

        with patch(
            "backend.routes.autonomous.run_autonomous_stream",
            side_effect=RuntimeError("stream-fail"),
        ):
            res = client.post(
                "/api/autonomous/stream",
                json={"target": "scanme.nmap.org", "objective": "scan"},
            )
            self.assertEqual(res.status_code, 200)
            self.assertIn("error", res.text)

        with patch(
            "backend.routes.chat.chat_stream",
            side_effect=RuntimeError("chat-fail"),
        ):
            res = client.post("/api/chat/stream", json={"message": "x", "history": []})
            self.assertEqual(res.status_code, 200)
            self.assertIn("error", res.text)

        # favicon + index
        res = client.get("/favicon.ico")
        self.assertEqual(res.status_code, 200)
        res = client.get("/")
        self.assertEqual(res.status_code, 200)

        # metrics already covered; tools
        res = client.get("/api/tools")
        self.assertEqual(res.status_code, 200)

        # invalid log id
        res = client.get("/api/logs/!!!")
        self.assertIn(res.status_code, (400, 404))

        # log stream invalid
        res = client.get("/api/logs/stream/!!!")
        self.assertEqual(res.status_code, 400)


class TestAuditAndMissionsExtra(unittest.TestCase):
    def test_list_events_date_and_cancel_cleanup(self):
        from backend.security import audit as aud

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(aud, "AUDIT_DIR", Path(tmp)):
                aud.record_event("x", {"a": 1})
                events = aud.list_events(date="not-a-date")
                self.assertEqual(events, [])
                events = aud.list_events(date="2099-01-01")
                self.assertEqual(events, [])
                events = aud.list_events(limit=1)
                self.assertLessEqual(len(events), 1)
                # redact nested
                aud.record_event("y", {"nested": {"password": "secret"}})

        reg = get_mission_registry()
        mid = "cov-m1"
        ctrl = reg.register(mid)
        proc = MagicMock()
        reg.register_process(mid, "e1", proc)
        reg.unregister_process(mid, "e1")
        reg.register_process(None, "e1", proc)
        reg.unregister_process(None, "e1")
        reg.cancel(mid)
        proc.kill.assert_not_called()  # already unregistered
        # kill path
        ctrl2 = reg.register("cov-m2")
        proc2 = MagicMock()
        reg.register_process("cov-m2", "e2", proc2)
        reg.cancel("cov-m2")
        proc2.kill.assert_called()
        reg.cleanup("cov-m2")


class TestOpenrouterAndConfig(unittest.TestCase):
    def test_generic_error_and_normalize_scope(self):
        from backend.ai.openrouter_common import openrouter_error_message
        from backend.config import _normalize_scope_target

        self.assertIn("Erro ao chamar", openrouter_error_message("weird failure"))
        self.assertEqual(_normalize_scope_target("https://Ex.COM/path"), "ex.com")
        self.assertEqual(_normalize_scope_target("!!!"), "___")
        self.assertEqual(_normalize_scope_target("   "), "unknown")


class TestDepsAndMiddleware(unittest.TestCase):
    def test_client_ip_fallbacks_and_tool_response(self):
        from backend.deps import client_ip, is_authenticated, tool_execution_response

        req = MagicMock()
        req.headers = {}
        req.client = None
        with patch("backend.deps.TRUST_PROXY", False):
            self.assertEqual(client_ip(req), "unknown")
        with patch("backend.deps.CHAT_API_TOKEN", ""):
            self.assertTrue(is_authenticated(req))
        e = MagicMock(
            command="c",
            reason="r",
            stdout="",
            stderr="",
            exit_code=0,
            success=True,
            blocked=False,
        )
        e.log_file_id = ""
        e.tool = ""
        resp = tool_execution_response(e)
        self.assertEqual(resp.command, "c")


class TestPlaybooksLoader(unittest.TestCase):
    def test_invalid_yaml_and_run(self):
        from backend.playbooks import loader as ld

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "noid.yaml").write_text("name: x\nsteps: []\n", encoding="utf-8")
            with patch.object(ld, "PLAYBOOKS_DIR", p):
                self.assertEqual(ld.list_playbooks(), [])
                self.assertIsNone(ld.load_playbook("missing"))
            good = p / "ok.yaml"
            good.write_text(
                "id: ok\nname: OK\ndescription: d\nsteps:\n"
                "  - tool: nmap\n    args: ['{target}']\n",
                encoding="utf-8",
            )
            with patch.object(ld, "PLAYBOOKS_DIR", p), patch.object(
                ld,
                "execute_kali_command",
                return_value=ExecutionResult("nmap t", "r", "v", "", 0, True),
            ), patch(
                "backend.playbooks.loader.validate_autonomous_target",
                return_value=(True, ""),
            ), patch(
                "backend.playbooks.loader.validate_command_scope",
                return_value=(True, ""),
            ):
                result = ld.run_playbook("ok", "scanme.nmap.org")
                self.assertEqual(result["steps_run"], 1)
            with patch.object(ld, "PLAYBOOKS_DIR", p), patch(
                "backend.playbooks.loader.validate_autonomous_target",
                return_value=(True, ""),
            ), patch(
                "backend.playbooks.loader.validate_command_scope",
                return_value=(False, "scope"),
            ):
                result = ld.run_playbook("ok", "scanme.nmap.org")
                self.assertTrue(result["results"][0]["blocked"])
            with self.assertRaises(ValueError):
                with patch.object(ld, "PLAYBOOKS_DIR", p):
                    ld.run_playbook("nope", "t")
            with self.assertRaises(PermissionError):
                with patch.object(ld, "PLAYBOOKS_DIR", p), patch(
                    "backend.playbooks.loader.validate_autonomous_target",
                    return_value=(False, "no"),
                ):
                    ld.run_playbook("ok", "t")
            self.assertEqual(ld._normalize_target_for_path("https://A.com/x"), "a.com")


if __name__ == "__main__":
    unittest.main()
