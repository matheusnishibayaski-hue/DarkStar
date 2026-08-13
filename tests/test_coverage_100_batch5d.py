"""Lote 5d: JSON inválido, GitHub parse, MCP framing, scheduler repeat, roles."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from backend.database import db as db_mod
from backend.executor.result import ExecutionResult


class TestJsonErrorPaths(unittest.TestCase):
    def test_stores_logs_mcp_github_roles(self):
        from backend.clients import store as cs
        from backend.executor import logs as logs_mod
        from backend.executor import session_intel as si
        from backend.integrations import github as gh
        from backend.mcp_server import _read_message
        from backend.schedule import runner as rn
        from backend.schedule import store as st
        from backend.security import roles as roles_mod

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            url = f"sqlite:///{(root / 't.db').as_posix()}"
            db_mod.reset_engine_for_tests()
            patches = [
                patch.object(db_mod, "DATABASE_URL", ""),
                patch.object(db_mod, "_SQLITE_PATH", root / "t.db"),
                patch.object(db_mod, "resolve_database_url", return_value=url),
                patch.object(cs, "CLIENTS_DIR", root / "clients"),
                patch.object(st, "SCHEDULE_DIR", root / "sched"),
                patch.object(si, "INTEL_SESSIONS_DIR", root / "intel"),
                patch.object(logs_mod, "LOG_DIR", root / "logs"),
                patch.object(logs_mod, "_SESSION_INDEX_DIR", root / "logs" / "by_session"),
            ]
            for p in patches:
                p.start()
            try:
                db_mod.reset_engine_for_tests()
                db_mod.init_db()
                (root / "clients" / "badco").mkdir(parents=True)
                (root / "clients" / "badco" / "meta.json").write_text("{", encoding="utf-8")
                self.assertIsNone(cs._read_meta_file("badco"))
                (root / "clients" / "notdict").mkdir()
                (root / "clients" / "notdict" / "meta.json").write_text("[]", encoding="utf-8")
                cs._read_meta_file("notdict")
                with patch.object(cs, "session_scope", create=True, side_effect=RuntimeError("db")):
                    cs.get_client("x")
                    cs.list_clients()
                    cs.delete_client("gone-client")
                with patch("backend.database.db.session_scope", side_effect=RuntimeError("db")):
                    cs.get_client("y")
                    st.get_job("jid")
                    st.list_jobs()
                    st.delete_job("jid")

                (root / "sched").mkdir(parents=True, exist_ok=True)
                (root / "sched" / "leg.json").write_text("{", encoding="utf-8")
                st._read_file("leg")
                bad_job = {"id": "mig1", "target": "t.test"}
                (root / "sched" / "mig1.json").write_text(json.dumps(bad_job), encoding="utf-8")
                with patch.object(st, "save_job", side_effect=RuntimeError("no")):
                    st.get_job("mig1")

                idx = root / "logs" / "by_session"
                idx.mkdir(parents=True)
                (idx / "sess-json-1.json").write_text("{", encoding="utf-8")
                logs_mod._register_session_log("sess-json-1", "log1")

                (root / "intel").mkdir(parents=True, exist_ok=True)
                (root / "intel" / "sess-bad1.json").write_text("{", encoding="utf-8")
                si._load_session_from_file("sess-bad1")
            finally:
                for p in patches:
                    p.stop()
                db_mod.reset_engine_for_tests()

        self.assertIsNone(gh.parse_repo_nwo(""))
        self.assertIsNone(gh.parse_repo_nwo("onlyone"))
        self.assertEqual(gh.parse_repo_nwo("git@github.com:o/r.git"), "o/r")
        self.assertEqual(gh.parse_pr_ref("o/r#12")[1], 12)
        self.assertEqual(gh.parse_pr_ref("nope"), (None, None))
        with (
            patch("github.Github", side_effect=RuntimeError("x"), create=True),
            patch("github.Auth", create=True),
        ):
            c = gh.GitHubClient(token="tok")
            self.assertFalse(c.is_available())
            self.assertIsNone(c.get_repo("o/r"))

        stream = io.BytesIO(b"Content-Length: abc\r\n\r\n")
        self.assertIsNone(_read_message(stream))
        stream2 = io.BytesIO(b"Content-Length: 0\r\n\r\n")
        self.assertIsNone(_read_message(stream2))
        stream3 = io.BytesIO(b"Content-Length: 5\r\n\r\n")
        self.assertIsNone(_read_message(stream3))
        stream4 = io.BytesIO(b"Content-Length: 3\r\n\r\n[1]")
        self.assertIsNone(_read_message(stream4))
        stream5 = io.BytesIO(b"Content-Length: 2\r\n\r\n{x")
        self.assertIsNone(_read_message(stream5))

        with patch.object(roles_mod, "OPERATOR_ROLE", "viewer"):
            self.assertFalse(roles_mod.can_admin())
            self.assertTrue(roles_mod.method_allowed("GET", "/api/x"))
            self.assertTrue(roles_mod.method_allowed("POST", "/api/auth/login"))
            self.assertFalse(roles_mod.method_allowed("DELETE", "/api/x"))

        job = {
            "id": "rep1",
            "target": "t.test",
            "scan_profile": "basic",
            "custom_tools": ["nmap"],
            "chat_session_id": "s",
            "risk_profile": "passive",
        }
        with (
            patch("backend.ai.autopilot.run_autonomous", return_value={"ok": True}),
            patch("backend.database.db.record_scan_from_target", side_effect=RuntimeError("x")),
            patch.object(rn, "advance_job"),
            patch("threading.Thread") as th,
        ):
            th.side_effect = lambda target, **kw: MagicMock(start=lambda: target())
            rn.execute_job({**job, "job_type": "repeat"})
        with (
            patch("backend.ai.autopilot.run_autonomous", side_effect=RuntimeError("boom")),
            patch.object(rn, "advance_job"),
            patch("threading.Thread") as th,
        ):
            th.side_effect = lambda target, **kw: MagicMock(start=lambda: target())
            rn.execute_job({**job, "job_type": "repeat"})
        with (
            patch.object(rn, "execute_in_kali", create=True),
            patch("backend.executor.kali.execute_in_kali") as ex,
            patch("backend.executor.surface.get_or_create_surface"),
            patch("backend.executor.surface.update_surface_from_execution"),
        ):
            ex.return_value = ExecutionResult(
                command="nmap",
                reason="",
                stdout="80/tcp open",
                stderr="",
                exit_code=0,
                success=True,
            )
            rn.run_light_monitor("mon.test")

        from backend.executor import data_cleanup as dc

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "a.txt"
            p.write_text("x")
            orig_stat = Path.stat

            class _BoomSize:
                def __init__(self, inner):
                    object.__setattr__(self, "_inner", inner)

                def __getattr__(self, name):
                    if name == "st_size":
                        raise OSError("x")
                    return getattr(object.__getattribute__(self, "_inner"), name)

            def _stat_fail_on_size(self, *a, **kw):
                result = orig_stat(self, *a, **kw)
                if self.suffix == ".txt":
                    return _BoomSize(result)
                return result

            with patch.object(Path, "stat", _stat_fail_on_size):
                dc._dir_stats(Path(tmp), "*.txt") if hasattr(dc, "_dir_stats") else None
            with patch.object(dc, "OUTPUTS_DIR", Path(tmp)):
                (Path(tmp) / "evidence").mkdir()
                (Path(tmp) / "foo.bin").write_text("z")
                dc.storage_summary()


if __name__ == "__main__":
    unittest.main()
