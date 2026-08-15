"""Escopo por cliente, auditoria, erase=all, CWE/OWASP e ROE."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.clients import store as clients_store
from backend.clients.runtime import set_active_client_id
from backend.database import db as db_mod
from fastapi.testclient import TestClient

from tests.auth_patch import patch_chat_api_token


def _sqlite_patches(root: Path):
    url = f"sqlite:///{(root / 't.db').as_posix()}"
    return [
        patch.object(db_mod, "DATABASE_URL", ""),
        patch.object(db_mod, "_SQLITE_PATH", root / "t.db"),
        patch.object(db_mod, "resolve_database_url", return_value=url),
        patch.object(clients_store, "CLIENTS_DIR", root / "clients"),
        patch("backend.clients.store.CLIENTS_DIR", root / "clients"),
    ]


class _DbCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "clients").mkdir()
        db_mod.reset_engine_for_tests()
        self.patches = _sqlite_patches(self.root)
        for p in self.patches:
            p.start()
        db_mod.reset_engine_for_tests()
        db_mod.init_db()
        set_active_client_id("default")

    def tearDown(self):
        set_active_client_id("default")
        for p in self.patches:
            p.stop()
        db_mod.reset_engine_for_tests()
        self.tmp.cleanup()


class TestNormalizeTargets(_DbCase):
    def test_normalize_allowed_targets_shapes(self):
        self.assertEqual(clients_store._normalize_allowed_targets(None), [])
        self.assertEqual(clients_store._normalize_allowed_targets(123), [])
        self.assertEqual(
            clients_store._normalize_allowed_targets("A.TEST, b.test; a.test"),
            ["a.test", "b.test"],
        )
        self.assertEqual(
            clients_store._normalize_allowed_targets(["lab.local", "lab.local"]),
            ["lab.local"],
        )
        self.assertEqual(
            clients_store._normalize_allowed_targets(["https://x.test:443/p"]), ["x.test"]
        )


class TestClientScopeFields(_DbCase):
    def test_create_update_and_legacy_defaults(self):
        created = clients_store.create_client(
            "acme-roe",
            display_name="Acme",
            allowed_targets=["scanme.nmap.org", "10.0.0.5"],
            contract_id="ROE-1",
        )
        self.assertEqual(created["allowed_targets"], ["scanme.nmap.org", "10.0.0.5"])
        self.assertEqual(created["contract_id"], "ROE-1")
        updated = clients_store.update_client(
            "acme-roe",
            allowed_targets="lab.test, lab.test",
            contract_id="ROE-2",
            display_name="Acme Lab",
            ignored="nope",
        )
        self.assertEqual(updated["allowed_targets"], ["lab.test"])
        self.assertEqual(updated["contract_id"], "ROE-2")
        self.assertEqual(updated["display_name"], "Acme Lab")

        from backend.database.db import session_scope
        from backend.database.models_store import ClientRecord

        with session_scope() as db:
            db.add(
                ClientRecord(
                    client_id="legacy-roe",
                    payload_json='{"client_id":"legacy-roe","display_name":"L"}',
                )
            )
        legacy = clients_store.get_client("legacy-roe")
        self.assertEqual(legacy["allowed_targets"], [])
        self.assertEqual(legacy["contract_id"], "")

    def test_update_missing_raises(self):
        with self.assertRaises(FileNotFoundError):
            clients_store.update_client("nope-roe", display_name="x")

    def test_reserved_workspace_dir_skipped(self):
        hidden = self.root / "clients" / ".hidden"
        hidden.mkdir()
        reserved = self.root / "clients" / "store"
        reserved.mkdir()
        self.assertFalse(clients_store._is_client_workspace_dir(hidden))
        self.assertFalse(clients_store._is_client_workspace_dir(reserved))
        self.assertFalse(clients_store._is_client_workspace_dir(self.root / "clients" / "nope"))


class TestEffectiveScope(_DbCase):
    def test_client_list_overrides_env(self):
        import backend.security.scope as scope_mod

        clients_store.create_client(
            "lock-roe",
            allowed_targets=["allowed.lab"],
            contract_id="C-1",
        )
        set_active_client_id("lock-roe")
        with patch.object(scope_mod, "ALLOWED_TARGETS", frozenset({"env.only"})):
            self.assertEqual(scope_mod.effective_allowed_targets(), frozenset({"allowed.lab"}))
            self.assertEqual(scope_mod.scope_source(), "cliente")
            self.assertTrue(scope_mod.scope_lock_enabled())
            self.assertTrue(scope_mod.is_target_allowed("allowed.lab"))
            self.assertTrue(scope_mod.is_target_allowed("sub.allowed.lab"))
            self.assertFalse(scope_mod.is_target_allowed("env.only"))
            ok, msg = scope_mod.validate_autonomous_target("evil.com")
            self.assertFalse(ok)
            self.assertIn("cliente ativo", msg)
            ok2, _ = scope_mod.validate_command_scope(["nmap", "evil.com"])
            self.assertFalse(ok2)

    def test_empty_client_falls_back_to_env(self):
        import backend.security.scope as scope_mod

        clients_store.create_client("empty-roe", allowed_targets=[])
        set_active_client_id("empty-roe")
        with patch.object(scope_mod, "ALLOWED_TARGETS", frozenset({"env.only"})):
            self.assertEqual(scope_mod.effective_allowed_targets(), frozenset({"env.only"}))
            self.assertEqual(scope_mod.scope_source(), "ALLOWED_TARGETS")
            self.assertTrue(scope_mod.is_target_allowed("env.only"))
            self.assertFalse(scope_mod.is_target_allowed("other.com"))

    def test_both_empty_allows(self):
        import backend.security.scope as scope_mod

        set_active_client_id("default")
        with patch.object(scope_mod, "ALLOWED_TARGETS", frozenset()):
            self.assertFalse(scope_mod.scope_lock_enabled())
            self.assertEqual(scope_mod.scope_source(), "")
            self.assertTrue(scope_mod.is_target_allowed("any.com"))
            self.assertTrue(scope_mod.validate_command_scope(["nmap", "any.com"])[0])
            self.assertTrue(scope_mod.validate_autonomous_target("any.com")[0])

    def test_client_lookup_error_falls_back(self):
        import backend.security.scope as scope_mod

        with (
            patch.object(scope_mod, "ALLOWED_TARGETS", frozenset({"env.only"})),
            patch("backend.clients.store.get_client", side_effect=RuntimeError("db")),
        ):
            self.assertEqual(scope_mod.effective_allowed_targets(), frozenset({"env.only"}))


class TestAuditIds(_DbCase):
    def test_record_tool_execution_fields(self):
        import backend.config as cfg
        import backend.security.audit as audit_mod

        clients_store.create_client("aud-roe", contract_id="CTR-9")
        set_active_client_id("aud-roe")
        audit_dir = self.root / "audit"
        audit_dir.mkdir()
        with (
            patch.object(cfg, "AUDIT_DIR", audit_dir),
            patch.object(audit_mod, "AUDIT_DIR", audit_dir),
        ):
            audit_mod.record_tool_execution(
                command="nmap -sV a.test",
                tool="nmap",
                targets=["a.test"],
                success=True,
                client_id="aud-roe",
                contract_id="CTR-9",
                session_id="sess-1",
            )
            events = audit_mod.list_events(limit=5)
            self.assertEqual(events[0]["client_id"], "aud-roe")
            self.assertEqual(events[0]["contract_id"], "CTR-9")
            self.assertEqual(events[0]["session_id"], "sess-1")
            with patch("backend.clients.runtime.get_active_client_id", side_effect=RuntimeError("x")):
                stamp = audit_mod._client_audit_stamp()
                self.assertEqual(stamp["client_id"], "")
            audit_mod.record_event("ping", {"ok": True})
            stamped = [e for e in audit_mod.list_events(limit=10) if e.get("event") == "ping"]
            self.assertEqual(stamped[0]["client_id"], "aud-roe")
            self.assertEqual(stamped[0]["contract_id"], "CTR-9")
            self.assertEqual(audit_mod.remove_entries_by_client_id("aud-roe"), 2)
            self.assertEqual(audit_mod.remove_entries_by_client_id("default"), 0)
            self.assertEqual(audit_mod.remove_entries_by_client_id(""), 0)

    def test_remove_keeps_bad_json(self):
        import backend.config as cfg
        import backend.security.audit as audit_mod

        audit_dir = self.root / "audit2"
        audit_dir.mkdir()
        path = audit_dir / "events-2026-08-14.jsonl"
        path.write_text(
            '{"client_id":"wipe-me","event":"x"}\n\nnot-json\n{"client_id":"keep","event":"y"}\n',
            encoding="utf-8",
        )
        fake_dir = audit_dir / "events-2099-01-01.jsonl"
        fake_dir.mkdir()
        with (
            patch.object(cfg, "AUDIT_DIR", audit_dir),
            patch.object(audit_mod, "AUDIT_DIR", audit_dir),
        ):
            removed = audit_mod.remove_entries_by_client_id("wipe-me")
            self.assertEqual(removed, 1)
            raw = path.read_text(encoding="utf-8")
            self.assertIn("not-json", raw)
            self.assertIn("keep", raw)

    def test_kali_audit_result_stamps_client(self):
        from backend.executor import kali as kali_mod
        from backend.executor.result import ExecutionResult

        clients_store.create_client("kali-roe", contract_id="K-1")
        set_active_client_id("kali-roe")
        result = ExecutionResult(
            command="nmap a.test",
            reason="t",
            stdout="",
            stderr="",
            exit_code=0,
            success=True,
            tool="nmap",
            log_file_id="abc",
        )
        with patch.object(kali_mod, "record_tool_execution") as rec:
            kali_mod._audit_result(result, ["nmap", "a.test"], "t", "m1", session_id="s1")
            kwargs = rec.call_args.kwargs
            self.assertEqual(kwargs["client_id"], "kali-roe")
            self.assertEqual(kwargs["contract_id"], "K-1")
            self.assertEqual(kwargs["session_id"], "s1")

        with (
            patch("backend.clients.runtime.get_active_client_id", side_effect=RuntimeError("x")),
            patch.object(kali_mod, "record_tool_execution") as rec2,
        ):
            kali_mod._audit_result(result, [], "t")
            self.assertEqual(rec2.call_args.kwargs["client_id"], "")


class TestEraseAll(_DbCase):
    def test_erase_all_clears_related(self):
        from backend.database.chat_store import upsert_chat_session
        from backend.executor import data_cleanup as dc
        from backend.schedule import store as schedule_store
        from backend.security import audit as audit_mod

        cid = "erase-roe"
        clients_store.create_client(cid, contract_id="E-1")
        recon_dir = self.root / "recon"
        recon_dir.mkdir()
        recon_dir.joinpath("lab.erase.json").write_text("{}", encoding="utf-8")
        audit_dir = self.root / "audit"
        audit_dir.mkdir()
        (audit_dir / "events-2026-08-14.jsonl").write_text(
            json.dumps({"client_id": cid, "event": "tool_execution"}) + "\n",
            encoding="utf-8",
        )
        upsert_chat_session({"id": "chat-erase-1", "title": "t", "client_id": cid, "messages": []})
        with (
            patch.object(dc, "RECON_DIR", recon_dir),
            patch.object(audit_mod, "AUDIT_DIR", audit_dir),
            patch.object(schedule_store, "SCHEDULE_DIR", self.root / "sched"),
            patch.object(clients_store, "list_client_targets", return_value=["lab.erase"]),
        ):
            job = schedule_store.create_job(target="lab.erase", client_id=cid)
            out = clients_store.delete_client(cid, erase_all=True)
        self.assertTrue(out["erase_all"])
        self.assertGreaterEqual(out["recon_cleared"], 1)
        self.assertGreaterEqual(out["schedules_cleared"], 1)
        self.assertGreaterEqual(out["sessions_cleared"], 1)
        self.assertGreaterEqual(out["audit_lines"], 1)
        self.assertIsNone(clients_store.get_client(cid))
        self.assertFalse(
            schedule_store.get_job(job["id"]) if hasattr(schedule_store, "get_job") else False
        )

    def test_erase_already_gone_and_default_blocked(self):
        gone = clients_store.delete_client("ghost-roe", erase_all=True)
        self.assertTrue(gone["already_gone"])
        self.assertEqual(gone["audit_lines"], 0)
        with self.assertRaises(ValueError):
            clients_store.delete_client("default", erase_all=True)

    def test_erase_related_swallows_errors(self):
        counts = clients_store._erase_client_related("x", ["t"])
        self.assertIn("recon", counts)
        with (
            patch("backend.executor.data_cleanup.delete_recon", side_effect=RuntimeError("r")),
            patch("backend.schedule.store.list_jobs", side_effect=RuntimeError("s")),
            patch("backend.database.chat_store.list_chat_sessions", side_effect=RuntimeError("c")),
            patch(
                "backend.security.audit.remove_entries_by_client_id", side_effect=RuntimeError("a")
            ),
        ):
            out = clients_store._erase_client_related("x", ["t"])
            self.assertEqual(out["recon"], 0)

        with (
            patch(
                "backend.database.chat_store.list_chat_sessions",
                return_value=[{"id": ""}, {"id": "s1"}],
            ),
            patch(
                "backend.database.reports_store.delete_reports_for_session",
                side_effect=RuntimeError("p"),
            ),
            patch(
                "backend.executor.session_intel.delete_session_intel", side_effect=RuntimeError("i")
            ),
            patch(
                "backend.executor.data_cleanup.delete_logs_for_session",
                side_effect=RuntimeError("l"),
            ),
            patch("backend.database.chat_store.delete_chat_session", return_value=True),
            patch("backend.executor.data_cleanup.delete_recon", return_value=False),
            patch("backend.schedule.store.list_jobs", return_value=[]),
            patch("backend.security.audit.remove_entries_by_client_id", return_value=0),
        ):
            out2 = clients_store._erase_client_related("x", [])
            self.assertEqual(out2["sessions"], 1)


class TestClientsApiRoe(_DbCase):
    def test_create_patch_erase_query(self):
        from backend.main import app

        with patch_chat_api_token(""):
            client = TestClient(app)
            created = client.post(
                "/api/clients",
                json={
                    "client_id": "api-roe",
                    "display_name": "API",
                    "contract_id": "API-1",
                    "allowed_targets": ["api.lab"],
                },
            )
            self.assertEqual(created.status_code, 200)
            self.assertEqual(created.json()["allowed_targets"], ["api.lab"])
            patched = client.patch(
                "/api/clients/api-roe",
                json={"allowed_targets": ["api2.lab"], "contract_id": "API-2"},
            )
            self.assertEqual(patched.status_code, 200)
            self.assertEqual(patched.json()["contract_id"], "API-2")
            erased = client.delete("/api/clients/api-roe?erase=all")
            self.assertEqual(erased.status_code, 200)
            self.assertTrue(erased.json()["erase_all"])
            self.assertEqual(client.delete("/api/clients/default?erase=all").status_code, 400)


class TestFindingRefsAndPdf(_DbCase):
    def test_enrich_finding_cwe_owasp(self):
        from backend.ai.report_model import enrich_finding, finding_refs

        refs = finding_refs({"title": "Reflected XSS", "kind": "xss"})
        self.assertEqual(refs["cwe"], "CWE-79")
        self.assertIn("A03", refs["owasp"])
        row = enrich_finding({"title": "SQL injection in login", "severity": "high"})
        self.assertEqual(row["cwe"], "CWE-89")
        self.assertTrue(row["owasp"])
        empty = finding_refs({"title": "banner", "kind": "generic"})
        self.assertEqual(empty["cwe"], "")

    def test_live_report_tags(self):
        from backend.ai.live_report import _render_findings

        html = _render_findings(
            [
                {
                    "title": "XSS",
                    "plain_title": "Script na página",
                    "severity": "high",
                    "severity_label": "Grave",
                    "status": "candidate",
                    "kind_label": "XSS",
                    "cwe": "CWE-79",
                    "owasp": "A03:2021 Injection",
                    "tool": "nuclei",
                    "host": "a.test",
                }
            ]
        )
        self.assertIn("CWE-79", html)
        self.assertIn("A03:2021 Injection", html)

    def test_commercial_pdf_has_roe(self):
        from backend.ai import pdf_report as pdf
        from backend.ai.pdf_report import generate_report_pdf
        from backend.executor import surface as sm
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet

        clients_store.create_client(
            "pdf-roe",
            display_name="PDF Co",
            contract_id="PDF-9",
            allowed_targets=["pdf.test"],
        )
        set_active_client_id("pdf-roe")
        surf_dir = self.root / "surface"
        surf_dir.mkdir()
        base = getSampleStyleSheet()
        styles_extra = {"banner_title": base["Normal"], "banner_sub": base["Normal"]}
        for source in ("cliente", "ALLOWED_TARGETS", ""):
            story: list = []
            pdf._append_roe_page(
                story,
                {
                    "display_name": "PDF Co",
                    "client_id": "pdf-roe",
                    "contract_id": "PDF-9",
                    "allowed": ["pdf.test"] if source else [],
                    "source": source,
                },
                colors.HexColor("#1E90FF"),
                colors.HexColor("#E8F4FF"),
                styles_extra,
                base["Heading2"],
                base["BodyText"],
            )
            self.assertGreater(len(story), 3)
        with patch.object(sm, "SURFACE_DIR", surf_dir):
            data = sm.get_or_create_surface("pdf.test")
            data["client_id"] = "pdf-roe"
            data["findings"] = [
                {
                    "id": "1",
                    "title": "Reflected XSS",
                    "severity": "high",
                    "status": "confirmed",
                    "kind": "xss",
                }
            ]
            sm.save_surface("pdf.test", data)
            with patch.object(pdf, "_append_roe_page", wraps=pdf._append_roe_page) as roe:
                raw = generate_report_pdf(surface_target="pdf.test", title="T")
        self.assertTrue(raw.startswith(b"%PDF"))
        roe.assert_called()

    def test_roe_context_fallbacks(self):
        from backend.ai import pdf_report as pdf

        with patch("backend.clients.runtime.get_active_client_id", side_effect=RuntimeError("x")):
            ctx = pdf._roe_context(None)
            self.assertEqual(ctx["client_id"], "")
        with (
            patch("backend.clients.runtime.get_active_client_id", return_value="pdf-roe"),
            patch("backend.clients.store.get_client", side_effect=RuntimeError("g")),
        ):
            ctx2 = pdf._roe_context({"client_id": ""})
            self.assertEqual(ctx2["display_name"], "pdf-roe")
        with patch(
            "backend.security.scope.effective_allowed_targets", side_effect=RuntimeError("s")
        ):
            ctx3 = pdf._roe_context({"client_id": "pdf-roe"})
            self.assertEqual(ctx3["allowed"], [])


class TestMcpAndCliScope(_DbCase):
    def test_mcp_and_cli_use_effective_lock(self):
        from backend.cli import _check_config
        from backend.mcp_service import server_info

        clients_store.create_client("mcp-roe", allowed_targets=["mcp.lab"])
        set_active_client_id("mcp-roe")
        info = server_info()
        self.assertTrue(info["scope_lock_enabled"])
        cfg = _check_config()
        self.assertIn("Scope lock ON", cfg["message"])
        set_active_client_id("default")
        with patch("backend.security.scope.ALLOWED_TARGETS", frozenset()):
            cfg2 = _check_config()
            self.assertIn("unrestricted", cfg2["message"])
