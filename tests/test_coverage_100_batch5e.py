"""Lote 5e: pdf_report, CLI, cli_report e rotas restantes até Miss=0."""

from __future__ import annotations

import asyncio
import builtins
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from backend.database import db as db_mod
from click.testing import CliRunner
from fastapi import HTTPException
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


class _LaterTruthy(str):
    """Falsy on first bool check, truthy afterwards (skip _pdf_from_session_model)."""

    def __bool__(self):
        n = getattr(self, "_b", 0) + 1
        object.__setattr__(self, "_b", n)
        return n > 1


class TestPdfHelpers(unittest.TestCase):
    def test_sev_brand_logo_iso_bar_annex(self):
        from backend.ai import pdf_report as pdf_mod
        from backend.ai.pdf_report import (
            _append_iso_soc2,
            _append_triage_annex,
            _bar_drawing,
            _resolve_brand,
            _safe_logo_path,
            _sev_bucket,
        )
        from backend.config import BASE_DIR
        from reportlab.lib.styles import getSampleStyleSheet

        self.assertEqual(_sev_bucket("medium"), "medio")
        self.assertEqual(_sev_bucket("medio"), "medio")
        self.assertEqual(_sev_bucket("média"), "medio")
        self.assertEqual(_sev_bucket("atencao"), "medio")
        self.assertEqual(_sev_bucket("atenção"), "medio")
        self.assertEqual(_sev_bucket("high"), "alto")
        self.assertEqual(_sev_bucket("info"), "baixo")

        with patch(
            "backend.clients.store.get_client",
            return_value={
                "consulting_name": "BrandCo",
                "consulting_color": "1E90FF",
                "consulting_logo_path": "assets/darkstar-logo.png",
                "consulting_footer": "rodape-x",
            },
        ):
            brand = _resolve_brand({"client_id": "acme", "brand_name": "Ignorado"})
        self.assertEqual(brand["name"], "BrandCo")
        self.assertEqual(brand["color"], "#1E90FF")
        self.assertIn("rodape", brand["footer"])

        with patch("backend.clients.store.get_client", side_effect=RuntimeError("meta")):
            _resolve_brand({"client_id": "acme"})

        with patch("backend.clients.store.get_client", return_value={"consulting_color": "ZZZZZZ"}):
            bad = _resolve_brand({"client_id": "acme"})
        self.assertEqual(bad["color"], "#1E90FF")

        with patch("backend.clients.store.get_client", return_value={"consulting_color": "1E90FF"}):
            hashed = _resolve_brand({"client_id": "acme"})
        self.assertEqual(hashed["color"], "#1E90FF")

        outside = Path(tempfile.gettempdir()) / "pdf5e-outside.png"
        outside.write_bytes(b"not-a-real-png")
        _safe_logo_path(str(outside))
        with patch.object(pdf_mod, "_DEFAULT_LOGO", "assets/missing-logo-5e.png"):
            self.assertIsNone(_safe_logo_path(str(outside)))
            self.assertIsNone(_safe_logo_path("assets/missing-logo-5e.png"))
            self.assertIsNone(_safe_logo_path(""))
        defaulted = _safe_logo_path("")
        logo = BASE_DIR / "assets" / "darkstar-logo.png"
        if logo.is_file():
            self.assertEqual(defaulted, logo.resolve())

        story: list = []
        with patch(
            "backend.compliance.reporter.generate_compliance_report",
            side_effect=RuntimeError("iso"),
        ):
            _append_iso_soc2(story, [], "t.test", None, None, None, None, None)
        _append_iso_soc2(story, [], "t.test", None, None, None, None, None, report={})
        with patch(
            "backend.compliance.reporter.generate_compliance_report",
            return_value=None,
        ):
            _append_iso_soc2(story, [], "t.test", None, None, None, None, None)

        ss = getSampleStyleSheet()
        _append_triage_annex(
            [],
            [{"title": "FP titulo"}, {"title": ""}],
            [{"title": "Pendente"}],
            ss["Heading2"],
            ss["BodyText"],
        )
        sp = _bar_drawing([])
        self.assertTrue(sp)


class TestPdfGenerate(unittest.TestCase):
    def test_session_model_digest_and_action(self):
        from backend.ai.pdf_report import _pdf_from_session_model

        model = {
            "title": "Sessao 5e",
            "target": "a.test",
            "now": "01/01/2026 00:00 UTC",
            "targets": ["a.test"],
            "risk": {"score": 12, "label": "baixo"},
            "severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            "kinds": {"Header": 1},
            "tools": {"nmap": 1},
            "executive": "resumo",
            "scope": "escopo",
            "ok_exec": 1,
            "fail_exec": 1,
            "executions": [
                {
                    "command": "nmap -sV a.test",
                    "success": False,
                    "stdout": "",
                    "stderr": "falhou",
                    "tool": "nmap",
                }
            ],
            "findings": [
                {
                    "title": "Missing HSTS",
                    "plain_title": "HSTS ausente",
                    "status": "confirmed",
                    "severity": "medium",
                    "severity_label": "Atencao",
                    "what_it_is": "header",
                    "everyday": "https",
                    "why_it_matters": "mitm",
                    "could_happen": ["roubo"],
                    "how_to_decide": ["curl"],
                    "command": "curl -I",
                    "evidence": "sem hsts",
                }
            ],
            "confirmed": [{"title": "Missing HSTS"}],
            "fps": [],
            "pending": [],
            "discarded": [],
            "remediations": [
                {
                    "remediation_title": "Corrigir HSTS",
                    "finding_title": "Missing HSTS",
                    "severity_label": "Atencao",
                    "who": "ops",
                    "why": "mitm",
                    "action": "Adicionar Strict-Transport-Security",
                    "steps": [],
                    "verify": "curl -I",
                }
            ],
            "notes": ["nota longa da conversa " * 3],
            "iso_cov": 10,
            "soc_cov": 20,
            "compliance": None,
        }
        digest = {
            "tool": "nmap",
            "status_label": "falha",
            "headline": "nao completou",
            "failure": "timeout",
            "bullets": ["porta 80"],
            "command": "nmap -sV a.test",
            "log": "err",
        }
        with (
            patch("backend.ai.report_model.assemble_session_report", return_value=model),
            patch("backend.ai.exec_digest.digest_execution", return_value=digest),
        ):
            raw = _pdf_from_session_model(
                session_id="pdfsess5e01",
                title="Sessao",
                tool_executions=model["executions"],
                history=[],
            )
        self.assertGreater(len(raw), 50)

    def test_import_error_and_commercial_paths(self):
        from backend.ai.pdf_report import generate_report_pdf
        from backend.config import BASE_DIR

        real_import = builtins.__import__

        def _boom(name, globals=None, locals=None, fromlist=(), level=0):  # noqa: A002
            if str(name).startswith("reportlab"):
                raise ImportError("no reportlab")
            return real_import(name, globals, locals, fromlist, level)

        with patch("builtins.__import__", side_effect=_boom):
            with self.assertRaises(RuntimeError):
                generate_report_pdf(surface_target="imp5e.test", title="T")

        targets = [f"h{i}.test" for i in range(5)]
        findings = [
            {"title": "Missing HSTS", "severity": "medium", "status": "confirmed"},
            {"title": "FP", "severity": "low", "status": "false_positive"},
            {"title": "Pend", "severity": "info", "status": "candidate"},
        ]
        execs = [
            {"command": "nmap -sV a.test", "success": True, "stdout": "80/tcp open"},
            {"command": "curl -I a.test", "success": False, "stderr": "fail", "stdout": ""},
        ]
        from reportlab.platypus import SimpleDocTemplate

        logo = (BASE_DIR / "assets" / "darkstar-logo.png").resolve()
        import reportlab.lib.colors as rlcolors

        real_init = rlcolors.Color.__init__

        def _color_init(self, red=0, green=0, blue=0, alpha=1):
            if not getattr(_color_init, "done", False) and float(red) >= 0.92:
                _color_init.done = True
                raise RuntimeError("header_bg")
            return real_init(self, red, green, blue, alpha)

        _color_init.done = False
        sid = _LaterTruthy("pdfsess5e99")
        try:
            rlcolors.Color.__init__ = _color_init
            with (
                patch(
                    "backend.executor.session_intel.load_session",
                    return_value={"targets": targets},
                ),
                patch(
                    "backend.executor.session_intel.aggregate_session_findings",
                    return_value=findings,
                ),
                patch(
                    "backend.executor.session_intel.collect_session_tool_executions",
                    return_value=execs,
                ),
                patch(
                    "backend.ai.pdf_report._safe_logo_path",
                    return_value=logo if logo.is_file() else None,
                ),
                patch("reportlab.platypus.Image", side_effect=RuntimeError("img")),
                patch.object(SimpleDocTemplate, "build", lambda self, *a, **k: None),
                patch("backend.security.audit.record_event", side_effect=RuntimeError("audit")),
            ):
                generate_report_pdf(session_id=sid, title="Relatorio de Pentest")
        finally:
            rlcolors.Color.__init__ = real_init

        sid2 = _LaterTruthy("pdfsess5e98")
        with (
            patch("backend.executor.session_intel.load_session", return_value={"targets": targets}),
            patch(
                "backend.executor.session_intel.aggregate_session_findings", return_value=findings
            ),
            patch(
                "backend.executor.session_intel.collect_session_tool_executions",
                return_value=execs,
            ),
            patch(
                "backend.ai.pdf_report._safe_logo_path",
                return_value=logo if logo.is_file() else None,
            ),
            patch("reportlab.platypus.Image", side_effect=RuntimeError("img")),
            patch("reportlab.pdfgen.canvas.Canvas.drawImage", side_effect=RuntimeError("draw")),
            patch("backend.security.audit.record_event", side_effect=RuntimeError("audit")),
        ):
            raw = generate_report_pdf(session_id=sid2, title="Relatorio de Pentest")
        self.assertGreater(len(raw), 50)

        surf = {
            "label": "",
            "client": "",
            "findings": [{"title": "X", "severity": "high", "status": "confirmed"}],
            "client_id": "acme",
            "objective": "obj",
            "lifecycle": "active",
        }
        with (
            patch("backend.ai.pdf_report.load_surface", return_value=surf),
            patch("backend.ai.pdf_report.normalize_target", return_value="disp5e.test"),
            patch("backend.security.audit.record_event"),
        ):
            raw2 = generate_report_pdf(surface_target="disp5e.test", title="T")
        self.assertGreater(len(raw2), 50)

        surf2 = {
            "label": "Lab",
            "client": "Acme Corp",
            "client_id": "acme",
            "findings": [{"title": "Y", "severity": "medium", "status": "confirmed"}],
            "objective": "pentest",
            "lifecycle": "active",
        }
        chains = [{"title": "Cadeia RCE", "detail": "via cms", "rationale": "r"}]
        with (
            patch("backend.ai.pdf_report.load_surface", return_value=surf2),
            patch("backend.ai.pdf_report.normalize_target", return_value="chain5e.test"),
            patch("backend.ai.delta.compute_delta", return_value={"has_baseline": False}),
            patch(
                "backend.ai.executive_summary.generate_executive_summary",
                return_value={"text": "## Resumo", "source": "rules"},
            ),
            patch("backend.ai.chains.infer_attack_chains", return_value=chains),
            patch(
                "backend.compliance.reporter.generate_compliance_report",
                side_effect=RuntimeError("comp"),
            ),
            patch("backend.security.audit.record_event"),
        ):
            raw3 = generate_report_pdf(
                surface_target="chain5e.test",
                title="T",
                tool_executions=execs,
                regenerate_executive=True,
            )
        self.assertGreater(len(raw3), 50)

        with (
            patch("backend.ai.pdf_report.load_surface", return_value=surf2),
            patch("backend.ai.pdf_report.normalize_target", return_value="chain5e.test"),
            patch("backend.ai.delta.compute_delta", return_value={"has_baseline": False}),
            patch(
                "backend.ai.executive_summary.generate_executive_summary",
                return_value={"text": "ok", "source": "rules"},
            ),
            patch("backend.ai.chains.infer_attack_chains", side_effect=RuntimeError("ch")),
            patch("backend.security.audit.record_event"),
        ):
            generate_report_pdf(surface_target="chain5e.test", title="T")


class TestCliCoverage(unittest.TestCase):
    def test_autonomous_health_tools(self):
        from backend import cli as c
        from backend.ai.autopilot import AutonomousResponse

        runner = CliRunner()
        with patch.object(c, "validate_autonomous_target", return_value=(False, "fora")):
            r = runner.invoke(c.cli, ["autonomous", "--target", "bad.test"])
            self.assertEqual(r.exit_code, c.EXIT_SCOPE)

        with patch.object(c, "validate_autonomous_target", return_value=(True, "")):
            r = runner.invoke(c.cli, ["autonomous", "--target", "scanme.nmap.org", "--dry-run"])
            self.assertEqual(r.exit_code, c.EXIT_OK)

        fake = AutonomousResponse(
            message="ok",
            report="md",
            objective_met=True,
            rounds=2,
            stopped_reason="done",
            tools_executed=1,
        )
        orig = __import__("backend.ai.autopilot", fromlist=["MAX_AUTONOMOUS_ROUNDS"])
        before = orig.MAX_AUTONOMOUS_ROUNDS
        report = {
            "critical": 1,
            "high": 0,
            "vulnerability_count": 1,
            "exit_code": 2,
            "findings": [],
            "target": "scanme.nmap.org",
            "risk_profile": "safe-active",
        }

        def _run(**_kw):
            self.assertEqual(orig.MAX_AUTONOMOUS_ROUNDS, 4)
            return fake

        with (
            patch.object(c, "validate_autonomous_target", return_value=(True, "")),
            patch("backend.ai.autopilot.run_autonomous", side_effect=_run),
            patch.object(c, "build_cli_report", return_value=report),
            patch(
                "backend.integrations.notifications.notification_manager.notify",
                side_effect=RuntimeError("notify"),
            ),
            patch.object(c, "_maybe_comment_pr") as comment,
        ):
            r = runner.invoke(
                c.cli,
                [
                    "autonomous",
                    "--target",
                    "scanme.nmap.org",
                    "--max-rounds",
                    "4",
                    "--github-pr",
                    "acme/repo#12",
                    "--objective",
                    "lab",
                ],
            )
            self.assertEqual(r.exit_code, 2)
            comment.assert_called()
        self.assertEqual(orig.MAX_AUTONOMOUS_ROUNDS, before)

        with (
            patch.object(c, "validate_autonomous_target", return_value=(True, "")),
            patch("backend.ai.autopilot.run_autonomous", side_effect=RuntimeError("boom")),
        ):
            r = runner.invoke(c.cli, ["autonomous", "--target", "scanme.nmap.org"])
            self.assertEqual(r.exit_code, c.EXIT_ERROR)

        r = runner.invoke(c.cli, ["list-tools", "--category", "no-such-cat"])
        self.assertEqual(r.exit_code, 1)
        r = runner.invoke(c.cli, ["list-tools", "--category", "rede"])
        self.assertEqual(r.exit_code, 0)
        self.assertIn("Ferramentas", r.output)

        prov = MagicMock()
        prov.health.return_value = {"ok": False, "detail": "down"}
        with (
            patch("backend.ai.providers.runtime.get_active_provider_name", return_value="ollama"),
            patch("backend.ai.providers.get_llm_provider", return_value=prov),
        ):
            ai = c._check_ai()
        self.assertEqual(ai["status"], "error")

        prov.health.return_value = {"ok": False}
        with (
            patch("backend.ai.providers.runtime.get_active_provider_name", return_value="ollama"),
            patch("backend.ai.providers.get_llm_provider", return_value=prov),
        ):
            c._check_ai()

        with patch(
            "backend.ai.providers.runtime.get_active_provider_name",
            side_effect=RuntimeError("runtime"),
        ):
            with (
                patch.object(c, "AI_PROVIDER", "openrouter"),
                patch.object(c, "OPENROUTER_API_KEY", ""),
            ):
                self.assertEqual(c._check_ai()["status"], "error")
            with patch.object(c, "AI_PROVIDER", "ollama"):
                self.assertIn("runtime", c._check_ai()["message"])

        with patch.object(c, "scope_lock_enabled", return_value=False):
            cfg = c._check_config()
        self.assertIn("unrestricted", cfg["message"])


class TestCliReportCoverage(unittest.TestCase):
    def test_flatten_sarif_risk(self):
        from backend import cli_report as cr

        buckets = {
            "confirmed": [{"id": "1", "title": "A", "severity": "high"}],
            "candidates": [{"id": "1", "title": "A", "severity": "high"}],
            "inconclusive": [{"id": "2", "title": "B", "severity": "weird"}],
        }
        out = cr.flatten_report_findings(buckets, include_candidates=False)
        self.assertEqual(len(out), 2)
        out2 = cr.flatten_report_findings(buckets, include_candidates=True)
        self.assertEqual(len(out2), 2)

        counts = cr.count_by_severity([{"severity": "weird"}, {"severity": "low"}])
        self.assertEqual(counts["weird"], 1)
        self.assertEqual(counts["low"], 1)

        with (
            patch.object(cr, "findings_for_report", return_value={}),
            patch.object(cr, "risk_score_for_target", side_effect=RuntimeError("risk")),
        ):
            rep = cr.build_cli_report("cli5e.test")
        self.assertEqual(rep["risk"]["band"], "unknown")

        self.assertEqual(cr._sarif_level("low"), "note")
        self.assertEqual(cr._sarif_level("info"), "note")
        self.assertEqual(cr._sarif_level("obscure"), "warning")
        self.assertEqual(cr._sarif_level(""), "warning")

        sarif = cr.convert_to_sarif(
            {
                "findings": ["skip", {"title": "X", "severity": "low", "host": "h.test"}],
                "version": "1",
            }
        )
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)


class TestRouteCoverage5e(_DbCase):
    def test_routes_remaining_branches(self):
        from backend.executor import session_intel as si
        from backend.executor import surface as sm
        from backend.main import app
        from backend.routes import chat_sessions as cs_rt
        from backend.routes import clients as cl_rt
        from backend.routes import dashboard as dash
        from backend.routes import data as data_rt
        from backend.routes import engagements as eng
        from backend.routes import intel_sessions as intel_rt
        from backend.routes import portfolio as port
        from backend.routes import reports as rep_rt
        from backend.schedule import store as st

        surf = self.root / "surface"
        surf.mkdir()
        sid = "c5e" + uuid.uuid4().hex[:10]
        intel_sid = "i5e" + uuid.uuid4().hex[:10]
        dash_sid = "d5e" + uuid.uuid4().hex[:10]
        with (
            patch.object(sm, "SURFACE_DIR", surf),
            patch.object(st, "SCHEDULE_DIR", self.root / "sched"),
            patch.object(si, "INTEL_SESSIONS_DIR", self.root / "intel"),
            patch_chat_api_token(""),
        ):
            client = TestClient(app)

            with patch.object(cs_rt, "upsert_chat_session", side_effect=ValueError("bad id")):
                self.assertEqual(
                    client.post(
                        "/api/chat-sessions",
                        json={"id": sid, "title": "t", "messages": []},
                    ).status_code,
                    400,
                )
            with patch.object(cs_rt, "upsert_chat_session", side_effect=ValueError("bad put")):
                self.assertEqual(
                    client.put(
                        f"/api/chat-sessions/{sid}",
                        json={"id": sid, "title": "t", "messages": []},
                    ).status_code,
                    400,
                )
            with patch.object(cs_rt, "upsert_chat_session", side_effect=RuntimeError("persist")):
                self.assertEqual(
                    client.put(
                        f"/api/chat-sessions/{sid}",
                        json={"id": sid, "title": "t", "messages": []},
                    ).status_code,
                    500,
                )
            with patch.object(cs_rt, "delete_chat_session", side_effect=RuntimeError("del")):
                self.assertEqual(client.delete(f"/api/chat-sessions/{sid}").status_code, 500)
            with (
                patch.object(cs_rt, "delete_chat_session", return_value=None),
                patch(
                    "backend.database.reports_store.delete_reports_for_session",
                    side_effect=RuntimeError("pdf"),
                ),
                patch(
                    "backend.executor.session_intel.delete_session_intel",
                    side_effect=RuntimeError("intel"),
                ),
            ):
                self.assertEqual(client.delete(f"/api/chat-sessions/{sid}").status_code, 200)

            with patch.object(cl_rt, "create_client", side_effect=ValueError("slug")):
                self.assertEqual(
                    client.post("/api/clients", json={"client_id": "ok-client"}).status_code,
                    400,
                )
            with patch.object(cl_rt, "delete_client", side_effect=FileNotFoundError("gone")):
                self.assertEqual(client.delete("/api/clients/ghost-co").status_code, 404)

            class _Huge:
                def __len__(self):
                    return 80 * 1024 * 1024 + 1

            up = MagicMock()
            up.read = AsyncMock(return_value=_Huge())
            with self.assertRaises(HTTPException) as ctx:
                asyncio.run(cl_rt.api_clients_restore("cid", file=up))
            self.assertEqual(ctx.exception.status_code, 413)

            with patch.object(cl_rt, "restore_client", side_effect=FileExistsError("exists")):
                self.assertEqual(
                    client.post(
                        "/api/clients/acme/restore",
                        files={"file": ("b.tar.gz", b"abc", "application/gzip")},
                    ).status_code,
                    409,
                )
            with patch.object(cl_rt, "restore_client", side_effect=ValueError("bad tar")):
                self.assertEqual(
                    client.post(
                        "/api/clients/acme/restore",
                        files={"file": ("b.tar.gz", b"abc", "application/gzip")},
                    ).status_code,
                    400,
                )

            from backend.routes import compliance as comp_rt

            with (
                patch.object(comp_rt, "COMPLIANCE_ENABLED", True),
                patch.object(
                    comp_rt, "generate_compliance_report", side_effect=ValueError("no surface")
                ),
            ):
                self.assertEqual(
                    client.post(
                        "/api/compliance/report",
                        json={"target": "comp.test", "frameworks": ["LGPD"]},
                    ).status_code,
                    404,
                )
            with (
                patch.object(comp_rt, "COMPLIANCE_ENABLED", True),
                patch.object(comp_rt, "get_framework", return_value=None),
            ):
                self.assertEqual(
                    client.get("/api/compliance/report/comp.test?frameworks=NOPE").status_code,
                    400,
                )
            with (
                patch.object(comp_rt, "COMPLIANCE_ENABLED", True),
                patch.object(comp_rt, "get_framework", return_value={"id": "LGPD"}),
                patch.object(
                    comp_rt,
                    "generate_compliance_report",
                    return_value={"report_md": "", "frameworks": {}},
                ),
            ):
                self.assertEqual(
                    client.get("/api/compliance/report/comp.test?format=xml").status_code,
                    400,
                )

            with self.assertRaises(HTTPException) as dctx:
                dash._require_session("")
            self.assertEqual(dctx.exception.status_code, 400)
            with self.assertRaises(HTTPException) as dctx2:
                dash.api_export(format="xml", days=30, session_id=dash_sid)
            self.assertEqual(dctx2.exception.status_code, 400)

            hist = [
                {
                    "target": f"t{i}.test",
                    "vulnerability_count": 1,
                    "critical": 0,
                    "timestamp": "2026-01-01",
                }
                for i in range(40)
            ]
            with (
                patch.object(dash, "get_scan_history", return_value=hist),
                patch.object(dash, "compute_metrics", return_value={"total_scans": 40}),
            ):
                pdf = dash.api_export(format="pdf", days=30, session_id=dash_sid)
                self.assertEqual(pdf.media_type, "application/pdf")

            real_import = builtins.__import__

            def _no_rl(name, globals=None, locals=None, fromlist=(), level=0):  # noqa: A002
                if str(name).startswith("reportlab"):
                    raise ImportError("no")
                return real_import(name, globals, locals, fromlist, level)

            with (
                patch.object(dash, "get_scan_history", return_value=[]),
                patch.object(dash, "compute_metrics", return_value={}),
                patch("builtins.__import__", side_effect=_no_rl),
            ):
                with self.assertRaises(HTTPException) as ictx:
                    dash.api_export(format="pdf", days=30, session_id=dash_sid)
                self.assertEqual(ictx.exception.status_code, 500)

            with patch.object(data_rt, "delete_recon", return_value=True):
                self.assertEqual(client.delete("/api/data/recon/ok.test").status_code, 200)
            with patch.object(data_rt, "delete_surface", return_value=True):
                self.assertEqual(client.delete("/api/data/surface/ok.test").status_code, 200)
            with patch.object(data_rt, "delete_output_file", return_value=True):
                self.assertEqual(client.delete("/api/data/files/ok.txt").status_code, 200)

            with patch.object(eng, "validate_autonomous_target", return_value=(False, "scope")):
                self.assertEqual(
                    client.post("/api/engagements", json={"target": "x.test"}).status_code,
                    403,
                )
            with (
                patch.object(eng, "validate_autonomous_target", return_value=(True, "")),
                patch.object(eng, "load_surface", return_value=None),
                patch.object(eng, "get_or_create_surface", return_value={}),
                patch(
                    "backend.ai.scanner_import.import_scanner_payload",
                    side_effect=ValueError("csv"),
                ),
            ):
                self.assertEqual(
                    client.post(
                        "/api/engagements/eng5e.test/import",
                        json={"content": "a,b", "format": "csv"},
                    ).status_code,
                    400,
                )
            self.assertEqual(
                client.post(
                    "/api/engagements/missing.test/findings/nope",
                    json={"status": "confirmed"},
                ).status_code,
                404,
            )

            with (
                patch.object(
                    intel_rt, "ingest_extracted_findings", side_effect=RuntimeError("ing")
                ),
                patch.object(intel_rt, "backfill_session_findings_from_client", return_value={}),
                patch.object(intel_rt, "aggregate_session_findings", return_value=[]),
            ):
                self.assertEqual(
                    client.post(
                        f"/api/intel/sessions/{intel_sid}/triage-queue",
                        json={"executions": [{"command": "nmap a.test"}]},
                    ).status_code,
                    200,
                )
                self.assertEqual(
                    client.get(f"/api/intel/sessions/{intel_sid}/triage-queue").status_code,
                    200,
                )
                self.assertEqual(
                    client.post(
                        f"/api/intel/sessions/{intel_sid}/sync-executions",
                        json={"executions": [{"command": "nmap a.test"}]},
                    ).status_code,
                    200,
                )

            si.save_session(
                intel_sid,
                {
                    "session_findings": [
                        {"id": "f1", "title": "Missing HSTS", "status": "candidate"}
                    ],
                    "targets": ["a.test"],
                },
            )
            self.assertEqual(
                client.post(
                    f"/api/intel/sessions/{intel_sid}/findings/f1",
                    json={"surface_target": "a.test", "status": "confirmed", "evidence": "ok"},
                ).status_code,
                200,
            )
            self.assertEqual(
                client.post(
                    f"/api/intel/sessions/{intel_sid}/findings/{'a' * 161}/ai-review"
                ).status_code,
                400,
            )
            finding = {
                "id": "fai",
                "title": "HSTS",
                "ai_review": {"source": "llm"},
            }
            with (
                patch.object(intel_rt, "aggregate_session_findings", return_value=[finding]),
                patch("backend.ai.fp_ai_review.review_finding", return_value={"source": "llm"}),
                patch.object(intel_rt, "merge_session_finding_fields"),
            ):
                rev = client.post(f"/api/intel/sessions/{intel_sid}/findings/fai/ai-review")
                self.assertEqual(rev.status_code, 200)
                self.assertTrue(rev.json().get("cached"))
            finding2 = {"id": "fai2", "title": "HSTS"}
            with (
                patch.object(intel_rt, "aggregate_session_findings", return_value=[finding2]),
                patch("backend.ai.fp_ai_review.review_finding", return_value={"source": "llm"}),
                patch.object(intel_rt, "merge_session_finding_fields"),
            ):
                rev2 = client.post(f"/api/intel/sessions/{intel_sid}/findings/fai2/ai-review")
                self.assertEqual(rev2.status_code, 200)
                self.assertFalse(rev2.json().get("cached"))

            self.assertEqual(
                client.get("/api/intelligence/threat-model/missing5e.test").status_code,
                404,
            )

            self.assertEqual(port._host(""), "")
            self.assertEqual(port._host("_session"), "")
            self.assertTrue(port._host("a.test"))
            counts = port._status_counts(
                [
                    {"status": "confirmed"},
                    {"status": "false_positive"},
                    {"status": "discarded"},
                    {"status": "candidate"},
                ]
            )
            self.assertEqual(counts["pending"], 1)
            hosts = port._collect_hosts(
                {"targets": ["a.test"]},
                [{"surface_target": "b.test"}, {"host": "c.test"}],
            )
            self.assertIn("a.test", hosts)
            with patch.object(port, "compute_delta", side_effect=RuntimeError("d")):
                self.assertFalse(port._delta_payload("a.test")["has_baseline"])
            with patch.object(port, "risk_score_for_target", side_effect=RuntimeError("r")):
                risk = port._risk_payload("a.test", [{"status": "confirmed", "severity": "high"}])
                self.assertIn("score", risk)
            port_sid = "p5e" + uuid.uuid4().hex[:10]
            with (
                patch.object(port, "sync_session_intel_from_logs", side_effect=RuntimeError("s")),
                patch.object(port, "aggregate_session_findings", side_effect=RuntimeError("a")),
            ):
                rport = client.get(f"/api/portfolio?session_id={port_sid}&client_id=default")
                self.assertEqual(rport.status_code, 200)
            self.assertEqual(client.get("/api/portfolio?session_id=%20%20").status_code, 400)

            fid = "rem5e" + uuid.uuid4().hex[:8]
            client.post(
                "/api/remediation/track",
                json={"finding_id": fid, "remediation_plan": {"steps": ["a"]}},
            )
            self.assertEqual(
                client.patch(
                    f"/api/remediation/track/{fid}",
                    json={"status": "completed", "steps_completed": 1, "notes": "ok"},
                ).status_code,
                200,
            )
            self.assertEqual(
                client.patch(
                    "/api/remediation/track/missing-fid",
                    json={"status": "failed"},
                ).status_code,
                404,
            )
            self.assertEqual(client.get("/api/remediation/alternatives/x").status_code, 501)

            self.assertEqual(
                client.post(
                    "/api/reports",
                    files={"file": ("empty.pdf", b"", "application/pdf")},
                ).status_code,
                400,
            )
            with patch.object(rep_rt, "MAX_PDF_BYTES", 4):
                self.assertEqual(
                    client.post(
                        "/api/reports",
                        files={"file": ("big.pdf", b"12345", "application/pdf")},
                    ).status_code,
                    413,
                )
            with patch.object(rep_rt, "save_report", side_effect=ValueError("bad pdf")):
                self.assertEqual(
                    client.post(
                        "/api/reports",
                        files={"file": ("a.pdf", b"%PDF", "application/pdf")},
                    ).status_code,
                    400,
                )
            disp = rep_rt._disposition("Relatorio")
            self.assertIn(".pdf", disp)
            with patch.object(rep_rt, "get_report", side_effect=RuntimeError("load")):
                self.assertEqual(client.get("/api/reports/rid-x").status_code, 500)
            with patch.object(rep_rt, "get_report", return_value=None):
                self.assertEqual(client.get("/api/reports/rid-x").status_code, 404)
            with patch.object(
                rep_rt, "get_report", return_value={"content": None, "fileName": "a"}
            ):
                self.assertEqual(client.get("/api/reports/rid-x").status_code, 404)
            with patch.object(
                rep_rt,
                "get_report",
                return_value={"content": memoryview(b"%PDF"), "fileName": "a.pdf", "id": "1"},
            ):
                self.assertEqual(client.get("/api/reports/rid-x").status_code, 200)
            with patch.object(rep_rt, "get_report", return_value={"content": b"", "fileName": "a"}):
                self.assertEqual(client.get("/api/reports/rid-x").status_code, 404)

            with patch(
                "backend.routes.schedule_api.validate_autonomous_target",
                return_value=(True, ""),
            ):
                created = client.post(
                    "/api/schedules",
                    json={"target": "sched5e.test", "job_type": "remind", "interval": "weekly"},
                )
            self.assertEqual(created.status_code, 200)
            jid = created.json()["id"]
            patched = client.patch(
                f"/api/schedules/{jid}",
                json={
                    "job_type": "monitor",
                    "scan_profile": "full",
                    "risk_profile": "passive",
                },
            )
            self.assertEqual(patched.status_code, 200)

            self.assertEqual(client.get("/api/scan-profiles").status_code, 200)
            self.assertEqual(client.get("/api/scan-profiles?offensive=true").status_code, 200)
            with patch(
                "backend.ai.providers.runtime.normalize_provider_name",
                return_value="nope",
            ):
                self.assertEqual(
                    client.post("/api/ai-provider", json={"provider": "ollama"}).status_code,
                    422,
                )
            from backend.routes import system as sys_rt

            with (
                patch(
                    "backend.executor.surface.repair_surface_from_stored_output",
                    side_effect=RuntimeError("repair"),
                ),
                patch(
                    "backend.executor.surface.load_surface",
                    return_value={
                        "findings": [{"title": "X", "severity": "high", "status": "confirmed"}]
                    },
                ),
                patch.object(sys_rt, "get_recon_data", return_value={"target": "recon5e.test"}),
            ):
                rec = client.get("/api/recon/recon5e.test")
                self.assertIn(rec.status_code, {200, 404})

            with (
                patch("backend.executor.surface.repair_surface_from_stored_output"),
                patch(
                    "backend.executor.surface.load_surface",
                    return_value={
                        "findings": [{"title": "X", "severity": "high"}],
                        "ports": [{"port": 80, "service": "http"}],
                    },
                ),
                patch.object(sys_rt, "get_recon_data", return_value={"target": "r5e.test"}),
            ):
                rec2 = client.get("/api/recon/r5e.test")
                self.assertEqual(rec2.status_code, 200)
                self.assertTrue(rec2.json().get("vulnerabilities"))

            with patch(
                "backend.executor.data_cleanup.delete_execution_log",
                return_value={"ok": False},
            ):
                self.assertEqual(client.delete("/api/logs/abc123").status_code, 404)
            with patch(
                "backend.executor.data_cleanup.delete_execution_log",
                return_value={"ok": True, "log_id": "abc123"},
            ):
                self.assertEqual(client.delete("/api/logs/abc123").status_code, 200)

            with patch("backend.routes.chat.generate_report_pdf", return_value=b"%PDF"):
                gen = client.post(
                    "/api/generate-report",
                    json={
                        "history": [],
                        "tool_executions": [],
                        "title": "T",
                        "chat_session_id": sid,
                    },
                )
                self.assertEqual(gen.status_code, 200)

            with patch("backend.security.roles.method_allowed", return_value=False):
                denied = client.post(
                    "/api/data/purge", json={"categories": ["logs"], "confirm": True}
                )
                self.assertEqual(denied.status_code, 403)


if __name__ == "__main__":
    unittest.main()
