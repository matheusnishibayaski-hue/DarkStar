"""Lote 5j: statements que o coverage do CI (Ubuntu/Python 3.11) ainda marca Miss."""

from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from backend.database import db as db_mod

from tests.test_coverage_100_batch5h import _FakeSession, _scope_for


class TestCiLinuxMisses(unittest.TestCase):
    def test_wifi_run_netsh_calls_subprocess(self):
        from backend.executor import wifi_scan as wifi

        proc = MagicMock(returncode=0, stdout="ok", stderr="")
        with patch.object(wifi.subprocess, "run", return_value=proc) as run:
            out = wifi._run_netsh(["wlan", "show", "interfaces"], timeout=15)
        self.assertIs(out, proc)
        run.assert_called_once()

    def test_openai_get_client_constructs_once(self):
        from backend.ai.providers.openrouter import OpenRouterAdapter

        fake = MagicMock()
        with patch("backend.ai.providers.openai_compatible.OpenAI", return_value=fake) as cls:
            p = OpenRouterAdapter(api_key="sk")
            c1 = p._get_client()
            c2 = p._get_client()
        self.assertIs(c1, fake)
        self.assertIs(c2, fake)
        cls.assert_called_once()

    def test_openrouter_resolve_models_uses_catalog(self):
        from backend.ai.providers.openrouter import OpenRouterAdapter

        p = OpenRouterAdapter(api_key="sk")
        primary, fallback = p.resolve_models(None, None)
        self.assertTrue(primary)
        self.assertTrue(fallback)

    def test_executive_summary_llm_success_and_source(self):
        from backend.ai import executive_summary as es
        from backend.executor import surface as sm

        prov = MagicMock()
        prov.is_configured.return_value = True
        prov.resolve_models.return_value = ("m", "m")
        inner = MagicMock()
        inner.content = "sumario ok"
        prov.complete.return_value = MagicMock(message=inner)
        with patch("backend.ai.providers.factory.get_llm_provider", return_value=prov):
            self.assertEqual(es._llm_generate("p"), "sumario ok")

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(sm, "SURFACE_DIR", Path(tmp)):
                data = sm.get_or_create_surface("exec5j.test")
                sm.save_surface("exec5j.test", data)
                with (
                    patch(
                        "backend.ai.verify.confidence_gate_buckets",
                        return_value={"executive": []},
                    ),
                    patch(
                        "backend.ai.risk_score.risk_score_for_target",
                        return_value={"label": "Baixo", "score": 1},
                    ),
                    patch(
                        "backend.ai.delta.compute_delta",
                        return_value={
                            "has_baseline": False,
                            "fixed": [],
                            "new": [],
                            "still_open": [],
                            "surface": {},
                        },
                    ),
                    patch(
                        "backend.ai.executive_summary._llm_generate",
                        return_value="llm-text",
                    ),
                ):
                    result = es.generate_executive_summary("exec5j.test", regenerate=True)
                self.assertEqual(result["source"], "llm")
                self.assertEqual(result["text"], "llm-text")

    def test_cli_check_ai_ollama_healthy(self):
        from backend import cli as c

        prov = MagicMock()
        prov.health.return_value = {"ok": True}
        with (
            patch(
                "backend.ai.providers.runtime.get_active_provider_name",
                return_value="ollama",
            ),
            patch("backend.ai.providers.get_llm_provider", return_value=prov),
        ):
            out = c._check_ai()
        self.assertEqual(out["status"], "ok")
        self.assertIn("ollama", out["message"])

    def test_remediation_track_keeps_created_at(self):
        from backend.ai.remediation_ai import RemediationPlan, RemediationTracker

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "track.json"
            tr = RemediationTracker(path)
            plan = RemediationPlan(
                finding_id="r5j",
                vulnerability_title="HSTS",
                severity="medium",
                root_cause="x",
            )
            first = tr.track("r5j", plan)
            created = first["created_at"]
            second = tr.track("r5j", plan, status="in_progress")
            self.assertEqual(second["created_at"], created)

    def test_delete_client_purge_counts_removed_surface(self):
        from backend.clients import store as cs

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            clients = root / "clients"
            surf = root / "surf"
            cdir = clients / "cov5j"
            (cdir / "surface").mkdir(parents=True)
            surf.mkdir()
            (cdir / "meta.json").write_text(
                json.dumps({"client_id": "cov5j"}),
                encoding="utf-8",
            )
            (cdir / "surface" / "lab.test.json").write_text("{}", encoding="utf-8")
            with (
                patch.object(cs, "CLIENTS_DIR", clients),
                patch.object(cs, "SURFACE_DIR", surf),
                patch("backend.database.db.session_scope", side_effect=RuntimeError("db")),
                patch("backend.executor.data_cleanup.delete_surface", return_value=True),
            ):
                out = cs.delete_client("cov5j", purge_surfaces=True)
            self.assertGreaterEqual(out.get("targets_cleared", 0), 1)

    def test_db_postgres_connect_success(self):
        fake_conn = MagicMock()
        fake_engine = MagicMock()
        cm = MagicMock()
        cm.__enter__.return_value = fake_conn
        cm.__exit__.return_value = False
        fake_engine.connect.return_value = cm

        db_mod.reset_engine_for_tests()
        try:
            with (
                patch.object(db_mod, "DATABASE_URL", "postgresql://u:p@127.0.0.1/db"),
                patch.object(db_mod, "_using_sqlite", False),
                patch("backend.database.db.create_engine", return_value=fake_engine),
            ):
                eng = db_mod.get_engine()
            self.assertIs(eng, fake_engine)
            fake_conn.execute.assert_called()
        finally:
            db_mod.reset_engine_for_tests()

    def test_find_surface_path_in_client_workspace(self):
        from backend.executor import surface as sm

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            surf = root / "surface"
            clients = root / "clients"
            surf.mkdir()
            acme = clients / "acme" / "surface"
            acme.mkdir(parents=True)
            cand = acme / "lab.test.json"
            cand.write_text("{}", encoding="utf-8")
            with (
                patch.object(sm, "SURFACE_DIR", surf),
                patch("backend.config.CLIENTS_DIR", clients),
            ):
                found = sm._find_surface_path("lab.test")
            self.assertEqual(found, cand)

    def test_hub_postgres_update_ti_and_stats(self):
        from backend.intelligence import hub
        from backend.intelligence import store as istore

        session = _FakeSession()
        ti = MagicMock()
        ti.industry = "tech"
        ti.findings_aggregate = "{}"
        ti.updated_at = None
        ti.target_name = "cov5j-hub.test"
        session.ti_row = ti
        session.ti_rows = [ti]
        pat = MagicMock()
        pat.industry = "tech"
        pat.pattern_key = "cve:CVE-2024-1"
        pat.finding_type = "cve"
        pat.frequency = 3
        session.pattern_rows = [pat]
        surface = {
            "findings": [
                {
                    "cve": "CVE-2024-1",
                    "title": "X",
                    "severity": "high",
                    "sources": ["nuclei"],
                }
            ],
            "tools_run": ["nuclei"],
            "phase": "vuln_scan",
            "label": "tech",
        }
        with (
            patch.object(hub, "INTELLIGENCE_ENABLED", True),
            patch.object(istore, "use_postgres", return_value=True),
            patch.object(hub, "load_surface", return_value=surface),
            patch.object(hub, "surface_summary", return_value={"findings": 1}),
            patch("backend.database.db.init_db"),
            patch("backend.database.db.session_scope", _scope_for(session)),
        ):
            out = hub.record_from_surface("cov5j-hub.test", industry="tech")
            self.assertEqual(out.get("storage"), "postgres")
            self.assertEqual(ti.findings_aggregate.startswith("{"), True)
            stats = hub.stats()
        self.assertEqual(stats.get("storage"), "postgres")
        self.assertIn("cov5j-hub.test", stats.get("targets") or [])

    def test_threat_model_empty_json_and_update_row(self):
        from backend.intelligence import store as istore
        from backend.intelligence import threat_modeling as tm
        from backend.intelligence.business_context import BusinessContext

        empty = MagicMock()
        empty.threat_model_json = ""
        session = _FakeSession()
        session.ti_row = empty
        with (
            patch.object(istore, "use_postgres", return_value=True),
            patch.object(istore, "load_threat_model_json", return_value={"from": "json"}),
            patch("backend.database.db.init_db"),
            patch("backend.database.db.session_scope", _scope_for(session)),
        ):
            self.assertEqual(tm.get_threat_model("tm5j-empty.test"), {"from": "json"})

        existing = MagicMock()
        existing.industry = "old"
        existing.company_size = "smb"
        existing.threat_model_json = "{}"
        existing.updated_at = None
        session.ti_row = existing
        with (
            patch.object(istore, "use_postgres", return_value=True),
            patch.object(istore, "save_threat_model_json"),
            patch("backend.database.db.init_db"),
            patch("backend.database.db.session_scope", _scope_for(session)),
        ):
            tm._persist_threat_model(
                "tm5j-upd.test",
                {"target": "tm5j-upd.test"},
                industry="tech",
                ctx=BusinessContext(company_size="enterprise"),
            )
        self.assertEqual(existing.industry, "tech")
        self.assertEqual(existing.company_size, "enterprise")
        self.assertTrue(existing.threat_model_json)
        self.assertIsNotNone(existing.updated_at)

    def test_lifespan_inits_intelligence_db(self):
        from backend import main as m

        async def _run():
            with (
                patch("backend.database.db.ensure_dashboard_db"),
                patch("backend.intelligence.store.use_postgres", return_value=True),
                patch("backend.config.DATABASE_URL", "postgresql://u:p@127.0.0.1/db"),
                patch("backend.database.db.init_db") as init,
                patch("backend.schedule.runner.start_scheduler"),
                patch("backend.schedule.runner.stop_scheduler"),
            ):
                async with m.lifespan(m.app):
                    pass
                init.assert_called()

        asyncio.run(_run())


if __name__ == "__main__":
    unittest.main()
