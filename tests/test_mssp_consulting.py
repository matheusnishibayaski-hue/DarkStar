"""MSSP local: white-label, delta enriquecido, clients API, PDF executivo."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.ai import delta as delta_mod
from backend.ai.delta import compute_delta, snapshot_surface_baseline
from backend.ai.executive_summary import (
    business_delta_narrative,
    fallback_executive_text,
    generate_executive_summary,
)
from backend.clients import store as clients_store
from backend.clients.runtime import get_active_client_id, set_active_client_id
from backend.executor import surface as surface_mod
from backend.executor.surface import get_or_create_surface, save_surface


class TestClientsStore(unittest.TestCase):
    def test_create_list_activate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(clients_store, "CLIENTS_DIR", root):
                with patch("backend.config.CLIENTS_DIR", root):
                    clients_store.ensure_default_client()
                    c = clients_store.create_client("acme-corp", display_name="Acme")
                    self.assertEqual(c["client_id"], "acme-corp")
                    items = clients_store.list_clients()
                    ids = {i["client_id"] for i in items}
                    self.assertIn("default", ids)
                    self.assertIn("acme-corp", ids)
                    set_active_client_id("acme-corp")
                    self.assertEqual(get_active_client_id(), "acme-corp")
                    set_active_client_id("default")


class TestSurfaceDelta(unittest.TestCase):
    def test_ports_and_findings_delta(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(surface_mod, "SURFACE_DIR", root):
                data = get_or_create_surface("delta.surf")
                data["ports"] = [
                    {"host": "delta.surf", "port": 80, "proto": "tcp", "service": "http"},
                    {"host": "delta.surf", "port": 443, "proto": "tcp", "service": "https"},
                ]
                data["hosts"] = ["delta.surf"]
                data["findings"] = [
                    {
                        "id": "1",
                        "title": "Old",
                        "severity": "high",
                        "status": "confirmed",
                        "cve": "CVE-2020-1",
                    }
                ]
                save_surface("delta.surf", data)
                snap = snapshot_surface_baseline("delta.surf")
                self.assertEqual(snap["baseline_count"], 1)
                self.assertTrue(snap["surface"].get("ports"))

                data = surface_mod.load_surface("delta.surf")
                data["ports"] = [
                    {"host": "delta.surf", "port": 443, "proto": "tcp", "service": "https"},
                    {"host": "delta.surf", "port": 8080, "proto": "tcp", "service": "http-proxy"},
                ]
                data["hosts"] = ["delta.surf", "api.delta.surf"]
                data["findings"] = [
                    {
                        "id": "2",
                        "title": "New",
                        "severity": "critical",
                        "status": "confirmed",
                        "template_id": "new-bug",
                    }
                ]
                save_surface("delta.surf", data)
                d = compute_delta("delta.surf")
                self.assertTrue(d["has_baseline"])
                self.assertEqual(len(d["fixed"]), 1)
                self.assertEqual(len(d["new"]), 1)
                self.assertGreaterEqual(len(d["surface"]["ports_opened"]), 1)
                self.assertGreaterEqual(len(d["surface"]["ports_closed"]), 1)
                self.assertGreaterEqual(len(d["surface"]["hosts_added"]), 1)
                narrative = business_delta_narrative(d)
                self.assertIn("porta", narrative.lower())


class TestExecutiveFallback(unittest.TestCase):
    def test_fallback_and_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(surface_mod, "SURFACE_DIR", root):
                data = get_or_create_surface("exec.test")
                data["findings"] = [
                    {
                        "id": "1",
                        "title": "Open admin",
                        "severity": "high",
                        "status": "confirmed",
                        "confidence": "high",
                        "template_id": "admin-panel",
                        "impact": "Acesso indevido",
                    }
                ]
                save_surface("exec.test", data)

                text = fallback_executive_text(
                    data["findings"],
                    {"label": "Alto", "score": 70},
                    "Acme",
                    "exec.test",
                    "escopo lab",
                    delta={"has_baseline": False},
                )
                self.assertIn("Postura de risco", text)

                with patch(
                    "backend.ai.executive_summary._llm_generate",
                    side_effect=RuntimeError("no llm"),
                ):
                    with patch(
                        "backend.ai.verify.confidence_gate_buckets",
                        return_value={"executive": data["findings"]},
                    ):
                        with patch(
                            "backend.ai.risk_score.risk_score_for_target",
                            return_value={"label": "Alto", "score": 70},
                        ):
                            with patch.object(
                                delta_mod,
                                "compute_delta",
                                return_value={
                                    "has_baseline": False,
                                    "fixed": [],
                                    "new": [],
                                    "still_open": [],
                                    "surface": {},
                                },
                            ):
                                result = generate_executive_summary("exec.test", use_llm=True)
                self.assertIn(result["source"], {"fallback", "fallback_error"})
                self.assertTrue(result["text"])

                # Cache hit
                with patch(
                    "backend.ai.verify.confidence_gate_buckets",
                    return_value={"executive": data["findings"]},
                ):
                    with patch(
                        "backend.ai.risk_score.risk_score_for_target",
                        return_value={"label": "Alto", "score": 70},
                    ):
                        with patch.object(
                            delta_mod,
                            "compute_delta",
                            return_value={
                                "has_baseline": False,
                                "fixed": [],
                                "new": [],
                                "still_open": [],
                                "surface": {},
                            },
                        ):
                            cached = generate_executive_summary("exec.test")
                self.assertEqual(cached["source"], "cache")


class TestPdfSections(unittest.TestCase):
    def test_pdf_has_executive_and_technical(self):
        try:
            import reportlab  # noqa: F401
        except ImportError:
            self.skipTest("reportlab não instalado")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(surface_mod, "SURFACE_DIR", root):
                data = get_or_create_surface("pdf.mssp")
                data["client"] = "Cliente Demo"
                data["ports"] = [
                    {"host": "pdf.mssp", "port": 443, "proto": "tcp", "service": "https"}
                ]
                data["findings"] = [
                    {
                        "id": "1",
                        "title": "Missing HSTS",
                        "severity": "medium",
                        "status": "confirmed",
                        "tool": "nmap",
                        "command": "nmap -sV pdf.mssp",
                        "evidence": "HSTS missing",
                    }
                ]
                save_surface("pdf.mssp", data)

                from backend.ai.pdf_report import generate_report_pdf

                with patch(
                    "backend.ai.executive_summary.generate_executive_summary",
                    return_value={
                        "text": "### Resumo\n\nRisco controlado.\n\n### Ações prioritárias (30 dias)\n\n- Corrigir HSTS",
                        "source": "fallback",
                        "fingerprint": "x",
                    },
                ):
                    with patch(
                        "backend.ai.verify.confidence_gate_buckets",
                        return_value={"executive": data["findings"]},
                    ):
                        with patch(
                            "backend.ai.risk_score.risk_score_for_target",
                            return_value={"label": "Médio", "score": 45},
                        ):
                            raw = generate_report_pdf(
                                surface_target="pdf.mssp",
                                title="Relatório — Demo",
                            )
                self.assertTrue(raw.startswith(b"%PDF"))
                self.assertGreater(len(raw), 800)


if __name__ == "__main__":
    unittest.main()
