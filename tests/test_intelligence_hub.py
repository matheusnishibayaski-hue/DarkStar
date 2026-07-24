"""Testes do Intelligence Hub (storage JSON — sem Postgres obrigatório)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient


def _fake_surface(target: str = "lab.example") -> dict:
    findings = []
    for i in range(10):
        findings.append(
            {
                "id": f"f{i}",
                "title": f"Finding sample {i}",
                "severity": "high" if i < 3 else "medium",
                "cve": f"CVE-2024-{1000 + i}" if i < 2 else "",
                "template_id": f"tpl-{i}" if i >= 2 else "",
                "status": "candidate" if i % 2 == 0 else "confirmed",
                "sources": ["nuclei"],
            }
        )
    return {
        "target": target,
        "findings": findings,
        "ports": [{"port": "443", "service": "https"}],
        "urls": ["https://lab.example"],
        "tools_run": ["nmap"],
        "phase": "vuln_scan",
        "label": "generic",
    }


class TestIntelligenceHubJson(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.intel_dir = Path(self.tmp.name)

        self.patches = [
            mock.patch("backend.config.INTELLIGENCE_ENABLED", True),
            mock.patch("backend.config.INTELLIGENCE_STORAGE", "json"),
            mock.patch("backend.config.INTELLIGENCE_DIR", self.intel_dir),
            mock.patch("backend.config.DATABASE_URL", ""),
            mock.patch("backend.intelligence.store.INTELLIGENCE_DIR", self.intel_dir),
            mock.patch("backend.intelligence.store.INTELLIGENCE_STORAGE", "json"),
            mock.patch("backend.intelligence.store.DATABASE_URL", ""),
            mock.patch("backend.intelligence.hub.INTELLIGENCE_ENABLED", True),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def test_record_and_patterns(self):
        from backend.intelligence import hub

        surface = _fake_surface("lab.example")
        with mock.patch("backend.intelligence.hub.load_surface", return_value=surface):
            with mock.patch(
                "backend.intelligence.hub.surface_summary",
                return_value={"findings": 10},
            ):
                result = hub.record_from_surface("lab.example")
        self.assertTrue(result["recorded"] if "recorded" in result else result.get("findings_count") == 10)
        self.assertEqual(result["storage"], "json")
        self.assertEqual(result["findings_count"], 10)
        # segunda gravação deve subir frequência
        with mock.patch("backend.intelligence.hub.load_surface", return_value=surface):
            with mock.patch(
                "backend.intelligence.hub.surface_summary",
                return_value={"findings": 10},
            ):
                hub.record_from_surface("lab.example")
        st = hub.stats()
        self.assertGreaterEqual(st["targets_count"], 1)
        self.assertTrue(st["top_patterns"])

    def test_suggest_has_rationale(self):
        from backend.intelligence import hub

        surface = _fake_surface("lab.example")
        surface["tools_run"] = ["nmap"]  # sem nuclei → sugestão
        with mock.patch("backend.intelligence.hub.load_surface", return_value=surface):
            out = hub.suggest("lab.example", limit=5)
        self.assertTrue(out["suggestions"])
        self.assertIn("rationale", out["suggestions"][0])

    def test_similar_overlap(self):
        from backend.intelligence import hub

        surface = _fake_surface("lab.example")
        with mock.patch("backend.intelligence.hub.load_surface", return_value=surface):
            with mock.patch(
                "backend.intelligence.hub.surface_summary",
                return_value={"findings": 10},
            ):
                hub.record_from_surface("lab.example")
                hub.record_from_surface("lab.example")  # history exists

        other = _fake_surface("other.example")
        with mock.patch("backend.intelligence.hub.load_surface", return_value=other):
            with mock.patch(
                "backend.intelligence.hub.surface_summary",
                return_value={"findings": 10},
            ):
                hub.record_from_surface("other.example")

        with mock.patch("backend.intelligence.hub.load_surface", return_value=surface):
            sim = hub.similar_targets("lab.example")
        self.assertTrue(any(t["target"] == "other.example" for t in sim["targets"]))

    def test_surface_missing(self):
        from backend.intelligence import hub
        from backend.intelligence.exceptions import SurfaceNotFound

        with mock.patch("backend.intelligence.hub.load_surface", return_value={}):
            with self.assertRaises(SurfaceNotFound):
                hub.record_from_surface("nope.example")


class TestIntelligenceRoutes(unittest.TestCase):
    def test_disabled_404(self):
        with mock.patch("backend.routes.intelligence.INTELLIGENCE_ENABLED", False):
            from backend.main import app

            client = TestClient(app)
            res = client.get("/api/intelligence/stats")
            self.assertEqual(res.status_code, 404)

    def test_suggest_ok(self):
        with mock.patch("backend.routes.intelligence.INTELLIGENCE_ENABLED", True):
            with mock.patch(
                "backend.intelligence.hub.suggest",
                return_value={"target": "x", "suggestions": []},
            ):
                from backend.main import app

                client = TestClient(app)
                res = client.get("/api/intelligence/suggest/x.example")
                self.assertEqual(res.status_code, 200)
