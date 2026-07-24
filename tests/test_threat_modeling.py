"""Testes de threat modeling heurístico."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock


class TestThreatModeling(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        intel = Path(self.tmp.name)
        self.patches = [
            mock.patch("backend.intelligence.store.INTELLIGENCE_DIR", intel),
            mock.patch("backend.intelligence.store.INTELLIGENCE_STORAGE", "json"),
            mock.patch("backend.intelligence.store.DATABASE_URL", ""),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def test_assets_financial_vs_healthcare(self):
        from backend.intelligence.asset_catalog import assets_for_industry

        fin = assets_for_industry("financial")
        health = assets_for_industry("healthcare")
        self.assertNotEqual(fin[0]["name"], health[0]["name"])
        self.assertGreaterEqual(fin[0]["criticality"], 8)

    def test_generate_plan_with_surface(self):
        from backend.intelligence.threat_modeling import generate_threat_model

        surface = {
            "target": "shop.example",
            "findings": [
                {
                    "id": "1",
                    "title": "SQL Injection",
                    "severity": "high",
                    "status": "confirmed",
                    "template_id": "sqli",
                }
            ],
            "ports": [{"port": "443"}],
            "urls": ["https://shop.example"],
            "tools_run": ["nmap"],
        }
        with mock.patch(
            "backend.intelligence.threat_modeling.load_surface",
            return_value=surface,
        ):
            model = generate_threat_model(
                "shop.example",
                {"industry": "ecommerce"},
            )
        self.assertTrue(model["assets"])
        self.assertTrue(model["scan_plan"])
        self.assertIn("disclaimer", model)
        self.assertTrue(any("nuclei" in (s.get("tools_hint") or []) for s in model["scan_plan"]))

    def test_without_surface(self):
        from backend.intelligence.threat_modeling import generate_threat_model

        with mock.patch(
            "backend.intelligence.threat_modeling.load_surface",
            return_value={},
        ):
            model = generate_threat_model("empty.example", {"industry": "generic"})
        self.assertTrue(model["scan_plan"])
        self.assertEqual(model["chains"], [])
