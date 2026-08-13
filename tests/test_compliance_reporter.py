"""Testes do compliance mapper indicativo."""

from __future__ import annotations

import unittest
from unittest import mock


class TestCompliance(unittest.TestCase):
    def test_list_frameworks(self):
        from backend.compliance.frameworks import list_frameworks

        ids = {f["id"] for f in list_frameworks()}
        self.assertTrue({"LGPD", "GDPR", "PCI-DSS", "SOC2", "HIPAA", "ISO27001"} <= ids)

    def test_mapping_and_score(self):
        from backend.compliance.mapper import map_findings_to_controls
        from backend.compliance.scoring import indicative_coverage

        findings = [
            {
                "id": "1",
                "title": "SQL Injection in login",
                "severity": "high",
                "status": "confirmed",
            }
        ]
        cmap = map_findings_to_controls(findings, "LGPD")
        score = indicative_coverage(cmap)
        self.assertEqual(score["status"], "gaps_detected")
        self.assertLess(score["indicative_coverage_0_100"], 100)

    def test_report_has_disclaimer(self):
        from backend.compliance.reporter import generate_compliance_report

        findings = [{"id": "1", "title": "Missing HSTS", "severity": "medium"}]
        with mock.patch(
            "backend.compliance.reporter.load_surface",
            return_value={"target": "t.example", "findings": findings},
        ):
            report = generate_compliance_report("t.example", ["LGPD", "GDPR"])
        self.assertIn("NÃO constitui", report["disclaimer_pt"])
        self.assertIn("NOT an audit", report["disclaimer_en"])
        self.assertIn("Disclaimer", report["report_md"])

    def test_unknown_framework(self):
        from backend.compliance.mapper import map_findings_to_controls

        with self.assertRaises(ValueError):
            map_findings_to_controls([], "NOPE")
