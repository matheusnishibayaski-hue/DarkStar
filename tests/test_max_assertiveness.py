"""Teto prático: Nuclei JSON, CVSS, evidências, risk, chains, ZIP, gate rígido."""

from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.ai.chains import infer_attack_chains
from backend.ai.cvss import correlate_cve_version, enrich_finding, estimate_cvss
from backend.ai.evidence import write_finding_evidence
from backend.ai.nuclei_json import parse_nuclei_json_lines
from backend.ai.report import generate_report, generate_report_html
from backend.ai.risk_score import compute_risk_score
from backend.ai.verify import (
    _executive_eligible,
    build_verify_command,
    confidence_gate_buckets,
    score_verification,
)
from backend.executor import surface as surface_mod
from backend.executor.result import ExecutionResult
from backend.executor.surface import get_or_create_surface, save_surface, update_surface_from_execution
from tests.auth_patch import patch_chat_api_token


NUCLEI_JSON = json.dumps(
    {
        "template-id": "missing-header:strict-transport-security",
        "info": {
            "name": "Strict-Transport-Security Header Not Set",
            "severity": "medium",
            "tags": ["misconfig", "headers"],
            "classification": {"cvss-score": 5.3},
        },
        "matched-at": "https://max.test",
        "curl-command": "curl -X GET https://max.test",
        "matcher-name": "header",
    }
)


class TestNucleiJson(unittest.TestCase):
    def test_parse_and_surface(self):
        events = parse_nuclei_json_lines(NUCLEI_JSON + "\n")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["template_id"], "missing-header:strict-transport-security")
        self.assertEqual(events[0]["matched_at"], "https://max.test")
        self.assertTrue(events[0]["curl_command"].startswith("curl"))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(surface_mod, "SURFACE_DIR", root):
                data = update_surface_from_execution(
                    "max.test",
                    command="nuclei -u https://max.test -jsonl",
                    tool="nuclei",
                    stdout=NUCLEI_JSON + "\n",
                    stderr="",
                    success=True,
                    blocked=False,
                )
                self.assertTrue(data["findings"])
                f = data["findings"][0]
                self.assertEqual(f.get("template_id"), "missing-header:strict-transport-security")
                self.assertEqual(f.get("matched_at"), "https://max.test")
                self.assertIsNotNone(f.get("cvss_score"))


class TestCvssAndVersion(unittest.TestCase):
    def test_estimate_and_enrich(self):
        f = {"title": "Missing HSTS", "severity": "medium", "finding_type": "header"}
        cv = estimate_cvss(f)
        self.assertGreater(cv["score"], 0)
        enrich_finding(f)
        self.assertIn("impact", f)
        self.assertIn("effort", f)

    def test_cve_correlation(self):
        finding = {"cve": "CVE-2024-1234", "title": "CVE-2024-1234"}
        corr = correlate_cve_version(
            finding,
            ports=[{"port": "80", "service": "http", "version": "2.4.49", "product": "apache"}],
            nmap_output="80/tcp open http Apache 2.4.49\nCVE-2024-1234\n",
        )
        self.assertTrue(corr["matched"])


class TestGateAndPass3(unittest.TestCase):
    def test_executive_gate_strict(self):
        self.assertTrue(
            _executive_eligible(
                {
                    "status": "confirmed",
                    "confidence": "high",
                    "template_id": "x",
                }
            )
        )
        self.assertFalse(
            _executive_eligible(
                {"status": "confirmed", "confidence": "low", "template_id": "x"}
            )
        )
        self.assertFalse(
            _executive_eligible(
                {"status": "confirmed", "confidence": "medium", "sources": 1}
            )
        )
        self.assertTrue(
            _executive_eligible(
                {
                    "status": "confirmed",
                    "confidence": "medium",
                    "template_id": "t1",
                    "verify_command": "nuclei -id t1",
                }
            )
        )

    def test_waf_pass3_inconclusive(self):
        st, _, reason = score_verification(
            {"title": "x", "severity": "high"},
            ExecutionResult(
                command="c",
                reason="r",
                stdout="cf-ray: 1\nAttention Required\n",
                stderr="",
                exit_code=0,
                success=True,
                blocked=False,
                tool="curl",
            ),
            pass_number=3,
        )
        self.assertEqual(st, "inconclusive")
        self.assertIn("WAF", reason.upper())

    def test_build_pass3_ua(self):
        cmd = build_verify_command(
            {"title": "x", "template_id": "exposed-panels", "severity": "high"},
            "t.com",
            urls=["https://t.com"],
            pass_number=3,
        )
        self.assertIn("User-Agent", cmd)
        self.assertIn("-jsonl", cmd)


class TestRiskChainsReport(unittest.TestCase):
    def test_risk_and_chains(self):
        risk = compute_risk_score(
            [
                {"severity": "critical", "confidence": "high", "cvss_score": 9.8},
                {"severity": "high", "confidence": "high", "cvss_score": 7.5},
            ]
        )
        self.assertEqual(risk["band"], "critical")
        self.assertGreater(risk["score"], 50)

        surface = {
            "ports": [{"port": "443", "service": "https"}],
            "urls": ["https://x"],
            "findings": [
                {
                    "status": "confirmed",
                    "severity": "high",
                    "title": "Missing HSTS",
                    "template_id": "missing-header:hsts",
                    "cve": "CVE-2024-1",
                },
                {
                    "status": "confirmed",
                    "severity": "high",
                    "title": "exposed admin panel",
                },
            ],
        }
        chains = infer_attack_chains(surface)
        self.assertTrue(chains)

    def test_commercial_report_sections(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(surface_mod, "SURFACE_DIR", root):
                data = get_or_create_surface(
                    "rep.max", client="Acme", scope_notes="só prod", brand_name="LabSec"
                )
                data["findings"] = [
                    {
                        "id": "a1",
                        "title": "Missing HSTS header",
                        "severity": "medium",
                        "status": "confirmed",
                        "confidence": "high",
                        "template_id": "missing-header:hsts",
                        "verify_command": "curl -sI https://rep.max",
                        "cvss_score": 5.3,
                        "impact": "MITM",
                        "effort": "baixo",
                        "evidence_path": "evidence/rep.max/a1.txt",
                    },
                    {
                        "id": "b1",
                        "title": "Noise",
                        "severity": "info",
                        "status": "false_positive",
                        "evidence": "ok",
                    },
                ]
                data["urls"] = ["https://rep.max"]
                save_surface("rep.max", data)
                md = generate_report(
                    [], [], surface_target="rep.max", snapshot_baseline=False
                )
                self.assertIn("Resumo Executivo", md)
                self.assertIn("Metodologia", md)
                self.assertIn("Limitações", md)
                self.assertIn("Risk score", md)
                self.assertIn("Missing HSTS", md)
                self.assertIn("confidencial", md.lower())
                html_doc = generate_report_html(
                    [], [], surface_target="rep.max", snapshot_baseline=False
                )
                self.assertIn("risk-badge", html_doc)
                self.assertIn("LabSec", html_doc)


class TestEvidenceAndZip(unittest.TestCase):
    def test_evidence_and_delivery_api(self):
        from backend.main import app

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "outputs"
            out.mkdir()
            with (
                patch.object(surface_mod, "SURFACE_DIR", root),
                patch("backend.ai.evidence.OUTPUTS_DIR", out),
                patch("backend.ai.delivery.OUTPUTS_DIR", out),
                patch_chat_api_token(""),
            ):
                data = get_or_create_surface("zip.test", client="C")
                data["findings"] = [
                    {
                        "id": "z1",
                        "title": "Real",
                        "severity": "high",
                        "status": "confirmed",
                        "confidence": "high",
                        "template_id": "x",
                        "verify_command": "curl -sI https://zip.test",
                    }
                ]
                save_surface("zip.test", data)
                write_finding_evidence(
                    "zip.test",
                    data["findings"][0],
                    command="curl -sI https://zip.test",
                    stdout="HTTP/1.1 200",
                    stderr="",
                    reason="ok",
                    pass_number=1,
                )
                gate = confidence_gate_buckets("zip.test")
                self.assertEqual(len(gate["executive"]), 1)

                client = TestClient(app)
                r = client.get("/api/engagements/zip.test/report?format=zip")
                self.assertEqual(r.status_code, 200)
                self.assertIn("zip", r.headers.get("content-type", ""))
                zf = zipfile.ZipFile(BytesIO(r.content))
                names = zf.namelist()
                self.assertIn("relatorio.md", names)
                self.assertIn("relatorio.html", names)
                self.assertIn("meta.json", names)
                self.assertTrue(any(n.startswith("evidencias/") for n in names))

                r = client.get("/api/engagements/zip.test/risk")
                self.assertEqual(r.status_code, 200)
                self.assertIn("score", r.json())


if __name__ == "__main__":
    unittest.main()
