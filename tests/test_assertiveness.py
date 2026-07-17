"""Dedup, remediação, delta, PoC tipado, WAF, triage API, relatório unificado."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.ai.delta import compute_delta, snapshot_confirmed
from backend.ai.remediation import remediation_for, remediations_for_findings
from backend.ai.report import generate_report, generate_report_html
from backend.ai.verify import (
    build_verify_command,
    classify_finding_type,
    confidence_gate_buckets,
    score_verification,
)
from backend.executor import surface as surface_mod
from backend.executor.result import ExecutionResult
from backend.executor.surface import (
    get_or_create_surface,
    save_surface,
    update_surface_from_execution,
)
from tests.auth_patch import patch_chat_api_token


def _exec(stdout: str = "", *, success: bool = True) -> ExecutionResult:
    return ExecutionResult(
        command="v",
        reason="t",
        stdout=stdout,
        stderr="",
        exit_code=0 if success else 1,
        success=success,
        blocked=False,
        tool="curl",
    )


class TestDedupAndTemplate(unittest.TestCase):
    def test_nuclei_template_dedup_by_cve(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(surface_mod, "SURFACE_DIR", root):
                update_surface_from_execution(
                    "dedup.test",
                    command="nuclei -u https://dedup.test",
                    tool="nuclei",
                    stdout="[critical] [CVE-2024-9999] Log4j RCE\n",
                    stderr="",
                    success=True,
                    blocked=False,
                )
                update_surface_from_execution(
                    "dedup.test",
                    command="nmap -sV dedup.test",
                    tool="nmap",
                    stdout="CVE-2024-9999\n80/tcp open http\n",
                    stderr="",
                    success=True,
                    blocked=False,
                )
                data = surface_mod.load_surface("dedup.test")
                cve_findings = [
                    f for f in data["findings"] if f.get("cve") == "CVE-2024-9999"
                ]
                self.assertEqual(len(cve_findings), 1)
                self.assertGreaterEqual(cve_findings[0].get("sources", 1), 2)
                self.assertTrue(cve_findings[0].get("template_id"))


class TestPocSpecific(unittest.TestCase):
    def test_build_uses_template_id(self):
        cmd = build_verify_command(
            {
                "title": "exposed panel",
                "severity": "high",
                "template_id": "exposed-panels",
                "tool": "nuclei",
            },
            "lab.test",
            urls=["https://lab.test"],
        )
        self.assertIn("-id exposed-panels", cmd)

    def test_cve_command(self):
        cmd = build_verify_command(
            {"title": "CVE-2024-1234", "cve": "CVE-2024-1234", "severity": "high"},
            "lab.test",
            urls=["https://lab.test"],
        )
        self.assertIn("nuclei", cmd)
        self.assertIn("cve-2024-1234", cmd.lower())


class TestWafScoring(unittest.TestCase):
    def test_waf_stays_inconclusive(self):
        status, conf, reason = score_verification(
            {"title": "Missing HSTS header", "severity": "medium"},
            _exec("HTTP/1.1 403\ncf-ray: abc\nAttention Required\n"),
            pass_number=1,
        )
        self.assertEqual(status, "inconclusive")
        self.assertIn("WAF", reason.upper())


class TestRemediation(unittest.TestCase):
    def test_hsts_remediation(self):
        rem = remediation_for({"title": "Missing HSTS header", "severity": "medium"})
        self.assertEqual(rem["key"], "header_hsts")
        self.assertIn("Strict-Transport", rem["action"])

    def test_list_for_confirmed(self):
        rows = remediations_for_findings(
            [
                {"id": "1", "title": "Missing HSTS", "severity": "medium"},
                {"id": "2", "title": "CVE-2024-1", "cve": "CVE-2024-0001", "severity": "high"},
            ]
        )
        self.assertEqual(len(rows), 2)


class TestDelta(unittest.TestCase):
    def test_delta_fixed_and_new(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(surface_mod, "SURFACE_DIR", root):
                data = get_or_create_surface("delta.test")
                data["findings"] = [
                    {
                        "id": "1",
                        "title": "Old bug",
                        "severity": "high",
                        "status": "confirmed",
                        "cve": "CVE-2020-1",
                    },
                    {
                        "id": "2",
                        "title": "Keep",
                        "severity": "medium",
                        "status": "confirmed",
                        "template_id": "keep-me",
                    },
                ]
                save_surface("delta.test", data)
                snapshot_confirmed("delta.test")

                data = surface_mod.load_surface("delta.test")
                data["findings"] = [
                    {
                        "id": "2",
                        "title": "Keep",
                        "severity": "medium",
                        "status": "confirmed",
                        "template_id": "keep-me",
                    },
                    {
                        "id": "3",
                        "title": "Brand new",
                        "severity": "critical",
                        "status": "confirmed",
                        "template_id": "new-one",
                    },
                ]
                save_surface("delta.test", data)
                d = compute_delta("delta.test")
                self.assertTrue(d["has_baseline"])
                self.assertEqual(len(d["fixed"]), 1)
                self.assertEqual(len(d["new"]), 1)
                self.assertEqual(len(d["still_open"]), 1)


class TestUnifiedReport(unittest.TestCase):
    def test_executive_only_confirmed_and_remediation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(surface_mod, "SURFACE_DIR", root):
                data = get_or_create_surface("rep2.test", client="Acme", brand_name="LabSec")
                data["findings"] = [
                    {
                        "id": "a",
                        "title": "Missing HSTS header",
                        "severity": "medium",
                        "status": "confirmed",
                        "confidence": "high",
                        "verify_command": "curl -sI https://x",
                    },
                    {
                        "id": "b",
                        "title": "Noise",
                        "severity": "info",
                        "status": "false_positive",
                        "evidence": "ok",
                    },
                ]
                save_surface("rep2.test", data)
                md = generate_report(
                    [], [], surface_target="rep2.test", snapshot_baseline=False
                )
                self.assertIn("Achados Confirmados", md)
                self.assertIn("Missing HSTS", md)
                self.assertIn("Anexo técnico", md)
                self.assertIn("Remediações", md)
                self.assertIn("Delta de reteste", md)
                self.assertIn("Metodologia", md)
                self.assertIn("Acme", md)
                # HTML export
                html_doc = generate_report_html(
                    [], [], surface_target="rep2.test", snapshot_baseline=False
                )
                self.assertIn("<!DOCTYPE html>", html_doc)
                self.assertIn("LabSec", html_doc)


class TestGateAndApi(unittest.TestCase):
    def test_gate_and_triage_routes(self):
        from backend.main import app

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(surface_mod, "SURFACE_DIR", root), patch_chat_api_token(""):
                data = get_or_create_surface("api.test", client="C1")
                data["findings"] = [
                    {
                        "id": "x1",
                        "title": "Real",
                        "severity": "high",
                        "status": "confirmed",
                        "confidence": "high",
                    },
                    {
                        "id": "x2",
                        "title": "Maybe WAF",
                        "severity": "medium",
                        "status": "inconclusive",
                        "needs_human_review": True,
                        "confidence": "low",
                    },
                ]
                save_surface("api.test", data)
                gate = confidence_gate_buckets("api.test")
                self.assertEqual(len(gate["executive"]), 1)
                self.assertEqual(len(gate["human_queue"]), 1)

                client = TestClient(app)
                r = client.get("/api/engagements/api.test/triage")
                self.assertEqual(r.status_code, 200)
                self.assertEqual(len(r.json()["executive"]), 1)

                r = client.get("/api/engagements/api.test/report?format=html")
                self.assertEqual(r.status_code, 200)
                self.assertIn("text/html", r.headers.get("content-type", ""))

                r = client.patch(
                    "/api/engagements/api.test",
                    json={"client": "C2", "scope_notes": "só prod"},
                )
                self.assertEqual(r.status_code, 200)
                self.assertEqual(r.json()["client"], "C2")

                r = client.post("/api/engagements/api.test/baseline")
                self.assertEqual(r.status_code, 200)
                self.assertEqual(r.json()["baseline_count"], 1)


class TestClassify(unittest.TestCase):
    def test_header_from_template(self):
        self.assertEqual(
            classify_finding_type(
                {"title": "x", "template_id": "missing-header:strict-transport-security"}
            ),
            "header",
        )


if __name__ == "__main__":
    unittest.main()
