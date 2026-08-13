"""Heurística de FP e mapeamento ISO 27001."""

from __future__ import annotations

import unittest
from unittest.mock import patch


class TestFpExplain(unittest.TestCase):
    def test_info_port_is_likely_fp(self):
        from backend.ai.fp_explain import explain_false_positive

        expl = explain_false_positive(
            {"title": "80/tcp open http", "severity": "info", "tool": "nmap", "status": "candidate"}
        )
        self.assertGreaterEqual(expl["likely_fp"], 40)
        self.assertTrue(expl["why_false_positive"])
        blob = (expl["plain_title"] + " " + " ".join(expl["why_false_positive"])).lower()
        self.assertTrue("porta" in blob or "serviço" in blob or "info" in blob)

    def test_xss_layperson_story(self):
        from backend.ai.fp_explain import explain_false_positive

        expl = explain_false_positive(
            {
                "title": "Reflected XSS in search",
                "severity": "high",
                "status": "candidate",
            }
        )
        self.assertEqual(expl["kind"], "xss")
        self.assertIn("navegador", (expl["what_it_is"] + expl["everyday"]).lower())
        self.assertTrue(expl["could_happen"])
        self.assertTrue(expl["how_to_decide"])
        self.assertEqual(expl["severity_plain"], "Grave")

    def test_scan_log_is_not_a_hole(self):
        from backend.ai.fp_explain import explain_false_positive

        expl = explain_false_positive(
            {"title": "OK — nmap", "severity": "info", "tool": "nmap", "status": "candidate"}
        )
        self.assertEqual(expl["kind"], "scan_summary")
        self.assertGreaterEqual(expl["likely_fp"], 40)
        blob = (expl["what_it_is"] + expl["plain_title"]).lower()
        self.assertTrue("teste" in blob or "ferramenta" in blob)

    def test_sqli_high_leans_vuln(self):
        from backend.ai.fp_explain import explain_false_positive

        expl = explain_false_positive(
            {
                "title": "SQL Injection in login",
                "severity": "high",
                "cve": "",
                "status": "candidate",
            }
        )
        self.assertLessEqual(expl["likely_fp"], 40)
        self.assertEqual(expl["suggestion"], "confirmed")
        self.assertEqual(expl["kind"], "sqli")
        self.assertTrue(expl["could_happen"])

    def test_queue_skips_confirmed(self):
        from backend.ai.fp_explain import build_triage_queue

        q = build_triage_queue(
            [
                {"id": "1", "title": "HSTS", "severity": "medium", "status": "candidate"},
                {"id": "2", "title": "XSS", "severity": "high", "status": "confirmed"},
                {"id": "3", "title": "old", "severity": "low", "status": "false_positive"},
            ]
        )
        ids = {x["id"] for x in q}
        self.assertEqual(ids, {"1"})
        self.assertIn("triage", q[0])

    def test_queue_includes_confirmed_info_port(self):
        from backend.ai.fp_explain import build_triage_queue

        q = build_triage_queue(
            [
                {
                    "id": "p1",
                    "title": "80/tcp open http",
                    "severity": "info",
                    "tool": "nmap",
                    "status": "confirmed",
                },
                {"id": "x1", "title": "SQL Injection in login", "severity": "high", "status": "confirmed"},
            ]
        )
        ids = {x["id"] for x in q}
        self.assertIn("p1", ids)
        self.assertNotIn("x1", ids)
        self.assertTrue(q[0].get("second_look"))


class TestReportSeverity(unittest.TestCase):
    def test_tagged_high_beats_info_field(self):
        from backend.ai.report_model import normalize_severity

        sev = normalize_severity(
            {"title": "[high] Reflected XSS in search", "severity": "info", "evidence": ""}
        )
        self.assertEqual(sev, "high")

    def test_sql_kind_is_high(self):
        from backend.ai.report_model import enrich_finding

        row = enrich_finding(
            {"title": "SQL Injection in login", "severity": "info", "status": "confirmed"}
        )
        self.assertEqual(row["severity"], "high")
        self.assertEqual(row["severity_label"], "Grave")
        self.assertEqual(row["kind"], "sqli")

    def test_scan_log_stays_info(self):
        from backend.ai.report_model import enrich_finding

        row = enrich_finding({"title": "OK — nmap", "severity": "info", "tool": "nmap"})
        self.assertEqual(row["kind"], "scan_summary")
        self.assertEqual(row["severity"], "info")

    def test_iso_listed_and_maps(self):
        from backend.compliance.frameworks import get_framework, list_frameworks
        from backend.compliance.mapper import map_findings_to_controls
        from backend.compliance.scoring import indicative_coverage

        ids = {f["id"] for f in list_frameworks()}
        self.assertIn("ISO27001", ids)
        self.assertIsNotNone(get_framework("ISO-27001"))
        findings = [
            {
                "id": "1",
                "title": "CVE-2024-1 outdated component",
                "severity": "high",
                "status": "confirmed",
                "cve": "CVE-2024-1",
            }
        ]
        cmap = map_findings_to_controls(findings, "ISO27001")
        score = indicative_coverage(cmap)
        self.assertEqual(score["status"], "gaps_detected")
        a88 = next(c for c in cmap["controls"] if c["id"] == "A.8.8")
        self.assertTrue(a88["gap"])


class TestIngestExtractedFindings(unittest.TestCase):
    def test_creates_candidates_from_execution_output(self):
        from backend.executor import session_intel as si

        execs = [
            {
                "command": "nuclei -u shop.test",
                "stdout": "[high] Reflected XSS in search\nCVE-2024-9999",
                "stderr": "",
                "success": True,
            }
        ]
        saved = {}

        def _save(_sid, data):
            saved.update(data)
            return data

        with (
            patch.object(si, "collect_session_tool_executions", return_value=execs),
            patch.object(si, "load_session", return_value={"session_id": "sess-abc12345", "session_findings": []}),
            patch.object(si, "save_session", side_effect=_save),
        ):
            n = si.ingest_extracted_findings("sess-abc12345")
        self.assertGreaterEqual(n, 1)
        self.assertTrue(any(f.get("status") == "candidate" for f in saved.get("session_findings") or []))

    def test_ingest_merges_when_logs_already_exist(self):
        from backend.executor import session_intel as si

        extra = [
            {
                "command": "nuclei -u shop.test",
                "stdout": "[critical] SQL Injection in /login",
                "stderr": "",
                "success": True,
            }
        ]
        saved = {}

        def _save(_sid, data):
            saved.update(data)
            return data

        existing = {
            "session_id": "sess-abc12345",
            "session_findings": [
                {"id": "exec-1", "title": "OK — nmap", "status": "candidate", "severity": "info"}
            ],
        }
        with (
            patch.object(si, "collect_session_tool_executions", return_value=[]),
            patch.object(si, "load_session", return_value=existing),
            patch.object(si, "save_session", side_effect=_save),
        ):
            n = si.ingest_extracted_findings("sess-abc12345", extra_executions=extra)
        self.assertGreaterEqual(n, 1)
        titles = [f.get("title") for f in saved.get("session_findings") or []]
        self.assertTrue(any("SQL" in str(t) or "Injection" in str(t) for t in titles))

    def test_skip_disk_logs_does_not_read_files(self):
        from backend.executor import session_intel as si

        extra = [
            {
                "command": "nuclei -u shop.test",
                "stdout": "[high] Reflected XSS in search",
                "stderr": "",
                "success": True,
            }
        ]
        saved = {}

        def _save(_sid, data):
            saved.update(data)
            return data

        def _boom(_sid, limit=80):
            raise AssertionError("não deveria ler logs em disco")

        with (
            patch.object(si, "collect_session_tool_executions", side_effect=_boom),
            patch.object(
                si,
                "load_session",
                return_value={"session_id": "sess-abc12345", "session_findings": []},
            ),
            patch.object(si, "save_session", side_effect=_save),
        ):
            n = si.ingest_extracted_findings(
                "sess-abc12345", extra_executions=extra, skip_disk_logs=True
            )
        self.assertGreaterEqual(n, 1)


class TestSessionReportPack(unittest.TestCase):
    def test_preview_and_pdf_share_charts_and_xss_severity(self):
        from backend.ai.live_report import generate_live_report_html
        from backend.ai.pdf_report import generate_report_pdf
        from backend.ai.report_model import assemble_session_report

        execs = [
            {
                "command": "nuclei -u https://shop.test",
                "stdout": "[high] Reflected XSS in search\n",
                "stderr": "",
                "success": True,
                "tool": "nuclei",
            }
        ]
        history = [
            {"role": "user", "content": "Teste autorizado em shop.test"},
            {
                "role": "assistant",
                "content": "A varredura apontou XSS refletido na busca. "
                "Isso precisa de triagem humana antes da entrega ao cliente.",
            },
        ]
        with (
            patch("backend.executor.session_intel.load_session", return_value={}),
            patch("backend.executor.session_intel.aggregate_session_findings", return_value=[]),
        ):
            model = assemble_session_report(
                history=history,
                tool_executions=execs,
                session_id="sess-report-pack",
                title="Relatório — teste",
            )
            html = generate_live_report_html(
                history=history,
                tool_executions=execs,
                session_id="sess-report-pack",
                title="Relatório — teste",
            )
            raw = generate_report_pdf(
                session_id="sess-report-pack",
                title="Relatório — teste",
                tool_executions=execs,
                history=history,
            )

        xss = [f for f in model["findings"] if f.get("kind") == "xss"]
        self.assertTrue(xss)
        self.assertEqual(xss[0]["severity"], "high")
        self.assertEqual(xss[0]["severity_label"], "Grave")
        self.assertTrue(xss[0].get("what_it_is"))
        self.assertTrue(model["executive"])
        self.assertTrue(model["remediations"])
        self.assertEqual(model["remediations"][0].get("key"), "xss")
        self.assertIn("charts", html)
        self.assertIn("Resumo executivo", html)
        self.assertIn("Risco residual", html)
        self.assertIn("Como corrigir", html)
        self.assertIn("script na página", html.lower())
        self.assertTrue(raw.startswith(b"%PDF"))
        self.assertGreater(len(raw), 2000)

