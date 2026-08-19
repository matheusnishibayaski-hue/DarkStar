"""Heurística de FP e mapeamento ISO 27001."""

from __future__ import annotations

import unittest
from unittest.mock import patch


class TestFpExplain(unittest.TestCase):
    def setUp(self):
        self._fp = patch("backend.ai.fp_learn.is_suppressed", return_value=False)
        self._fp.start()

    def tearDown(self):
        self._fp.stop()

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
        self.assertGreaterEqual(expl["likely_fp"], 88)
        self.assertEqual(expl["suggestion"], "false_positive")
        blob = (expl["what_it_is"] + expl["plain_title"]).lower()
        self.assertTrue("teste" in blob or "ferramenta" in blob)

    def test_xss_high_payload_low_fp(self):
        from backend.ai.fp_explain import explain_false_positive

        expl = explain_false_positive(
            {
                "title": "[high] Reflected XSS in search",
                "severity": "info",
                "evidence": "search=<script>alert(1)</script> reflected in HTML",
                "status": "candidate",
            }
        )
        self.assertEqual(expl["kind"], "xss")
        self.assertLessEqual(expl["likely_fp"], 25)
        self.assertEqual(expl["suggestion"], "confirmed")

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
        self.assertNotIn("2", ids)
        self.assertNotIn("3", ids)
        # candidate claro (confirmed) ou incerto — nunca confirmed humano já fechado
        for row in q:
            self.assertEqual(row["triage"]["suggestion"], "unsure")

    def test_queue_only_unsure_buckets_auto(self):
        from backend.ai.fp_explain import build_triage_buckets

        buckets = build_triage_buckets(
            [
                {
                    "id": "p1",
                    "title": "OK — nmap",
                    "severity": "info",
                    "tool": "nmap",
                    "status": "candidate",
                    "source": "client_history",
                },
                {
                    "id": "x1",
                    "title": "SQL Injection in login",
                    "severity": "high",
                    "status": "candidate",
                },
                {
                    "id": "u1",
                    "title": "Something ambiguous header maybe",
                    "severity": "medium",
                    "status": "candidate",
                    "evidence": "partial timeout",
                },
            ]
        )
        q_ids = {x["id"] for x in buckets["queue"]}
        conf_ids = {x["id"] for x in buckets["auto_confirmed"]}
        fp_ids = {x["id"] for x in buckets["auto_false_positive"]}
        disc_ids = {x["id"] for x in buckets["auto_discarded"]}
        self.assertIn("p1", disc_ids)
        self.assertNotIn("p1", fp_ids)
        self.assertIn("x1", conf_ids)
        self.assertNotIn("p1", q_ids)
        self.assertNotIn("x1", q_ids)
        for row in buckets["queue"]:
            self.assertEqual(row["triage"]["suggestion"], "unsure")

    def test_idor_narrative_not_auto_fp(self):
        from backend.ai.fp_explain import (
            build_triage_buckets,
            detect_finding_kind,
            explain_false_positive,
        )

        finding = {
            "id": "idor1",
            "title": "IDOR / falha de autorização (acesso a dados de outros usuários)",
            "severity": "high",
            "status": "candidate",
            "source": "assistant_narrative",
            "evidence": (
                "Isso confirma que o endpoint não está validando corretamente a autorização "
                "para acessar dados de outros usuários. Um atacante poderia facilmente "
                "iterar sobre os IDs para coletar e-mails e telefones."
            ),
        }
        self.assertEqual(detect_finding_kind(finding), "idor")
        expl = explain_false_positive(finding)
        self.assertEqual(expl["kind"], "idor")
        self.assertNotEqual(expl["suggestion"], "false_positive")
        self.assertLessEqual(expl["likely_fp"], 54)
        buckets = build_triage_buckets([finding])
        disc = {x["id"] for x in buckets["auto_discarded"]}
        fps = {x["id"] for x in buckets["auto_false_positive"]}
        self.assertNotIn("idor1", disc)
        self.assertNotIn("idor1", fps)
        in_queue_or_conf = {x["id"] for x in buckets["queue"]} | {
            x["id"] for x in buckets["auto_confirmed"]
        }
        self.assertIn("idor1", in_queue_or_conf)

    def test_perfil_not_lfi_via_rfi_substring(self):
        from backend.ai.fp_explain import detect_finding_kind

        kind = detect_finding_kind(
            {
                "title": "Endpoint /api/perfil",
                "evidence": "GET /api/perfil/42 retornou nome e e-mail",
                "severity": "info",
            }
        )
        self.assertNotEqual(kind, "lfi")

    def test_receipt_with_idor_evidence_not_scan_summary(self):
        from backend.ai.fp_explain import detect_finding_kind, is_pure_scan_receipt

        finding = {
            "title": "OK — curl",
            "severity": "info",
            "source": "client_history",
            "evidence": "IDOR: endpoint não valida autorização; dados de outros usuários",
        }
        self.assertFalse(is_pure_scan_receipt(finding))
        self.assertEqual(detect_finding_kind(finding), "idor")

    def test_medium_never_forced_auto_fp(self):
        from backend.ai.fp_explain import apply_fp_hard_rules

        likely, verdict, adj, _ = apply_fp_hard_rules(
            kind="generic",
            blob="possible issue",
            likely_fp=90,
            verdict="false_positive",
            severity="medium",
        )
        self.assertEqual(verdict, "unsure")
        self.assertTrue(adj)
        self.assertLessEqual(likely, 54)

    def test_second_look_confirmed_high_fp_in_queue(self):
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
                {
                    "id": "x1",
                    "title": "SQL Injection in login",
                    "severity": "high",
                    "status": "confirmed",
                },
            ]
        )
        ids = {x["id"] for x in q}
        self.assertIn("p1", ids)
        self.assertNotIn("x1", ids)
        self.assertTrue(q[0].get("second_look"))

    def test_auto_confirm_normalizes_severity(self):
        from backend.executor.session_intel import patch_session_finding

        saved = {}

        def _save(_sid, data):
            saved.clear()
            saved.update(data)
            return data

        session = {
            "session_id": "sess-sev-1",
            "session_findings": [
                {
                    "id": "xss1",
                    "title": "[high] Reflected XSS in search",
                    "severity": "info",
                    "status": "candidate",
                    "evidence": "search=<script>alert(1)</script>",
                }
            ],
        }
        with (
            patch("backend.executor.session_intel.load_session", return_value=session),
            patch("backend.executor.session_intel.save_session", side_effect=_save),
        ):
            out = patch_session_finding(
                "sess-sev-1",
                "_session",
                "xss1",
                "confirmed",
                evidence="triage-auto:confirmed",
            )
        self.assertIsNotNone(out)
        self.assertEqual(out["status"], "confirmed")
        self.assertEqual(out["severity"], "high")
        self.assertEqual(saved["session_findings"][0]["severity"], "high")

    def test_batch_preserve_evidence(self):
        from backend.executor.session_intel import patch_session_findings_batch

        saved = {}
        session = {
            "session_id": "sess-batch-1",
            "session_findings": [
                {
                    "id": "r1",
                    "title": "OK — nmap",
                    "severity": "info",
                    "status": "candidate",
                    "evidence": "nmap -sV example.com\n80/tcp open",
                    "source": "client_history",
                }
            ],
        }

        def _save(_sid, data):
            saved.clear()
            saved.update(data)
            return data

        with (
            patch("backend.executor.session_intel.load_session", return_value=session),
            patch("backend.executor.session_intel.save_session", side_effect=_save),
        ):
            n = patch_session_findings_batch(
                "sess-batch-1",
                [{"id": "r1", "status": "discarded", "surface_target": "_session"}],
                preserve_evidence=True,
            )
        self.assertEqual(n, 1)
        self.assertEqual(saved["session_findings"][0]["status"], "discarded")
        self.assertIn("nmap -sV", saved["session_findings"][0]["evidence"])

    def test_ingest_assistant_idor(self):
        from backend.executor.session_intel import ingest_assistant_findings

        saved = {}
        session = {
            "session_id": "sess-narr-1",
            "session_findings": [],
            "targets": [],
            "label": "",
        }

        def _save(_sid, data):
            saved.clear()
            saved.update(data)
            return data

        chat = {
            "messages": [
                {
                    "role": "assistant",
                    "content": (
                        "Isso confirma que o endpoint não está validando corretamente a autorização "
                        "para acessar dados de outros usuários. Um atacante poderia facilmente "
                        "iterar sobre os IDs para coletar informações sensíveis."
                    ),
                }
            ]
        }
        with (
            patch("backend.executor.session_intel.load_session", return_value=session),
            patch("backend.executor.session_intel.save_session", side_effect=_save),
            patch("backend.database.chat_store.get_chat_session", return_value=chat),
        ):
            added = ingest_assistant_findings("sess-narr-1")
        self.assertEqual(added, 1)
        row = saved["session_findings"][0]
        self.assertEqual(row["source"], "assistant_narrative")
        self.assertEqual(row["kind"], "idor")
        self.assertEqual(row["severity"], "high")
        self.assertIn("autorização", row["evidence"].lower())


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
            patch.object(
                si,
                "load_session",
                return_value={"session_id": "sess-abc12345", "session_findings": []},
            ),
            patch.object(si, "save_session", side_effect=_save),
        ):
            n = si.ingest_extracted_findings("sess-abc12345")
        self.assertGreaterEqual(n, 1)
        self.assertTrue(
            any(f.get("status") == "candidate" for f in saved.get("session_findings") or [])
        )

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
            patch(
                "backend.executor.session_intel.aggregate_session_findings",
                return_value=[
                    {
                        "id": "xss1",
                        "title": "[high] Reflected XSS in search",
                        "severity": "high",
                        "status": "confirmed",
                        "evidence": "<script>alert(1)</script>",
                        "host": "shop.test",
                    }
                ],
            ),
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
        self.assertEqual(len(model["client_cards"]), 1)
        self.assertIn("O que pode causar", html)
        self.assertIn("Como corrigir", html)
        self.assertIn("Problemas encontrados", html)
        self.assertIn("Prompt para IA", html)
        self.assertIn("nível de perigo", html.lower())
        self.assertIn("Você é um especialista", model.get("ai_prompt") or "")
        self.assertTrue(raw.startswith(b"%PDF"))
        self.assertGreater(len(raw), 2000)
        self.assertLess(len(raw), 200_000)

    def test_danger_score_one_high_idor(self):
        from backend.ai.fp_explain import residual_risk_score

        one = residual_risk_score([{"status": "confirmed", "severity": "high", "title": "IDOR"}])
        self.assertEqual(one["score"], 62)
        self.assertEqual(one["label"], "Médio alto")
        crit = residual_risk_score(
            [{"status": "confirmed", "severity": "critical"} for _ in range(3)]
        )
        self.assertGreaterEqual(crit["score"], 90)
        self.assertEqual(crit["label"], "Alto")
        empty = residual_risk_score([])
        self.assertEqual(empty["score"], 0)
        self.assertEqual(empty["label"], "Baixo")
        mid = residual_risk_score([{"status": "confirmed", "severity": "medium"}])
        self.assertEqual(mid["label"], "Médio")
        low = residual_risk_score([{"status": "confirmed", "severity": "low"}])
        self.assertEqual(low["label"], "Baixo")

    def test_discarded_receipts_out_of_body(self):
        from backend.ai.report_model import assemble_session_report

        findings = [
            {
                "id": "1",
                "title": "IDOR /users/{id}",
                "severity": "high",
                "status": "confirmed",
                "evidence": "users/1 vs users/2",
            },
            {
                "id": "2",
                "title": "OK — nmap",
                "severity": "info",
                "status": "discarded",
                "kind": "scan_summary",
                "evidence": "triage-auto:false_positive",
            },
        ]
        with (
            patch("backend.executor.session_intel.load_session", return_value={}),
            patch(
                "backend.executor.session_intel.aggregate_session_findings",
                return_value=findings,
            ),
        ):
            model = assemble_session_report(
                history=[{"role": "user", "content": "Teste em shop.example.com"}],
                tool_executions=[],
                session_id="sess-disc-body",
                title="T",
            )
        self.assertEqual(len(model["report_findings"]), 1)
        self.assertEqual(model["report_findings"][0]["status"], "confirmed")
        self.assertEqual(len(model["client_cards"]), 1)
        self.assertEqual(len(model["discarded"]), 1)
        self.assertIn(
            "perigo",
            (model["executive"] + model["simple_summary"]["found"]).lower(),
        )
        self.assertNotIn("process.cwd", ",".join(model["targets"]))
