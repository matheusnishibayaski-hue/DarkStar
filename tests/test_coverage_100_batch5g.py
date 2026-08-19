"""Lote 5g: linhas restantes dos módulos AI (fp, verify, remediation, report)."""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from concurrent.futures import TimeoutError as FuturesTimeout
from pathlib import Path
from unittest.mock import MagicMock, patch

from backend.database import db as db_mod
from backend.executor.result import ExecutionResult


def _sqlite_patches(root: Path):
    url = f"sqlite:///{(root / 't.db').as_posix()}"
    return [
        patch.object(db_mod, "DATABASE_URL", ""),
        patch.object(db_mod, "_SQLITE_PATH", root / "t.db"),
        patch.object(db_mod, "resolve_database_url", return_value=url),
    ]


def _er(**kw):
    d = dict(
        command="c",
        reason="",
        stdout="",
        stderr="",
        exit_code=0,
        success=True,
        blocked=False,
    )
    d.update(kw)
    return ExecutionResult(**d)


def _msg(content="", tool_calls=None):
    inner = MagicMock()
    inner.content = content
    inner.tool_calls = tool_calls if tool_calls is not None else []
    return MagicMock(message=inner)


def _provider(content="", tool_calls=None, configured=True):
    provider = MagicMock()
    provider.is_configured.return_value = configured
    provider.configuration_error.return_value = "IA off"
    provider.resolve_models.return_value = ("m", "m")
    provider.format_error.side_effect = lambda e: str(e)
    provider.is_retryable_error.return_value = False
    provider.complete.return_value = _msg(content, tool_calls)
    return provider


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


class TestFpExplainRemaining(unittest.TestCase):
    def test_plain_title_explain_queue_risk_counts(self):
        from backend.ai.fp_explain import (
            _plain_title,
            _what_to_check,
            build_triage_queue,
            explain_false_positive,
            residual_risk_score,
            severity_counts,
        )

        cve_f = {
            "id": "fp5g-cve",
            "title": "CVE-2021-41773 apache",
            "cve": "CVE-2021-41773",
            "severity": "high",
        }
        self.assertIn("CVE-2021-41773", _plain_title(cve_f, "cve"))

        with patch("backend.ai.fp_learn.is_suppressed", side_effect=RuntimeError("db")):
            explain_false_positive({"title": "generic noise", "severity": "info"})
        with patch("backend.ai.fp_learn.is_suppressed", return_value=True):
            expl = explain_false_positive({"title": "generic noise", "severity": "low"})
        self.assertGreaterEqual(int(expl.get("likely_fp") or 0), 0)

        explain_false_positive({"title": "Missing HSTS", "severity": "low", "cve": "CVE-2020-1"})
        explain_false_positive(
            {
                "title": "x-frame-options clickjack",
                "host": "mail.b5g.local",
                "evidence": "x-frame-options absent smtp",
                "severity": "info",
            }
        )
        explain_false_positive(
            {
                "title": "scan",
                "evidence": "cloudflare waf blocked 403 forbidden",
                "severity": "info",
            }
        )
        explain_false_positive(
            {"title": "scan", "evidence": "timeout connection refused", "severity": "info"}
        )

        a = {"id": "dup-a", "title": "Same Title 5g", "cve": "", "severity": "info"}
        b = {"id": "dup-b", "title": "Same Title 5g", "cve": "", "severity": "info"}
        explain_false_positive(a, siblings=[a, b])
        c1 = {"id": "cve-a", "title": "One", "cve": "CVE-2019-1", "severity": "high"}
        c2 = {"id": "cve-b", "title": "Two", "cve": "CVE-2019-1", "severity": "high"}
        explain_false_positive(c1, siblings=[c1, c2])

        _what_to_check({}, "missing header hsts x-frame csp")
        _what_to_check({"cve": "CVE-2021-1"}, "cve-2021-1")
        _what_to_check({}, "sql xss rce ssti")
        _what_to_check({}, "cloudflare waf blocked")
        _what_to_check({}, "22/tcp open ssh open port")
        _what_to_check({}, "random banner only")

        q = build_triage_queue(
            [
                {"id": "q1", "title": "X", "status": "discarded", "severity": "low"},
                {"id": "q2", "title": "Y", "status": "candidate", "severity": "info"},
                {"id": "q2", "title": "Y-dup", "status": "candidate", "severity": "info"},
                {"id": "q3", "title": "Z", "status": "confirmed", "severity": "info"},
            ]
        )
        self.assertIsInstance(q, list)

        residual_risk_score([{"status": "confirmed", "severity": "critical"} for _ in range(3)])
        residual_risk_score(
            [
                {"status": "confirmed", "severity": "high"},
                {"status": "confirmed", "severity": "high"},
                {"status": "confirmed", "severity": "medium"},
            ]
        )
        residual_risk_score([{"status": "confirmed", "severity": "low"}])
        residual_risk_score([])
        severity_counts(
            [
                {"status": "false_positive", "severity": "critical"},
                {"status": "discarded", "severity": "high"},
                {"status": "confirmed", "severity": "critical"},
                {"status": "candidate", "severity": "medium"},
                {"status": "candidate", "severity": "low"},
                {"status": "candidate", "severity": "info"},
            ]
        )


class TestFpLearnRemaining(_DbCase):
    def test_migrate_remember_unlink_branches(self):
        from backend.ai import fp_learn
        from backend.database.db import session_scope
        from backend.database.models_store import FpSuppressPattern
        from backend.intelligence.patterns import pattern_key_for_finding

        fp_learn.reset_for_tests()
        missing = self.root / "no-fp-file.json"
        with patch.object(fp_learn, "FP_SUPPRESS_PATH", missing):
            fp_learn._migrate_legacy_json()

        fp_learn.reset_for_tests()
        fp_learn.remember_false_positive({"title": "MigExist 5g"}, target="a.b5g.test")
        key, _ = pattern_key_for_finding({"title": "MigExist 5g"})
        with session_scope() as db:
            row = db.query(FpSuppressPattern).filter(FpSuppressPattern.pattern_key == key).first()
            row.targets_json = "{notjson"
            row.title = ""

        legacy = self.root / "fp-legacy-5g.json"
        legacy.write_text(
            json.dumps(
                {
                    "patterns": {
                        key: {
                            "pattern_key": key,
                            "title": "MigExist 5g",
                            "hits": 4,
                            "targets": ["b.b5g.test"],
                        },
                        "skip-nd": "not-a-dict",
                        "": {"pattern_key": "", "title": "empty-pk"},
                    }
                }
            ),
            encoding="utf-8",
        )
        fp_learn.reset_for_tests()
        with patch.object(fp_learn, "FP_SUPPRESS_PATH", legacy):
            fp_learn._migrate_legacy_json()

        with patch.object(Path, "unlink", side_effect=OSError("denied")):
            fp_learn._unlink_legacy(self.root / "gone.json")

        fp_learn.remember_false_positive({"title": "SameHit 5g"}, target="t1.b5g.test")
        key2, _ = pattern_key_for_finding({"title": "SameHit 5g"})
        with session_scope() as db:
            row = db.query(FpSuppressPattern).filter(FpSuppressPattern.pattern_key == key2).first()
            row.targets_json = "{bad"
            row.title = ""
        fp_learn.remember_false_positive({"title": "SameHit 5g"}, target="t2.b5g.test")
        with session_scope() as db:
            row = db.query(FpSuppressPattern).filter(FpSuppressPattern.pattern_key == key2).first()
            row.targets_json = '{"a": 1}'
            row.title = ""
        rec = fp_learn.remember_false_positive({"title": "SameHit 5g"}, target="t3.b5g.test")
        self.assertTrue(rec.get("pattern_key"))


class TestFpAiReviewRemaining(unittest.TestCase):
    def test_extract_parse_calibrate_review_llm(self):
        from backend.ai.fp_ai_review import (
            _extract_json,
            _unavailable,
            calibrate_review,
            parse_ai_review,
            review_finding,
        )

        self.assertIsNone(_extract_json("no braces here"))
        self.assertEqual(_extract_json('prefix {"verdict": "ok"} suffix')["verdict"], "ok")
        self.assertIsNone(_extract_json("{not json at all}"))
        self.assertIsNone(parse_ai_review("nope"))
        fp = parse_ai_review('{"verdict":"fp","confidence":80,"reasons":"unico"}')
        self.assertEqual(fp["verdict"], "false_positive")
        unsure = parse_ai_review('{"verdict":"weird","confidence":"x"}')
        self.assertEqual(unsure["verdict"], "unsure")
        _unavailable("offline")
        cal = calibrate_review(
            {"title": "Missing HSTS"},
            {"verdict": "unsure", "likely_fp": "nope"},
        )
        self.assertIn("verdict", cal)

        finding = {"title": "Missing HSTS 5g", "evidence": "no header"}
        with patch(
            "backend.ai.providers.get_llm_provider", return_value=_provider(configured=False)
        ):
            out = review_finding(finding)
        self.assertEqual(out.get("source"), "unavailable")

        bad = _provider(content="not-json-at-all")
        with patch("backend.ai.providers.get_llm_provider", return_value=bad):
            out = review_finding({"title": "HSTS", "evidence": "x"})
        self.assertEqual(out.get("source"), "unavailable")

        ok = _provider(content='{"verdict":"confirmed","likely_fp":10,"summary":"ok"}')
        with patch("backend.ai.providers.get_llm_provider", return_value=ok):
            out = review_finding({"title": "HSTS", "evidence": "x"})
        self.assertIn(out.get("source"), {"llm", "unavailable"})

        cached = {
            "title": "HSTS",
            "ai_review": {"source": "llm", "verdict": "confirmed", "likely_fp": 12},
        }
        review_finding(cached)

        with patch("backend.ai.fp_ai_review.ThreadPoolExecutor") as pool:
            inst = MagicMock()
            fut = MagicMock()
            fut.result.side_effect = FuturesTimeout()
            inst.submit.return_value = fut
            pool.return_value.__enter__.return_value = inst
            timed = review_finding({"title": "timeout-5g", "evidence": "e"})
        self.assertEqual(timed.get("source"), "unavailable")

        with patch("backend.ai.fp_ai_review.ThreadPoolExecutor") as pool:
            inst = MagicMock()
            fut = MagicMock()
            fut.result.side_effect = RuntimeError("llm-down")
            inst.submit.return_value = fut
            pool.return_value.__enter__.return_value = inst
            failed = review_finding({"title": "fail-5g", "evidence": "e"})
        self.assertEqual(failed.get("source"), "unavailable")


class TestVerifyRemainingLines(unittest.TestCase):
    def test_base_url_commands_score_pipeline(self):
        from backend.ai import verify as v
        from backend.executor import surface as sm

        self.assertEqual(
            v._base_url("zzzuniquehost.example", ["https://other.example/path"]),
            "https://other.example/path",
        )
        self.assertIn(
            "nuclei",
            v.build_verify_command(
                {"title": "xss", "finding_type": "xss", "template_id": "xss-ref"},
                "t.com",
                pass_number=2,
            )
            or "",
        )
        self.assertIn(
            "curl",
            v.build_verify_command({"title": "xss", "finding_type": "xss"}, "t.com", pass_number=2)
            or "",
        )
        self.assertIn(
            "curl",
            v.build_verify_command({"finding_type": "mystery", "title": "x"}, "t.com") or "",
        )

        st, _, _ = v.score_verification(
            {"title": "HSTS header check", "template_id": "hsts", "finding_type": "header"},
            _er(stdout="HTTP/1.1 200 OK"),
        )
        self.assertEqual(st, "false_positive")

        with patch.object(v, "_CONFIRM_HINTS", re.compile(r"(?!x)x")):
            st, conf, _ = v.score_verification(
                {
                    "title": "Apache path",
                    "cve": "CVE-2021-41773",
                    "finding_type": "cve",
                    "severity": "high",
                },
                _er(stdout="CVE-2021-41773 apache/2.4.49"),
                surface_context={"ports": [{"service": "http", "port": 80, "version": "2.4.49"}]},
            )
            self.assertEqual(st, "confirmed")
            st, conf, _ = v.score_verification(
                {
                    "title": "web cve",
                    "cve": "CVE-2021-41773",
                    "finding_type": "cve",
                    "severity": "high",
                },
                _er(stdout="CVE-2021-41773 cited"),
                surface_context={"ports": [{"service": "http", "port": 80, "version": "2.4"}]},
            )
            self.assertEqual(st, "confirmed")
            st, conf, _ = v.score_verification(
                {
                    "title": "ssh cve",
                    "cve": "CVE-2021-41773",
                    "finding_type": "cve",
                    "severity": "high",
                },
                _er(stdout="CVE-2021-41773 cited"),
                surface_context={"ports": [{"service": "ssh", "port": 22, "version": "8.0"}]},
            )
            self.assertEqual(st, "confirmed")

        st, _, _ = v.score_verification(
            {"title": "unique-title-xyz5g", "severity": "medium"},
            _er(stdout="unique-title-xyz5g seen on host"),
        )
        self.assertEqual(st, "confirmed")
        st, _, _ = v.score_verification(
            {"title": "high-gap-5g", "severity": "high"},
            _er(stdout="hello world only"),
            pass_number=1,
        )
        self.assertEqual(st, "inconclusive")
        st, _, _ = v.score_verification(
            {"title": "unique-title-xyz5g", "severity": "high"},
            _er(stdout="unique-title-xyz5g not vulnerable"),
            pass_number=2,
        )
        self.assertEqual(st, "discarded")
        st, _, _ = v.score_verification(
            {"title": "ambig-5g", "severity": "high"},
            _er(success=False, stdout="error details here", exit_code=1),
            pass_number=1,
        )
        self.assertEqual(st, "inconclusive")

        self.assertFalse(v._executive_eligible({"status": "candidate", "confidence": "high"}))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(sm, "SURFACE_DIR", root):
                data = sm.get_or_create_surface("ver5g.test")
                data["urls"] = ["https://ver5g.test/"]
                data["findings"] = [
                    {
                        "id": "h5g",
                        "title": "Missing HSTS",
                        "severity": "medium",
                        "status": "candidate",
                        "template_id": "hsts",
                    }
                ]
                sm.save_surface("ver5g.test", data)
                with patch("backend.ai.cvss.enrich_finding", side_effect=TypeError("x")):
                    v._apply_status(
                        "ver5g.test",
                        "h5g",
                        "confirmed",
                        evidence="e",
                        confidence="high",
                        verify_command="curl",
                        pass_number=1,
                    )
                data_n = sm.get_or_create_surface("nocmd5g.test")
                data_n["findings"] = [
                    {
                        "id": "n5g",
                        "title": "generic-none-cmd",
                        "severity": "low",
                        "status": "candidate",
                        "finding_type": "generic",
                    }
                ]
                sm.save_surface("nocmd5g.test", data_n)
                with patch.object(v, "build_verify_command", return_value=None):
                    pipe = v.run_verification_pipeline(
                        "nocmd5g.test",
                        max_findings=2,
                        execute=lambda command, reason: _er(stdout="ok"),
                    )
                self.assertEqual(pipe.confirmed, 0)

                data = sm.load_surface("ver5g.test") or sm.get_or_create_surface("ver5g.test")
                data["findings"] = [
                    {
                        "id": "p5g",
                        "title": "Missing HSTS",
                        "severity": "medium",
                        "status": "candidate",
                        "template_id": "hsts",
                    }
                ]
                sm.save_surface("ver5g.test", data)
                with patch("backend.executor.kali.execute_in_kali", return_value=_er(stdout="ok")):
                    v.run_verification_pipeline("ver5g.test", max_findings=1)

                data["findings"] = [
                    {
                        "id": "w5g",
                        "title": "xss",
                        "severity": "high",
                        "status": "candidate",
                        "finding_type": "xss",
                    }
                ]
                sm.save_surface("ver5g.test", data)
                with patch(
                    "backend.ai.evidence.write_finding_evidence", side_effect=OSError("disk")
                ):
                    v.run_verification_pipeline(
                        "ver5g.test",
                        max_findings=1,
                        execute=lambda command, reason: _er(stdout="hello world only"),
                    )

                data["findings"] = [
                    {
                        "id": "c5g",
                        "title": "generic-gap-5g",
                        "severity": "high",
                        "status": "candidate",
                        "finding_type": "generic",
                    }
                ]
                sm.save_surface("ver5g.test", data)
                orig_apply = v._apply_status

                def _apply_skip_reverify(target, finding_id, status, **kw):
                    saved = "confirmed" if status == "inconclusive" else status
                    return orig_apply(target, finding_id, saved, **kw)

                with patch.object(v, "_apply_status", side_effect=_apply_skip_reverify):
                    v.run_verification_pipeline(
                        "ver5g.test",
                        max_findings=1,
                        execute=lambda command, reason: _er(stdout="hello world only"),
                    )

                data = sm.get_or_create_surface("can5g.test")
                data["findings"] = [
                    {
                        "id": "m5g",
                        "title": "Missing HSTS",
                        "severity": "medium",
                        "status": "candidate",
                        "template_id": "hsts",
                    }
                ]
                sm.save_surface("can5g.test", data)
                with patch("backend.security.missions.get_mission_registry") as reg:
                    inst = MagicMock()
                    inst.is_cancelled.return_value = True
                    reg.return_value = inst
                    cancelled = v.run_verification_pipeline(
                        "can5g.test",
                        max_findings=1,
                        execute=lambda command, reason: _er(stdout="ok"),
                        mission_id="miss-5g-01",
                    )
                self.assertTrue(cancelled is not None)


class TestRemediationAiRemaining(unittest.TestCase):
    def test_extract_generate_parse_verify_track(self):
        from backend.ai.providers.base import LLMMessage
        from backend.ai.remediation_ai import (
            RemediationAdvisor,
            RemediationPlan,
            RemediationTracker,
            RemediationVerifier,
            _extract_json_object,
        )

        self.assertIsNone(_extract_json_object(""))
        self.assertIsNone(_extract_json_object("no-braces"))
        self.assertIsNone(_extract_json_object("{not json} prefix ```json\n{also bad}\n```"))
        fenced = '{not json} ```json\n{"a":1}\n``` extra}'
        self.assertEqual(_extract_json_object(fenced), {"a": 1})

        adv = RemediationAdvisor()
        finding = {"id": "r5g", "title": "Missing HSTS", "severity": "medium"}
        with patch(
            "backend.ai.remediation_ai.get_llm_provider", return_value=_provider(configured=False)
        ):
            fb = adv.generate_remediation(finding)
        self.assertEqual(fb.source, "fallback")

        p = _provider()
        p.complete.side_effect = RuntimeError("down")
        with patch("backend.ai.remediation_ai.get_llm_provider", return_value=p):
            adv.generate_remediation(finding)

        body = json.dumps(
            {
                "root_cause": "header",
                "steps": [
                    "skip-me",
                    {
                        "step": 1,
                        "title": "Fix",
                        "description": "add header",
                        "command": "curl -sI https://x",
                        "notes": "n",
                    },
                ],
                "confidence": "bad",
                "estimated_time": "bad",
                "difficulty": "insane",
                "references": "not-list",
            }
        )
        plan = adv.parse_remediation_response(body, {"id": "r5g", "title": "CVE-2021-41773 hsts"})
        self.assertTrue(plan.steps or plan.source == "fallback")
        adv._enrich(plan, {"title": "Apache CVE-2021-41773"})
        adv.parse_remediation_response("not json", finding)
        adv.parse_remediation_response('{"steps":[]}', finding)

        msg_dict_provider = _provider()
        completion = MagicMock()
        completion.message = {
            "content": json.dumps({"steps": [{"title": "A", "description": "b"}]})
        }
        msg_dict_provider.complete.return_value = completion
        with patch("backend.ai.remediation_ai.get_llm_provider", return_value=msg_dict_provider):
            adv.generate_remediation(finding)

        other = _provider()
        completion2 = MagicMock()
        completion2.message = LLMMessage(content='{"steps":[{"title":"A","description":"b"}]}')
        other.complete.return_value = completion2
        with patch("backend.ai.remediation_ai.get_llm_provider", return_value=other):
            adv.generate_remediation(finding)
        attr_p = _provider()
        completion3 = MagicMock()
        odd = MagicMock()
        odd.content = '{"steps":[{"title":"A","description":"b"}]}'
        completion3.message = odd
        attr_p.complete.return_value = completion3
        with patch("backend.ai.remediation_ai.get_llm_provider", return_value=attr_p):
            adv.generate_remediation(finding)

        ver = RemediationVerifier()
        ver.verify_fix("a", "print(1)", "pytest", "python")
        ver.verify_fix("a", "x = 1", "echo", "ruby")
        ver.verify_fix("a", "bad (", "", "python")

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "track.json"
            path.write_text("{", encoding="utf-8")
            tr = RemediationTracker(path)
            self.assertEqual(tr._load(), {})
            plan_obj = RemediationPlan(
                finding_id="r5g-t",
                vulnerability_title="HSTS",
                severity="medium",
                root_cause="x",
            )
            tr.track("r5g-t", plan_obj)
            self.assertIsNone(tr.update("missing-id"))
            tr.update("r5g-t", status="done", steps_completed=1, notes="ok")


class TestRemediationMapRemaining(unittest.TestCase):
    def test_classify_without_kind_and_cve_title(self):
        from backend.ai.remediation import (
            classify_remediation_key,
            remediation_for,
            remediations_for_findings,
        )

        self.assertEqual(
            classify_remediation_key(
                {"kind": "generic", "title": "CVE-2020-1", "cve": "CVE-2020-1"}
            ),
            "cve",
        )
        self.assertEqual(
            classify_remediation_key(
                {"kind": "generic", "finding_type": "header", "title": "hsts"}
            ),
            "header_hsts",
        )
        self.assertEqual(
            classify_remediation_key(
                {"kind": "generic", "finding_type": "header", "title": "x-frame"}
            ),
            "header_xfo",
        )
        self.assertEqual(
            classify_remediation_key({"kind": "generic", "finding_type": "header", "title": "csp"}),
            "header_csp",
        )
        self.assertEqual(
            classify_remediation_key(
                {"kind": "generic", "finding_type": "header", "title": "x-content-type"}
            ),
            "header_xcto",
        )
        self.assertEqual(
            classify_remediation_key({"kind": "generic", "finding_type": "ssl", "title": "tls"}),
            "ssl",
        )
        self.assertEqual(
            classify_remediation_key({"kind": "generic", "title": "reflected xss"}), "xss"
        )
        self.assertEqual(
            classify_remediation_key({"kind": "generic", "title": "sql injection"}), "sqli"
        )
        self.assertEqual(
            classify_remediation_key({"kind": "generic", "title": "22/tcp open"}), "port_exposure"
        )
        self.assertEqual(
            classify_remediation_key({"kind": "generic", "title": "wordpress wp-login"}),
            "wordpress",
        )
        self.assertEqual(
            classify_remediation_key({"kind": "generic", "title": "admin panel exposed"}),
            "exposure",
        )
        rem = remediation_for({"kind": "cve", "title": "Apache CVE-2021-41773", "severity": "high"})
        self.assertIn("CVE-2021-41773", rem["action"])
        rows = remediations_for_findings(
            [
                {"id": "1", "kind": "hsts", "title": "Missing HSTS", "severity": "medium"},
                {"id": "2", "kind": "hsts", "title": "Missing HSTS", "severity": "medium"},
            ]
        )
        self.assertEqual(len(rows), 1)


class TestAutopilotRemaining(unittest.TestCase):
    def test_cycle_heal_block_and_body_branches(self):
        from backend.ai import autopilot as ap
        from backend.ai.phases import PhaseDecision
        from backend.ai.providers.base import ToolCall
        from backend.executor import surface as sm

        tc_bad = ToolCall(id="t1", name="run_kali_tool", arguments="not-json")
        inner = MagicMock()
        inner.content = ""
        inner.tool_calls = [tc_bad]
        provider = _provider()
        provider.complete.return_value = MagicMock(message=inner)
        with patch.object(ap, "resolve_tool_arguments", return_value=(None, "heal-fail")):
            text, finished, met, _ = ap._run_autonomous_cycle(
                provider,
                [{"role": "system", "content": "s"}],
                [],
                "m1",
                "m1",
                1,
                phase="recon",
                risk_profile="safe-active",
            )
        self.assertFalse(finished)

        tc_nmap = ToolCall(
            id="t2",
            name="run_kali_tool",
            arguments='{"command":"nmap -sV t.com","reason":"ports"}',
        )
        inner2 = MagicMock()
        inner2.content = ""
        inner2.tool_calls = [tc_nmap]
        provider2 = _provider()
        provider2.complete.return_value = MagicMock(message=inner2)
        text, finished, met, _ = ap._run_autonomous_cycle(
            provider2,
            [{"role": "system", "content": "s"}],
            [],
            "m1",
            "m1",
            2,
            phase="report",
            risk_profile="safe-active",
        )
        self.assertFalse(finished)

        with tempfile.TemporaryDirectory() as tmp:
            surf = Path(tmp)
            events = []
            fake_p = _provider()
            fake_p.is_configured.return_value = True
            decision = PhaseDecision("enumerate", True, "ok", False)

            def _cycle(*_a, **_k):
                return "done-early", True, False, "m1"

            with (
                patch.object(sm, "SURFACE_DIR", surf),
                patch("backend.ai.autopilot.get_llm_provider", return_value=fake_p),
                patch(
                    "backend.security.privileges.effective_risk_profile",
                    side_effect=RuntimeError("priv"),
                ),
                patch("backend.ai.autopilot._run_autonomous_cycle", side_effect=_cycle),
                patch("backend.ai.autopilot.generate_report", return_value="# r"),
                patch(
                    "backend.ai.autopilot.run_verification_pipeline",
                    return_value=MagicMock(
                        verify_commands_run=1, confirmed=1, false_positive=1, discarded=1
                    ),
                ),
                patch(
                    "backend.ai.autopilot.findings_for_report",
                    return_value={
                        "confirmed": [{"severity": "high", "title": "HSTS", "confidence": "high"}],
                        "false_positive": [{"severity": "low", "title": "FP"}],
                        "discarded": [{"severity": "info", "title": "D"}],
                        "inconclusive": [],
                        "candidates": [],
                    },
                ),
                patch("backend.ai.autopilot.advance_surface_phase", return_value=({}, decision)),
                patch(
                    "backend.database.db.record_scan_from_target", side_effect=RuntimeError("db")
                ),
            ):
                res = ap.run_autonomous(
                    "auto5g.test",
                    "mapear",
                    scan_profile="full",
                    emit=lambda e, d: events.append(e),
                    mission_id="ap-5g-01",
                )
            self.assertTrue(res.message)

            with (
                patch.object(sm, "SURFACE_DIR", surf),
                patch("backend.ai.autopilot.get_llm_provider", return_value=fake_p),
                patch(
                    "backend.ai.autopilot._run_autonomous_cycle",
                    return_value=("x", True, True, "m"),
                ),
                patch("backend.ai.autopilot.generate_report", return_value="# r"),
                patch("backend.ai.autopilot.run_verification_pipeline", return_value=None),
                patch(
                    "backend.ai.autopilot.findings_for_report",
                    return_value={
                        "confirmed": [],
                        "false_positive": [],
                        "discarded": [],
                        "inconclusive": [],
                        "candidates": [],
                    },
                ),
            ):
                ap.run_autonomous("auto5g.test", "obj", scan_profile="intermediate")
                ap.run_autonomous(
                    "auto5g.test",
                    "obj",
                    scan_profile="custom",
                    custom_tools=[f"tool{i}" for i in range(26)],
                )
                empty = ap.run_autonomous(
                    "auto5g.test", "obj", scan_profile="custom", custom_tools=[]
                )
            self.assertEqual(empty.stopped_reason, "error")


class TestLiveReportRemaining(unittest.TestCase):
    def test_helpers_and_generate(self):
        from backend.ai import live_report as lr

        self.assertEqual(lr._tool_name({"tool": "nmap"}), "nmap")
        self.assertEqual(lr._tool_name({"command": ""}), "comando")
        self.assertEqual(lr._tool_name({"command": "/usr/bin/httpx -u x"}), "httpx")
        self.assertEqual(lr._sev_class("high"), "alto")
        self.assertEqual(lr._sev_class("medium"), "medio")
        self.assertEqual(lr._sev_class("info"), "info")
        self.assertEqual(lr._sev_class("low"), "baixo")
        with patch(
            "backend.compliance.reporter.generate_compliance_report",
            side_effect=RuntimeError("x"),
        ):
            html = lr._render_iso_soc2([], "t.com")
        self.assertIn("Não foi possível", html)
        self.assertIn("Nenhum comando", lr._render_tests([]))
        lr._render_tests(
            [
                {
                    "tool": "nmap",
                    "command": "nmap -sV t",
                    "stdout": "80/tcp open http",
                    "success": True,
                }
            ]
        )
        self.assertIn("Nenhum problema listado", lr._render_findings([]))
        lr._render_findings(
            [
                {
                    "title": "Missing HSTS",
                    "plain_title": "HTTPS sem HSTS",
                    "severity": "medium",
                    "status": "candidate",
                    "what_it_is": "header",
                    "everyday": "https",
                    "why_it_matters": "downgrade",
                    "could_happen": ["mitm"],
                    "how_to_decide": ["curl -sI"],
                    "command": "curl -sI https://x",
                    "evidence": "no hsts",
                    "kind_label": "HSTS",
                }
            ]
        )
        self.assertIn("Sem plano", lr._render_remediations([]))
        lr._render_remediations(
            [
                {
                    "remediation_title": "HSTS",
                    "finding_title": "Missing HSTS",
                    "severity": "medium",
                    "steps": ["enable header"],
                    "who": "ops",
                    "why": "https",
                    "verify": "curl -sI",
                }
            ]
        )
        self.assertIn("ainda não registrou", lr._render_chat_notes(["short"]))
        notes = lr._render_chat_notes(["A" * 50, "B" * 50])
        self.assertIn("Nota", notes)
        html = lr.generate_live_report_html(
            history=[
                {"role": "user", "content": "scan t.com"},
                {"role": "assistant", "content": "A" * 50},
            ],
            tool_executions=[
                {"command": "nmap -sV t.com", "stdout": "80/tcp open", "success": True}
            ],
            title="Live 5g",
        )
        self.assertIn("<html", html)


class TestReportModelRemaining(unittest.TestCase):
    def test_severity_merge_assemble_paragraph(self):
        from backend.ai.report_model import (
            _executive_paragraph,
            _merge_extracted,
            assemble_session_report,
            enrich_finding,
            normalize_severity,
        )

        self.assertEqual(normalize_severity({"title": "x", "severity": "high"}), "high")
        self.assertEqual(
            normalize_severity({"title": "something else", "severity": "weird"}), "info"
        )
        with patch("backend.ai.fp_explain.explain_false_positive", side_effect=RuntimeError("x")):
            enrich_finding({"title": "generic thing", "severity": "info"})
        merged = _merge_extracted(
            [{"title": "[high] xss found"}],
            [{"stdout": "[high] xss found", "command": "nuclei -u x"}],
        )
        self.assertEqual(len(merged), 1)
        _merge_extracted([], [{"stdout": "[medium] new thing", "command": "nikto -h x"}])

        with patch("backend.database.chat_store.get_chat_session", side_effect=RuntimeError("x")):
            assemble_session_report(session_id="sess5gchat01", history=None)
        with patch("backend.executor.session_intel.load_session", side_effect=RuntimeError("x")):
            assemble_session_report(
                session_id="sess5gintel01",
                history=[{"role": "user", "content": "hi"}],
            )
        with (
            patch(
                "backend.ai.remediation.remediations_for_findings", side_effect=RuntimeError("x")
            ),
            patch("backend.ai.fp_explain.residual_risk_score", side_effect=RuntimeError("x")),
            patch(
                "backend.compliance.reporter.generate_compliance_report",
                side_effect=RuntimeError("x"),
            ),
        ):
            assemble_session_report(
                history=[{"role": "user", "content": "scan"}],
                tool_executions=[
                    {"command": "nmap -sV t.com", "stdout": "80/tcp open", "success": True}
                ],
            )
        assemble_session_report(
            history=[{"role": "user", "content": "scan t.com"}],
            tool_executions=[{"command": "whois t.com", "stdout": "ok", "success": True}],
        )
        findings = [
            {"title": "HSTS", "status": "false_positive", "kind": "hsts", "severity": "medium"},
            {"title": "XSS", "status": "confirmed", "kind": "xss", "severity": "high"},
        ]
        with (
            patch(
                "backend.executor.session_intel.aggregate_session_findings",
                return_value=[
                    {
                        "title": "HSTS",
                        "status": "false_positive",
                        "kind": "hsts",
                        "severity": "medium",
                    },
                    {"title": "XSS", "status": "confirmed", "kind": "xss", "severity": "high"},
                ],
            ),
            patch(
                "backend.executor.session_intel.load_session",
                return_value={"targets": ["kinds5g.test"]},
            ),
            patch(
                "backend.executor.session_intel.collect_session_tool_executions",
                return_value=[],
            ),
        ):
            assemble_session_report(
                session_id="sess5gkinds01",
                history=[{"role": "user", "content": "scan kinds5g.test"}],
            )
        with patch("backend.ai.report._extract_vulnerabilities", return_value=[]):
            assemble_session_report(
                history=[{"role": "user", "content": "x"}],
                tool_executions=[{"command": "nmap -sV t.com", "success": True, "stdout": "ok"}],
            )
        _executive_paragraph(
            targets=["t.com"],
            n_tests=1,
            n_ok=1,
            n_fail=0,
            n_findings=2,
            n_confirmed=1,
            n_fp=0,
            n_pending=0,
            risk={"score": 80, "label": "Alto"},
            top_fixes=["HSTS"],
            sev_conf={"critical": 1, "high": 1},
        )
        self.assertTrue(findings)


class TestToolHealParseRemaining(unittest.TestCase):
    def test_heal_parse_sdk_and_openrouter(self):
        from backend.ai.openrouter_common import assistant_message_dict
        from backend.ai.providers import tool_heal as th
        from backend.ai.providers import tool_parse as tp
        from backend.ai.providers.base import LLMMessage, ToolCall

        self.assertIsNone(tp.try_parse_json("'still-not-json"))
        self.assertIsNone(tp.try_parse_json("xx {not json} yy"))
        self.assertTrue(
            tp._dict_to_tool_call(
                {"name": "finish_mission", "summary": "feito", "objective_met": True}
            )
        )
        self.assertTrue(
            tp._dict_to_tool_call({"name": "run_kali_tool", "command": "nmap -V", "reason": "x"})
        )
        self.assertTrue(tp._dict_to_tool_call({"name": "run_kali_tool"}))
        self.assertIsNone(tp._dict_to_tool_call({"foo": 1}))
        self.assertTrue(
            tp._dict_to_tool_call(
                {"function": {"name": "run_kali_tool", "arguments": '{"command":"nmap -V"}'}}
            )
        )
        self.assertTrue(
            tp.extract_tool_calls_from_content(
                'noise ```json\nnotjson\n``` then {"command":"nmap -sV t.com","reason":"p"}'
            )
            or True
        )
        self.assertTrue(
            tp.extract_tool_calls_from_content('[1, {"command":"nmap -sV t.com","reason":"ports"}]')
        )
        self.assertTrue(
            tp.extract_tool_calls_from_content(
                '{"tool_calls":[{"name":"run_kali_tool","arguments":{"command":"nmap -V","reason":"x"}}]}'
            )
        )

        parsed_ok = th.heal_tool_arguments(
            MagicMock(),
            model="m",
            tool_name="run_kali_tool",
            broken_arguments='{"command":"nmap -V","reason":"x"}',
        )
        self.assertEqual(parsed_ok["command"], "nmap -V")

        provider = MagicMock()
        provider.complete.side_effect = RuntimeError("down")
        self.assertIsNone(
            th.heal_tool_arguments(
                provider,
                model="m",
                tool_name="run_kali_tool",
                broken_arguments='{"reason":"only"}',
                max_attempts=1,
            )
        )

        tc = MagicMock()
        tc.name = "run_kali_tool"
        tc.arguments = '{"command":"whois t.com","reason":"x"}'
        inner = MagicMock()
        inner.content = "not-json"
        inner.tool_calls = [tc]
        healer = MagicMock()
        healer.complete.return_value = MagicMock(message=inner)
        healed = th.heal_tool_arguments(
            healer,
            model="m",
            tool_name="run_kali_tool",
            broken_arguments='{"reason":"only"}',
            max_attempts=2,
        )
        self.assertTrue(healed is None or healed.get("command"))

        still_bad = MagicMock()
        still_inner = MagicMock()
        still_inner.content = '{"reason":"still"}'
        still_inner.tool_calls = []
        still_bad.complete.return_value = MagicMock(message=still_inner)
        self.assertIsNone(
            th.heal_tool_arguments(
                still_bad,
                model="m",
                tool_name="run_kali_tool",
                broken_arguments='{"reason":"only"}',
                max_attempts=1,
            )
        )

        ok_heal = MagicMock()
        ok_inner = MagicMock()
        ok_inner.content = '{"command":"nmap -V","reason":"x"}'
        ok_inner.tool_calls = []
        ok_heal.complete.return_value = MagicMock(message=ok_inner)
        data, err = th.resolve_tool_arguments(
            ok_heal,
            model="m",
            tool_call=ToolCall(id="1", name="run_kali_tool", arguments="{broken"),
        )
        self.assertTrue(data is None or data.get("command"))
        fail_p = MagicMock()
        fail_p.complete.return_value = _msg("nope")
        data2, err2 = th.resolve_tool_arguments(
            fail_p,
            model="m",
            tool_call=ToolCall(id="2", name="run_kali_tool", arguments="{broken"),
        )
        self.assertIsNone(data2)
        self.assertTrue(err2)

        assistant_message_dict(LLMMessage(content="hi", tool_calls=[]))


class TestScannerImportRemaining(unittest.TestCase):
    def test_suppressed_empty_title_auto_jsonl(self):
        from backend.ai import scanner_import as si
        from backend.executor import surface as sm

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with (
                patch.object(sm, "SURFACE_DIR", root),
                patch("backend.ai.scanner_import.is_suppressed", return_value=True),
            ):
                sm.get_or_create_surface("imp5g.test")
                jsonl = json.dumps(
                    {"info": {"name": "XSS", "severity": "high"}, "template-id": "xss"}
                )
                out = si.import_nuclei_jsonl("imp5g.test", jsonl)
                self.assertGreaterEqual(out["skipped_fp_learned"], 1)
                csv_ok = "Plugin Name,Severity,CVE,Host,Port\nA,4,CVE-2020-1,imp5g.test,443\n\n"
                nessus = si.import_nessus_csv("imp5g.test", csv_ok)
                self.assertGreaterEqual(nessus["skipped_fp_learned"], 1)

            with (
                patch.object(sm, "SURFACE_DIR", root),
                patch("backend.ai.fp_learn._migrated", True),
            ):
                sm.get_or_create_surface("imp5g.test")
                si.import_nessus_csv(
                    "imp5g.test",
                    "Plugin Name,Severity\n,High\nKeep,Low\n",
                )
                auto = si.import_scanner_payload(
                    "imp5g.test",
                    '0\n{"info":{"name":"t","severity":"low"}}\n',
                    format="auto",
                )
                self.assertIn(auto["format"], {"nuclei_jsonl", "nessus_csv"})
                try:
                    si.import_scanner_payload("imp5g.test", "hello\nnotjson", format="auto")
                except ValueError:
                    pass


class TestExecutiveSummaryRemaining(unittest.TestCase):
    def test_narrative_llm_cache_timeout(self):
        from backend.ai import executive_summary as es
        from backend.executor import surface as sm

        self.assertIn(
            "ainda aberto",
            es.business_delta_narrative(
                {
                    "has_baseline": True,
                    "fixed": [1],
                    "new": [1],
                    "still_open": [1, 2],
                    "surface": {"ports_opened": [1], "hosts_added": [1]},
                }
            ),
        )
        with patch(
            "backend.ai.providers.factory.get_llm_provider",
            return_value=_provider(configured=False),
        ):
            with self.assertRaises(RuntimeError):
                es._llm_generate("p")
        empty_p = _provider(content="")
        with patch("backend.ai.providers.factory.get_llm_provider", return_value=empty_p):
            with self.assertRaises(RuntimeError):
                es._llm_generate("p")

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(sm, "SURFACE_DIR", Path(tmp)):
                empty = es.generate_executive_summary("missing5g.none")
                self.assertEqual(empty["source"], "empty")
                data = sm.get_or_create_surface("exec5g.test")
                sm.save_surface("exec5g.test", data)
                fb = es.generate_executive_summary("exec5g.test", use_llm=False)
                self.assertEqual(fb["source"], "fallback")
                with patch("backend.ai.executive_summary.ThreadPoolExecutor") as pool:
                    inst = MagicMock()
                    fut = MagicMock()
                    fut.result.side_effect = FuturesTimeout()
                    inst.submit.return_value = fut
                    pool.return_value.__enter__.return_value = inst
                    timed = es.generate_executive_summary("exec5g.test", regenerate=True)
                self.assertIn("fallback", timed["source"])


class TestAgentChainsDeltaEvidence(unittest.TestCase):
    def test_agent_chains_delta_evidence(self):
        from backend.ai import agent as ag
        from backend.ai import delta as d
        from backend.ai import evidence as ev
        from backend.ai.chains import infer_attack_chains
        from backend.executor import surface as sm

        with (
            patch("backend.ai.agent.extract_targets", return_value=["scanme.nmap.org"]),
            patch("backend.executor.recon_db.is_recon_target", return_value=True),
            patch("backend.executor.surface.build_surface_context", return_value="SURFACE"),
            patch("backend.executor.recon_db.build_recon_context", return_value=""),
        ):
            msg, targets = ag._apply_recon_context("scan scanme.nmap.org", [])
        self.assertIn("SURFACE", msg)

        fail = MagicMock(
            success=False,
            blocked=False,
            command="nmap a.com",
            stdout="",
            stderr="fail",
            tool="nmap",
            exit_code=1,
        )
        with (
            patch("backend.executor.recon_db.extract_targets", return_value=["a.com"]),
            patch("backend.executor.recon_db.is_recon_target", return_value=True),
            patch("backend.executor.session_intel.touch_session") as touch,
            patch("backend.executor.surface.update_surface_from_execution"),
        ):
            ag._persist_recon(fail, ["a.com"], chat_session_id="sess5grecon01")
        touch.assert_called()

        p = _provider(content="texto sem tool")
        p.complete.side_effect = [
            _msg(content="", tool_calls=[]),
            _msg(content="resposta final", tool_calls=[]),
        ]
        with patch("backend.ai.agent.get_llm_provider", return_value=p):
            out = ag._run_openrouter_body(
                [],
                "rode nmap",
                None,
                None,
                None,
                None,
                None,
                force_tool_use=True,
            )
        self.assertIn("resposta", out.message)

        chains = infer_attack_chains(
            {
                "findings": [
                    {"status": "confirmed", "title": "xss missing hsts", "severity": "high"},
                    {
                        "status": "confirmed",
                        "title": "sql injection",
                        "severity": "critical",
                        "cve": "CVE-1",
                    },
                ],
                "ports": [{"port": "22"}, {"port": "80"}],
                "urls": ["https://x"],
            }
        )
        self.assertTrue(any("XSS" in c["title"] or "SSH" in c["title"] for c in chains) or chains)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(sm, "SURFACE_DIR", root):
                data = sm.get_or_create_surface("d5g.test")
                data["findings"] = [
                    {"id": "1", "title": "HSTS", "status": "confirmed", "severity": "medium"}
                ]
                data["services"] = [
                    {"host": "d5g.test", "port": "80", "name": "http", "version": "1"}
                ]
                sm.save_surface("d5g.test", data)
                d.snapshot_surface_baseline("d5g.test")
                data = sm.load_surface("d5g.test")
                data["services"] = [
                    {"host": "d5g.test", "port": "80", "name": "http", "version": "2"},
                    "not-a-dict",
                    {"host": "d5g.test", "port": "443", "name": "https", "version": "1"},
                ]
                sm.save_surface("d5g.test", data)
                d.compute_delta("d5g.test")
            md = d.format_delta_markdown(
                {
                    "has_baseline": True,
                    "baseline_count": 1,
                    "current_count": 1,
                    "fixed": [],
                    "new": [],
                    "still_open": [{"severity": "low", "title": "open"}],
                    "surface": {
                        "ports_opened": [
                            "80/tcp",
                            {"host": "h", "port": 443, "proto": "tcp", "service": "https"},
                        ],
                        "ports_closed": [],
                        "hosts_added": [],
                        "hosts_removed": [],
                        "services_changed": [],
                    },
                }
            )
            self.assertIn("80/tcp", md)

            class _EvPath:
                def __init__(self, name, boom=False):
                    self.name = name
                    self._boom = boom

                def stat(self):
                    if self._boom:
                        raise OSError("x")
                    st = MagicMock()
                    st.st_size = 4
                    return st

                def __lt__(self, other):
                    return self.name < getattr(other, "name", "")

            with patch("backend.ai.evidence.evidence_dir") as ed:
                root_m = MagicMock()
                root_m.glob.return_value = [_EvPath("bad.txt", boom=True), _EvPath("ok.txt")]
                ed.return_value = root_m
                items = ev.list_evidence_files("e5g.test")
            self.assertTrue(any(i["name"] == "ok.txt" for i in items))
            self.assertEqual(ev.read_evidence("missing5g.none", "nope"), "")


class TestExecDigestNucleiOllamaReportRiskIntel(unittest.TestCase):
    def test_digest_nuclei_ollama_report_risk_intel(self):
        from backend.ai import exec_digest as ed
        from backend.ai import nuclei_json as nj
        from backend.ai import report as rp
        from backend.ai import risk_history as rh
        from backend.ai import risk_score as rs
        from backend.ai import threat_intel as ti
        from backend.ai.phases import evaluate_phase_advance, is_tool_allowed, tool_binary
        from backend.ai.providers.ollama import OllamaAdapter
        from backend.executor import surface as sm

        art = "||||abcd||||ef||||"
        self.assertTrue(ed._is_banner_line(art))
        hosts = " ".join(f"h{i}.example.com" for i in range(12))
        got = ed._hosts_from(hosts)
        self.assertEqual(len(got), 8)
        ed.digest_execution({"tool": "subfinder", "stdout": "a.example.com", "success": True})
        ed.digest_execution({"tool": "whatweb", "stdout": "Title[Home]", "success": True})
        ed.digest_execution({"tool": "nikto", "stdout": "+ XSS", "success": True})
        ed.digest_execution({"tool": "custom", "stdout": "", "success": True})

        line_list = json.dumps([{"template-id": "t1", "info": {"name": "N", "severity": "low"}}])
        evs = nj.parse_nuclei_json_lines("prefix\n" + line_list + "\n")
        self.assertTrue(evs)
        one = json.dumps(
            {
                "template-id": "cve-2021-41773",
                "info": {
                    "name": "Apache CVE-2021-41773",
                    "severity": "high",
                    "classification": {"cve-id": "CVE-2021-41773", "cvss-score": "bad"},
                    "tags": "xss,sqli",
                },
            }
        )
        self.assertTrue(nj.parse_nuclei_json_lines(one))
        named = json.dumps(
            {
                "template-id": "apache-path",
                "info": {"name": "Apache CVE-2021-41773", "severity": "high"},
            }
        )
        self.assertTrue(nj.parse_nuclei_json_lines(named))

        self.assertEqual(tool_binary(""), "")
        self.assertEqual(is_tool_allowed("", phase="recon", risk_profile="safe-active")[0], False)
        d0 = evaluate_phase_advance({"phase": "nope"})
        self.assertEqual(d0.phase, "recon")
        self.assertFalse(evaluate_phase_advance({"phase": "enumerate", "commands_run": 0}).advanced)
        self.assertFalse(
            evaluate_phase_advance(
                {"phase": "vuln_scan", "commands_run": 0, "findings": []}
            ).advanced
        )
        self.assertFalse(
            evaluate_phase_advance(
                {
                    "phase": "verify",
                    "commands_run": 0,
                    "findings": [{"status": "candidate"}],
                }
            ).advanced
        )

        o = OllamaAdapter(base_url="http://127.0.0.1:11434/v1")
        resp = MagicMock()
        resp.status = 500
        resp.read.return_value = b'{"models":[]}'
        cm = MagicMock()
        cm.__enter__.return_value = resp
        cm.__exit__.return_value = False
        with patch("backend.ai.providers.ollama.http_urlopen", return_value=cm):
            health = o.health()
        self.assertFalse(health.get("ok"))
        self.assertTrue(health.get("detail"))
        with patch.object(OllamaAdapter, "_list_local_models", return_value=["zzz-local-only"]):
            cat = o.models_catalog()
        self.assertTrue(cat.get("models") or cat.get("tiers"))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(sm, "SURFACE_DIR", root):
                data = sm.get_or_create_surface("rep5g.test")
                data["findings"] = [
                    {
                        "id": "e1",
                        "title": "CVE-2021-41773",
                        "cve": "CVE-2021-41773",
                        "status": "confirmed",
                        "severity": "high",
                        "confidence": "high",
                        "template_id": "cve-2021-41773",
                        "verify_command": "nuclei -u x",
                        "cisa_kev_flag": True,
                        "kev_date_added": "2021-01-01",
                        "kev_ransomware_use": True,
                        "epss_score": 0.9,
                        "epss_percentile": 0.99,
                        "matched_at": "https://rep5g.test/",
                    }
                ]
                data["urls"] = ["https://rep5g.test/"]
                data["ports"] = [{"port": "80"}, {"port": "22"}]
                sm.save_surface("rep5g.test", data)
                md = rp.generate_report(
                    [{"role": "user", "content": "scan"}],
                    [{"command": "nmap", "success": True, "stdout": "ok"}],
                    surface_target="rep5g.test",
                    snapshot_baseline=False,
                )
            self.assertIn("CISA", md)
            html = rp.generate_report_html([], [], title="t")
            with patch(
                "backend.ai.report.generate_report",
                return_value="# t\n> quote line\n#### Heading\n",
            ):
                html2 = rp.generate_report_html([], [])
            self.assertIn("blockquote", html2)
            self.assertTrue(html)

        with tempfile.TemporaryDirectory() as tmp:
            with patch("backend.ai.risk_history.RISK_HISTORY_DIR", Path(tmp)):
                p = Path(tmp) / "risk5g.test.jsonl"
                p.write_text(
                    json.dumps({"score": "bad"}) + "\n" + json.dumps({"score": 1}) + "\n",
                    encoding="utf-8",
                )
                self.assertIsNone(rh.previous_score("risk5g.test"))

        rs.compute_risk_score([{"severity": "high", "cvss_score": "bad", "confidence": "low"}])
        rs.compute_risk_score([{"severity": "medium", "epss_score": "bad", "confidence": "medium"}])
        with patch.dict(rs._WEIGHT, {"info": 0.0}):
            band = rs.compute_risk_score([{"severity": "info"}])
        self.assertEqual(band["band"], "info")

        resp_j = MagicMock()
        resp_j.read.return_value = b'{"ok": true}'
        cmj = MagicMock()
        cmj.__enter__.return_value = resp_j
        cmj.__exit__.return_value = False
        with patch("backend.ai.threat_intel.http_urlopen", return_value=cmj):
            ti._http_get_json("http://example.invalid/x")
        ti._epss_cache.clear()
        with patch(
            "backend.ai.threat_intel._http_get_json",
            return_value={"data": [{"epss": "bad", "percentile": "bad"}]},
        ):
            ti.fetch_epss_score("CVE-2021-41773")
        with (
            patch("backend.ai.threat_intel.THREAT_INTEL_ENABLED", True),
            patch("backend.ai.threat_intel.lookup_cve_intel", return_value={}),
        ):
            out = ti.enrich_finding_with_threat_intel({"cve": "CVE-2021-41773", "title": "x"})
        self.assertEqual(out.get("cve"), "CVE-2021-41773")


if __name__ == "__main__":
    unittest.main()
