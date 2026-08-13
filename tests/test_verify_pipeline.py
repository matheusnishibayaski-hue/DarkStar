"""Pipeline de verificação assertiva (PoC → confirmed/FP/discarded)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.ai.verify import (
    build_verify_command,
    classify_finding_type,
    run_verification_pipeline,
    score_verification,
)
from backend.executor import surface as surface_mod
from backend.executor.result import ExecutionResult
from backend.executor.surface import get_or_create_surface, save_surface


def _exec_result(
    stdout: str = "",
    *,
    success: bool = True,
    exit_code: int = 0,
    blocked: bool = False,
    stderr: str = "",
) -> ExecutionResult:
    return ExecutionResult(
        command="verify",
        reason="poc",
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        success=success,
        blocked=blocked,
        tool="curl",
    )


class TestClassifyAndCommands(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(classify_finding_type({"title": "CVE-2024-1234 foo"}), "cve")
        self.assertEqual(classify_finding_type({"title": "Missing HSTS header"}), "header")
        self.assertEqual(
            classify_finding_type({"title": "80/tcp open http", "tool": "nmap"}),
            "port_info",
        )

    def test_build_header_cmd(self):
        cmd = build_verify_command(
            {"title": "Missing Strict-Transport-Security", "severity": "medium"},
            "lab.test",
            urls=["https://lab.test"],
        )
        self.assertIn("curl", cmd)
        self.assertIn("lab.test", cmd)


class TestScoreVerification(unittest.TestCase):
    def test_header_missing_confirmed(self):
        finding = {"title": "Missing HSTS header", "severity": "medium"}
        status, conf, _ = score_verification(
            finding,
            _exec_result("HTTP/1.1 200 OK\nServer: nginx\n\n"),
        )
        self.assertEqual(status, "confirmed")
        self.assertEqual(conf, "high")

    def test_header_present_fp(self):
        finding = {"title": "Missing HSTS header", "severity": "medium"}
        status, conf, _ = score_verification(
            finding,
            _exec_result("HTTP/1.1 200 OK\nStrict-Transport-Security: max-age=31536000\n\n"),
        )
        self.assertEqual(status, "false_positive")

    def test_repro_confirmed(self):
        finding = {"title": "[high] exposed admin panel", "severity": "high"}
        status, _, _ = score_verification(
            finding,
            _exec_result("[high] exposed admin panel at /admin\nvulnerable\n"),
        )
        self.assertEqual(status, "confirmed")

    def test_pass2_closes_ambiguous(self):
        finding = {"title": "something obscure xyz", "severity": "medium"}
        status, _, reason = score_verification(
            finding,
            _exec_result("ok", success=True),
            pass_number=2,
        )
        self.assertIn(status, {"false_positive", "discarded"})
        self.assertTrue(reason)


class TestPipeline(unittest.TestCase):
    def test_pipeline_closes_all(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(surface_mod, "SURFACE_DIR", root):
                data = get_or_create_surface("lab.test", objective="x")
                data["urls"] = ["https://lab.test"]
                data["findings"] = [
                    {
                        "id": "f1",
                        "title": "Missing HSTS header",
                        "severity": "medium",
                        "status": "candidate",
                        "tool": "nuclei",
                        "evidence": "x",
                    },
                    {
                        "id": "f2",
                        "title": "[high] exposed panel",
                        "severity": "high",
                        "status": "candidate",
                        "tool": "nuclei",
                        "evidence": "y",
                    },
                ]
                save_surface("lab.test", data)

                calls: list[str] = []

                def fake_exec(command: str, reason: str) -> ExecutionResult:
                    calls.append(command)
                    if "curl" in command and "HSTS" not in reason:
                        # first finding header check — no HSTS
                        if "Missing" in reason or "HSTS" in reason.lower() or True:
                            if "curl" in command:
                                return _exec_result("HTTP/1.1 200\nServer: x\n")
                    if "nuclei" in command or "exposed" in reason.lower():
                        return _exec_result("[high] exposed panel\nvulnerable confirmed\n")
                    return _exec_result("HTTP/1.1 200\nServer: x\n")

                # Simpler deterministic fake:
                def fake_exec2(command: str, reason: str) -> ExecutionResult:
                    calls.append(command)
                    if "Missing HSTS" in reason or ("curl" in command and "hsts" in reason.lower()):
                        return _exec_result("HTTP/1.1 200 OK\nContent-Type: text/html\n")
                    if "exposed" in reason.lower():
                        return _exec_result("[high] exposed panel\nvulnerable\n")
                    # default by command type
                    if command.startswith("curl"):
                        return _exec_result("HTTP/1.1 200 OK\nContent-Type: text/html\n")
                    return _exec_result("[high] exposed panel\nvulnerable\n", success=True)

                result = run_verification_pipeline("lab.test", execute=fake_exec2, max_findings=10)
                self.assertGreaterEqual(result.verify_commands_run, 1)

                final = surface_mod.load_surface("lab.test")
                statuses = {f["id"]: f["status"] for f in final["findings"]}
                # Nenhum candidate/inconclusive residual
                self.assertTrue(
                    all(
                        s in {"confirmed", "false_positive", "discarded"} for s in statuses.values()
                    )
                )
                self.assertEqual(statuses["f1"], "confirmed")  # missing HSTS
                self.assertEqual(statuses["f2"], "confirmed")


class TestReportSections(unittest.TestCase):
    def test_report_lists_fp_and_discarded(self):
        from backend.ai.report import generate_report

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(surface_mod, "SURFACE_DIR", root):
                data = get_or_create_surface("rep.test")
                data["findings"] = [
                    {
                        "id": "a",
                        "title": "Real issue",
                        "severity": "high",
                        "status": "confirmed",
                        "confidence": "high",
                        "template_id": "real-issue",
                        "verify_command": "curl -sI https://rep.test",
                        "tool": "nuclei",
                    },
                    {
                        "id": "b",
                        "title": "Noise",
                        "severity": "info",
                        "status": "false_positive",
                        "evidence": "header present",
                        "tool": "nuclei",
                    },
                    {
                        "id": "c",
                        "title": "Ambiguous",
                        "severity": "medium",
                        "status": "discarded",
                        "discard_reason": "não reproduzível",
                        "tool": "nikto",
                    },
                ]
                save_surface("rep.test", data)
                md = generate_report([], [], surface_target="rep.test", snapshot_baseline=False)
                self.assertIn("Confirmados", md)
                self.assertIn("Falsos positivos", md)
                self.assertIn("Descartados", md)
                self.assertIn("Real issue", md)
                self.assertIn("Noise", md)
                self.assertIn("Ambiguous", md)
                # Gate rígido: high confidence + verify → executivo
                self.assertIn("Resumo Executivo", md)


if __name__ == "__main__":
    unittest.main()
