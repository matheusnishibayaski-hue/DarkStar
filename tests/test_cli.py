"""Testes do DarkStar CLI e helpers de relatório."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from backend.cli import cli
from backend.cli_report import (
    EXIT_CRITICAL,
    EXIT_HIGH,
    EXIT_OK,
    build_cli_report,
    convert_to_sarif,
    determine_exit_code,
    flatten_report_findings,
    save_cli_output,
)
from click.testing import CliRunner


class TestCliReportHelpers(unittest.TestCase):
    def test_exit_codes(self):
        self.assertEqual(determine_exit_code(critical=0, high=0), EXIT_OK)
        self.assertEqual(determine_exit_code(critical=0, high=2), EXIT_HIGH)
        self.assertEqual(determine_exit_code(critical=1, high=9), EXIT_CRITICAL)

    def test_flatten_and_sarif(self):
        buckets = {
            "confirmed": [
                {
                    "id": "1",
                    "title": "Missing HSTS",
                    "severity": "medium",
                    "host": "example.com",
                    "status": "confirmed",
                }
            ],
            "false_positive": [],
            "discarded": [],
            "inconclusive": [],
            "candidates": [
                {
                    "id": "2",
                    "title": "CVE-2020-1234",
                    "severity": "critical",
                    "cve": "CVE-2020-1234",
                    "url": "https://example.com",
                    "status": "candidate",
                }
            ],
        }
        findings = flatten_report_findings(buckets)
        self.assertEqual(len(findings), 2)
        self.assertTrue(any(f.get("remediation") for f in findings))

        report = {
            "target": "example.com",
            "version": "2.0.0",
            "findings": findings,
        }
        sarif = convert_to_sarif(report)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), 2)

    def test_save_output(self):
        report = {
            "target": "t",
            "findings": [],
            "critical": 0,
            "high": 0,
            "version": "2.0.0",
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out" / "report.json"
            save_cli_output(report, str(path), "json")
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["target"], "t")
            sarif_path = Path(tmp) / "out" / "report.sarif"
            save_cli_output(report, str(sarif_path), "sarif")
            sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
            self.assertIn("runs", sarif)

    def test_build_cli_report_mocked(self):
        buckets = {
            "confirmed": [{"id": "a", "title": "X", "severity": "high", "status": "confirmed"}],
            "false_positive": [],
            "discarded": [],
            "inconclusive": [],
            "candidates": [],
        }
        with (
            patch("backend.cli_report.findings_for_report", return_value=buckets),
            patch(
                "backend.cli_report.risk_score_for_target",
                return_value={"score": 40, "band": "medium"},
            ),
        ):
            report = build_cli_report("lab.test", risk_profile="safe-active", rounds=2)
            self.assertEqual(report["high"], 1)
            self.assertEqual(report["exit_code"], EXIT_HIGH)
            self.assertEqual(report["target"], "lab.test")


class TestCliCommands(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()

    def test_help(self):
        result = self.runner.invoke(cli, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("DarkStar CLI", result.output)

    def test_autonomous_dry_run(self):
        with patch("backend.cli.validate_autonomous_target", return_value=(True, "")):
            result = self.runner.invoke(
                cli,
                ["autonomous", "--target", "scanme.nmap.org", "--dry-run", "--quiet"],
            )
            self.assertEqual(result.exit_code, 0)

    def test_autonomous_scope_fail(self):
        with patch(
            "backend.cli.validate_autonomous_target",
            return_value=(False, "fora do escopo"),
        ):
            result = self.runner.invoke(
                cli,
                ["autonomous", "--target", "evil.example", "--dry-run", "--quiet"],
            )
            self.assertEqual(result.exit_code, 102)

    def test_autonomous_mocked_run(self):
        mock_result = MagicMock()
        mock_result.rounds = 1
        mock_result.tools_executed = 0
        mock_result.stopped_reason = "completed"
        mock_result.objective_met = True
        mock_result.report = "# ok"
        mock_result.message = "done"
        buckets = {
            "confirmed": [],
            "false_positive": [],
            "discarded": [],
            "inconclusive": [],
            "candidates": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            out = str(Path(tmp) / "r.json")
            with (
                patch("backend.cli.validate_autonomous_target", return_value=(True, "")),
                patch("backend.ai.autopilot.run_autonomous", return_value=mock_result),
                patch("backend.cli_report.findings_for_report", return_value=buckets),
                patch(
                    "backend.cli_report.risk_score_for_target",
                    return_value={"score": 0, "band": "low"},
                ),
            ):
                result = self.runner.invoke(
                    cli,
                    [
                        "autonomous",
                        "--target",
                        "scanme.nmap.org",
                        "--quiet",
                        "-o",
                        out,
                    ],
                )
                self.assertEqual(result.exit_code, 0)
                self.assertTrue(Path(out).is_file())

    def test_health_config(self):
        result = self.runner.invoke(cli, ["health", "--check", "config", "--output", "json"])
        self.assertEqual(result.exit_code, 0)
        data = json.loads(result.output)
        self.assertEqual(data["config"]["status"], "ok")

    def test_list_tools(self):
        result = self.runner.invoke(cli, ["list-tools", "--pattern", "nmap", "--output", "json"])
        self.assertEqual(result.exit_code, 0)
        data = json.loads(result.output)
        self.assertTrue(any(t["name"] == "nmap" for t in data))


if __name__ == "__main__":
    unittest.main()
