"""Sanitizar stdout de tools e segunda opinião LLM (parse)."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch


class TestExecDigest(unittest.TestCase):
    def test_strip_ansi_and_leftover_sgr(self):
        from backend.ai.exec_digest import strip_ansi

        raw = "\x1b[34mINF\x1b[0m hello [91moutdated[0m [1mbold"
        clean = strip_ansi(raw)
        self.assertNotIn("\x1b", clean)
        self.assertNotIn("[34m", clean)
        self.assertNotIn("[0m", clean)
        self.assertIn("hello", clean)
        self.assertIn("outdated", clean)

    def test_nmap_open_ports(self):
        from backend.ai.exec_digest import digest_execution

        d = digest_execution(
            {
                "tool": "nmap",
                "command": "nmap -sV lincoln.korbil.cloud",
                "success": True,
                "stdout": "Host is up.\n80/tcp open http\n443/tcp open ssl/http\n",
            }
        )
        self.assertEqual(d["status"], "ok")
        self.assertIn("2 porta", d["headline"])
        self.assertTrue(any("80/tcp" in b for b in d["bullets"]))

    def test_gobuster_missing_wordlist(self):
        from backend.ai.exec_digest import digest_execution

        d = digest_execution(
            {
                "tool": "gobuster",
                "command": "gobuster dir -u https://x/ -w /usr/share/seclists/foo.txt",
                "success": False,
                "stderr": "Error: wordlist file /usr/share/seclists/foo.txt does not exist",
            }
        )
        self.assertEqual(d["status"], "fail")
        self.assertIn("wordlist", d["failure"].lower())
        self.assertIn("Não rodou", d["headline"])

    def test_nuclei_unresponsive(self):
        from backend.ai.exec_digest import digest_execution, clean_tool_output

        banner = "  __  _  __\n / / / |/ /\nprojectdiscovery.io\n"
        stdout = (
            banner
            + "Skipped lincoln.korbil.cloud:443 from target list as found unresponsive 30 times\n"
        )
        cleaned = clean_tool_output(stdout)
        self.assertNotIn("projectdiscovery.io", cleaned.lower())
        d = digest_execution(
            {"tool": "nuclei", "command": "nuclei -u https://x", "success": True, "stdout": stdout}
        )
        blob = (d["headline"] + " " + d["failure"]).lower()
        self.assertIn("sem resposta", blob)


class TestAiReviewParse(unittest.TestCase):
    def test_parse_json_verdict(self):
        from backend.ai.fp_ai_review import parse_ai_review

        parsed = parse_ai_review(
            '{"verdict":"false_positive","confidence":70,"summary":"Só cookie.",'
            '"reasons":["Sem HttpOnly não prova invasão"]}'
        )
        self.assertEqual(parsed["verdict"], "false_positive")
        self.assertEqual(parsed["confidence"], 70)
        self.assertEqual(parsed["source"], "llm")
        self.assertTrue(parsed["reasons"])

    def test_review_uses_cache_and_mock_llm(self):
        from backend.ai.fp_ai_review import review_finding
        from backend.ai.providers.base import LLMCompletion, LLMMessage

        cached = review_finding(
            {
                "title": "XSS",
                "ai_review": {
                    "verdict": "confirmed",
                    "confidence": 80,
                    "reasons": ["payload refletido"],
                    "source": "llm",
                },
            }
        )
        self.assertEqual(cached["verdict"], "confirmed")

        mock_p = MagicMock()
        mock_p.is_configured.return_value = True
        mock_p.resolve_models.return_value = ("m", "m")
        mock_p.complete.return_value = LLMCompletion(
            message=LLMMessage(
                content='{"verdict":"unsure","confidence":40,"reasons":["pouca evidência"]}'
            )
        )
        with patch("backend.ai.providers.get_llm_provider", return_value=mock_p):
            out = review_finding(
                {"title": "HSTS missing", "severity": "medium", "evidence": "no header"}
            )
        self.assertEqual(out["source"], "llm")
        self.assertEqual(out["verdict"], "unsure")
