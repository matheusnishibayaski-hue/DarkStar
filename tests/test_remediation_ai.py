"""Testes da remediação IA / tracker / API."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from backend.ai.providers.base import LLMCompletion, LLMMessage
from backend.ai.remediation_ai import (
    RemediationAdvisor,
    RemediationTracker,
    RemediationVerifier,
    remediation_advisor,
)
from fastapi.testclient import TestClient

from tests.auth_patch import patch_chat_api_token

SAMPLE_FINDING = {
    "id": "f1",
    "title": "Missing HSTS",
    "severity": "medium",
    "host": "lab.test",
    "evidence": "No Strict-Transport-Security header",
    "tool": "nuclei",
}


class TestRemediationParseFallback(unittest.TestCase):
    def test_fallback_plan(self):
        plan = RemediationAdvisor().create_fallback_remediation(SAMPLE_FINDING)
        self.assertEqual(plan.source, "fallback")
        self.assertGreaterEqual(len(plan.steps), 2)
        blob = (plan.steps[1].title or "") + (plan.steps[1].description or "")
        self.assertTrue(
            "HSTS" in blob or "Strict-Transport-Security" in blob,
            blob,
        )

    def test_parse_json(self):
        raw = """
        Here is the plan:
        {
          "root_cause": "Header ausente",
          "steps": [
            {"step": 1, "title": "Configurar HSTS", "description": "No proxy", "command": "nginx -t"}
          ],
          "code_before": "server {}",
          "code_after": "add_header Strict-Transport-Security ...",
          "test_command": "curl -I https://lab.test",
          "deployment_notes": "reload nginx",
          "estimated_time": 20,
          "difficulty": "easy",
          "references": ["https://owasp.org"],
          "confidence": 0.9
        }
        """
        plan = RemediationAdvisor().parse_remediation_response(raw, SAMPLE_FINDING)
        self.assertEqual(plan.source, "ai")
        self.assertEqual(plan.difficulty, "easy")
        self.assertEqual(len(plan.steps), 1)
        self.assertAlmostEqual(plan.confidence_score, 0.9)

    def test_generate_uses_fallback_when_provider_down(self):
        mock_p = MagicMock()
        mock_p.is_configured.return_value = False
        with patch("backend.ai.remediation_ai.get_llm_provider", return_value=mock_p):
            plan = remediation_advisor.generate_remediation(SAMPLE_FINDING)
            self.assertEqual(plan.source, "fallback")

    def test_generate_with_mocked_llm(self):
        mock_p = MagicMock()
        mock_p.is_configured.return_value = True
        mock_p.resolve_models.return_value = ("model", "fb")
        mock_p.complete.return_value = LLMCompletion(
            message=LLMMessage(
                content='{"root_cause":"x","steps":[{"step":1,"title":"A","description":"B"}],'
                '"estimated_time":10,"difficulty":"easy","confidence":0.8,"references":[]}'
            ),
            model="model",
        )
        with patch("backend.ai.remediation_ai.get_llm_provider", return_value=mock_p):
            plan = RemediationAdvisor().generate_remediation(SAMPLE_FINDING)
            self.assertEqual(plan.source, "ai")
            self.assertEqual(plan.steps[0].title, "A")


class TestVerifierAndTracker(unittest.TestCase):
    def test_python_syntax(self):
        v = RemediationVerifier()
        ok = v.verify_fix("print(1)", "print(1)", "pytest", "python")
        self.assertTrue(ok["syntax_valid"])
        self.assertTrue(ok["test_skipped"])
        bad = v.verify_fix("", "def (", "", "python")
        self.assertFalse(bad["syntax_valid"])

    def test_tracker_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "track.json"
            tr = RemediationTracker(path=path)
            tr.track("f1", {"vulnerability_title": "x"}, status="in_progress")
            tr.update("f1", status="completed", steps_completed=3, notes="done")
            st = tr.stats()
            self.assertEqual(st["total_tracked"], 1)
            self.assertEqual(st["completed"], 1)


class TestRemediationRoutes(unittest.TestCase):
    def test_generate_and_stats(self):
        mock_p = MagicMock()
        mock_p.is_configured.return_value = False
        with (
            patch_chat_api_token(""),
            patch("backend.ai.remediation_ai.get_llm_provider", return_value=mock_p),
            tempfile.TemporaryDirectory() as tmp,
        ):
            path = Path(tmp) / "t.json"
            with patch("backend.ai.remediation_ai.remediation_tracker.path", path):
                # also patch singleton used by routes
                from backend.routes import remediation as rem_routes

                rem_routes.remediation_tracker.path = path
                from backend.main import app

                client = TestClient(app)
                r = client.post(
                    "/api/remediation/generate",
                    json={"finding": SAMPLE_FINDING},
                )
                self.assertEqual(r.status_code, 200)
                body = r.json()
                self.assertEqual(body["status"], "generated")
                self.assertTrue(body["plan"]["steps"])
                r2 = client.post(
                    "/api/remediation/track",
                    json={
                        "finding_id": "f1",
                        "remediation_plan": body["plan"],
                        "status": "in_progress",
                    },
                )
                self.assertEqual(r2.status_code, 200)
                r3 = client.get("/api/remediation/stats")
                self.assertEqual(r3.status_code, 200)
                self.assertGreaterEqual(r3.json()["statistics"]["total_tracked"], 1)


if __name__ == "__main__":
    unittest.main()
