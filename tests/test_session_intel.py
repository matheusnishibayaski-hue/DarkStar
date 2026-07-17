"""Testes do intel agrupado por conversa."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient


class TestSessionIntel(unittest.TestCase):
    def test_aggregate_and_patch_by_session(self):
        from backend.executor import session_intel as si
        from backend.executor.surface import get_or_create_surface, save_surface

        with tempfile.TemporaryDirectory() as tmp:
            intel_dir = Path(tmp) / "intel"
            surface_dir = Path(tmp) / "surface"
            intel_dir.mkdir()
            surface_dir.mkdir()

            sid = "sess-test-12345678"
            target_a = "lab.a.test"
            target_b = "lab.b.test"

            with (
                patch.object(si, "INTEL_SESSIONS_DIR", intel_dir),
                patch("backend.executor.surface.SURFACE_DIR", surface_dir),
            ):
                si.touch_session(sid, target_a)
                si.touch_session(sid, target_b)

                data_a = get_or_create_surface(target_a)
                data_a["findings"] = [
                    {
                        "id": "f1",
                        "title": "High on A",
                        "severity": "high",
                        "status": "candidate",
                        "chat_session_id": sid,
                        "tool": "nmap",
                    },
                    {
                        "id": "f-other",
                        "title": "Other session",
                        "severity": "low",
                        "status": "candidate",
                        "chat_session_id": "other-session-id",
                        "tool": "nmap",
                    },
                ]
                save_surface(target_a, data_a)

                data_b = get_or_create_surface(target_b)
                data_b["findings"] = [
                    {
                        "id": "f2",
                        "title": "Medium on B",
                        "severity": "medium",
                        "status": "candidate",
                        "chat_session_id": sid,
                        "tool": "nikto",
                    }
                ]
                save_surface(target_b, data_b)

                findings = si.aggregate_session_findings(sid)
                self.assertEqual(len(findings), 2)
                titles = {f["title"] for f in findings}
                self.assertIn("High on A", titles)
                self.assertIn("Medium on B", titles)

                patched = si.patch_session_finding(
                    sid, target_a, "f1", "confirmed", evidence="manual"
                )
                self.assertEqual(patched["status"], "confirmed")

                si.set_session_label(sid, "Pentest Cliente X")
                summary = si.session_summary(sid)
                self.assertEqual(summary["label"], "Pentest Cliente X")
                self.assertEqual(summary["findings_total"], 2)
                self.assertEqual(summary["findings_confirmed"], 1)

                self.assertTrue(si.delete_session_intel(sid))
                self.assertEqual(si.aggregate_session_findings(sid), [])
                self.assertFalse((intel_dir / f"{sid}.json").exists())

    def test_intel_session_routes(self):
        from backend.main import app

        sid = "route-test-sess-01"
        finding = {
            "id": "f1",
            "title": "Test",
            "severity": "high",
            "status": "confirmed",
            "surface_target": "x.test",
            "tool": "nmap",
        }
        with (
            patch(
                "backend.routes.intel_sessions.aggregate_session_findings",
                return_value=[finding],
            ),
            patch(
                "backend.routes.intel_sessions.load_session",
                return_value={"label": "Relatório Demo", "targets": ["x.test"]},
            ),
            patch(
                "backend.routes.intel_sessions.session_summary",
                return_value={
                    "session_id": sid,
                    "label": "Relatório Demo",
                    "targets": ["x.test"],
                    "findings_total": 1,
                    "findings_confirmed": 1,
                },
            ),
            patch(
                "backend.ai.pdf_report.generate_report_pdf",
                return_value=b"%PDF-1.4",
            ),
        ):
            client = TestClient(app)
            detail = client.get(f"/api/intel/sessions/{sid}")
            self.assertEqual(detail.status_code, 200)
            body = detail.json()
            self.assertEqual(body["findings_total"], 1)
            self.assertEqual(len(body["findings"]), 1)

            patch_res = client.patch(
                f"/api/intel/sessions/{sid}",
                json={"label": "Novo nome"},
            )
            self.assertEqual(patch_res.status_code, 200)

            pdf = client.get(f"/api/intel/sessions/{sid}/report")
            self.assertEqual(pdf.status_code, 200)
            self.assertIn("pdf", pdf.headers.get("content-type", ""))


if __name__ == "__main__":
    unittest.main()
