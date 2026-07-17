"""Attack Surface Graph + motor de fases."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.ai.phases import (
    advance_surface_phase,
    evaluate_phase_advance,
    is_tool_allowed,
    kickoff_for_phase,
    normalize_risk_profile,
)
from backend.executor import surface as surface_mod
from backend.executor.surface import (
    empty_surface,
    get_or_create_surface,
    update_surface_from_execution,
)
from tests.auth_patch import patch_chat_api_token


class TestPhases(unittest.TestCase):
    def test_risk_profile_and_blocks(self):
        self.assertEqual(normalize_risk_profile("nope"), "safe-active")
        ok, msg = is_tool_allowed("sqlmap -u http://x", phase="vuln_scan", risk_profile="safe-active")
        self.assertFalse(ok)
        self.assertIn("bloqueada", msg.lower())
        ok, _ = is_tool_allowed("nmap -sV t.com", phase="enumerate", risk_profile="safe-active")
        self.assertTrue(ok)
        ok, _ = is_tool_allowed("nmap -sV t.com", phase="recon", risk_profile="passive")
        self.assertFalse(ok)
        ok, msg = is_tool_allowed("nmap -V", phase="report", risk_profile="full")
        self.assertFalse(ok)
        self.assertIn("finish_mission", msg)

    def test_phase_advance(self):
        s = empty_surface("lab.test")
        s["commands_run"] = 2
        s["tools_run"] = ["subfinder"]
        d = evaluate_phase_advance(s)
        self.assertTrue(d.advanced)
        self.assertEqual(d.phase, "enumerate")

        s["phase"] = "enumerate"
        s["ports"] = [{"host": "lab.test", "port": "80", "proto": "tcp"}]
        d = evaluate_phase_advance(s)
        self.assertEqual(d.phase, "vuln_scan")

        s["phase"] = "vuln_scan"
        s["findings"] = [{"id": "1", "status": "candidate", "title": "x"}]
        d = evaluate_phase_advance(s)
        self.assertEqual(d.phase, "verify")

        s["phase"] = "verify"
        s["findings"] = [{"id": "1", "status": "confirmed", "verified_at": "t"}]
        s, d = advance_surface_phase(s)
        self.assertEqual(s["phase"], "report")
        self.assertTrue(d.can_finish)

    def test_kickoff(self):
        text = kickoff_for_phase(
            phase="recon",
            target="t.com",
            objective="mapear",
            round_idx=0,
            max_rounds=10,
            tools_executed=0,
            surface_summary_data={"hosts_count": 1, "ports_count": 0, "urls_count": 0,
                                  "findings_candidates": 0, "findings_confirmed": 0},
        )
        self.assertIn("FASE ATUAL", text)
        self.assertIn("recon", text)


class TestSurface(unittest.TestCase):
    def test_update_from_nmap_and_nuclei(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(surface_mod, "SURFACE_DIR", root):
                data = update_surface_from_execution(
                    "scanme.nmap.org",
                    command="nmap -sV scanme.nmap.org",
                    tool="nmap",
                    stdout="80/tcp open http\n443/tcp open https\n",
                    stderr="",
                    success=True,
                    blocked=False,
                )
                self.assertGreaterEqual(len(data["ports"]), 2)
                self.assertIn("nmap", data["tools_run"])

                data = update_surface_from_execution(
                    "scanme.nmap.org",
                    command="nuclei -u http://scanme.nmap.org",
                    tool="nuclei",
                    stdout="[high] CVE-2024-1234 exposed panel\nhttp://scanme.nmap.org/admin\n",
                    stderr="",
                    success=True,
                    blocked=False,
                )
                self.assertTrue(data["findings"])
                self.assertTrue(any(f["status"] == "candidate" for f in data["findings"]))
                self.assertTrue(data["urls"])
                # CVE correlacionado no finding
                self.assertTrue(
                    any(
                        f.get("cve") == "CVE-2024-1234" or "CVE-2024-1234" in f.get("title", "")
                        for f in data["findings"]
                    )
                )

                eng = get_or_create_surface(
                    "scanme.nmap.org", objective="mapear", risk_profile="safe-active"
                )
                self.assertEqual(eng["objective"], "mapear")


class TestEngagementsApi(unittest.TestCase):
    def test_create_and_get_surface(self):
        from backend.main import app

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(surface_mod, "SURFACE_DIR", root), patch_chat_api_token(""):
                client = TestClient(app)
                res = client.post(
                    "/api/engagements",
                    json={
                        "target": "lab.example.com",
                        "objective": "recon web",
                        "risk_profile": "safe-active",
                    },
                )
                self.assertEqual(res.status_code, 200)
                self.assertEqual(res.json()["phase"], "recon")

                res = client.get("/api/surface/lab.example.com")
                self.assertEqual(res.status_code, 200)
                self.assertEqual(res.json()["target"], "lab.example.com")

                res = client.patch(
                    "/api/engagements/lab.example.com/phase",
                    json={"phase": "enumerate"},
                )
                self.assertEqual(res.status_code, 200)
                self.assertEqual(res.json()["phase"], "enumerate")


if __name__ == "__main__":
    unittest.main()
