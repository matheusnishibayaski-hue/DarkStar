"""Testes de playbooks."""

import unittest
from unittest.mock import patch

from backend.executor.result import ExecutionResult
from fastapi.testclient import TestClient


class TestPlaybooks(unittest.TestCase):
    def setUp(self):
        from backend.main import app

        self.client = TestClient(app)

    def test_list_playbooks(self):
        res = self.client.get("/api/playbooks")
        self.assertEqual(res.status_code, 200)
        playbooks = res.json()["playbooks"]
        ids = {p["id"] for p in playbooks}
        self.assertIn("recon-web", ids)
        self.assertIn("port-scan", ids)

    @patch("backend.playbooks.loader.execute_kali_command")
    def test_run_playbook_mock(self, mock_exec):
        mock_exec.return_value = ExecutionResult(
            command="nmap -sV scanme.nmap.org",
            reason="test",
            stdout="ok",
            stderr="",
            exit_code=0,
            success=True,
            tool="nmap",
            log_file_id="log1",
        )
        res = self.client.post(
            "/api/playbooks/port-scan/run",
            json={"target": "scanme.nmap.org"},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["playbook_id"], "port-scan")
        self.assertGreaterEqual(data["steps_run"], 1)

    def test_run_playbook_not_found(self):
        res = self.client.post(
            "/api/playbooks/missing/run",
            json={"target": "scanme.nmap.org"},
        )
        self.assertEqual(res.status_code, 404)

    @patch("backend.config.ALLOWED_TARGETS", frozenset({"allowed.lab"}))
    def test_run_playbook_scope_block(self):
        import backend.security.scope as scope_mod

        with patch.object(scope_mod, "ALLOWED_TARGETS", frozenset({"allowed.lab"})):
            res = self.client.post(
                "/api/playbooks/port-scan/run",
                json={"target": "evil.com"},
            )
            self.assertEqual(res.status_code, 403)
