"""Testes do sistema de master key / privilégios DarkStar."""

from __future__ import annotations

import unittest
from unittest import mock

from fastapi.testclient import TestClient


class TestPrivileges(unittest.TestCase):
    def test_profile_b_blocks_aggressive_tools(self):
        from backend.security.privileges import privilege_blocks_tool, set_elevated

        set_elevated(False)
        blocked, msg = privilege_blocks_tool("sqlmap")
        self.assertTrue(blocked)
        self.assertIn("perfil B", msg)
        ok, _ = privilege_blocks_tool("nmap")
        self.assertFalse(ok)

    def test_elevated_allows_aggressive(self):
        from backend.security.privileges import privilege_blocks_tool, set_elevated

        set_elevated(True)
        blocked, _ = privilege_blocks_tool("sqlmap")
        self.assertFalse(blocked)
        set_elevated(False)

    def test_effective_risk_clamps_full(self):
        from backend.security.privileges import effective_risk_profile, set_elevated

        set_elevated(False)
        self.assertEqual(effective_risk_profile("full"), "safe-active")
        set_elevated(True)
        self.assertEqual(effective_risk_profile("full"), "full")
        set_elevated(False)

    def test_master_key_unlock_http(self):
        with mock.patch("backend.security.privileges.MASTER_KEY", "test-master-key-xyz"):
            with mock.patch("backend.routes.auth.master_key_configured", return_value=True):
                with mock.patch(
                    "backend.routes.auth.verify_master_key",
                    side_effect=lambda k: k == "test-master-key-xyz",
                ):
                    from backend.main import app

                    client = TestClient(app)
                    bad = client.post("/api/auth/master-key", json={"key": "wrong"})
                    self.assertEqual(bad.status_code, 401)
                    ok = client.post(
                        "/api/auth/master-key",
                        json={"key": "test-master-key-xyz"},
                    )
                    self.assertEqual(ok.status_code, 200)
                    self.assertTrue(ok.json()["elevated"])
                    self.assertIn("darkstar_privilege", ok.cookies)

    def test_privilege_tokens_survive_reload(self):
        import tempfile
        from pathlib import Path

        from backend.security import privileges as priv

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "privileges.json"
            with mock.patch.object(priv, "PRIVILEGES_FILE", path):
                priv._tokens.clear()
                priv._loaded = False
                tok = priv.create_privilege_token()
                self.assertTrue(path.is_file())
                # Simula restart do processo
                priv._tokens.clear()
                priv._loaded = False
                self.assertTrue(priv.validate_privilege_token(tok))
                priv.revoke_privilege_token(tok)
                priv._tokens.clear()
                priv._loaded = False
                self.assertFalse(priv.validate_privilege_token(tok))
