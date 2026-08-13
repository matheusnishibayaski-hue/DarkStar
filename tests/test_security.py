"""Testes de sessão, rate limit e cancelamento de missões."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from tests.auth_patch import patch_chat_api_token


class TestSessionAuth(unittest.TestCase):
    def test_login_sets_session_cookie(self):
        from backend.main import app

        with patch_chat_api_token("secret-test-token"):
            client = TestClient(app)
            res = client.post("/api/auth/login", json={"token": "secret-test-token"})
            self.assertEqual(res.status_code, 200)
            self.assertIn("kali_session", res.cookies)

            anon = TestClient(app)
            res = anon.get("/api/tools")
            self.assertEqual(res.status_code, 401)

            res = client.get("/api/tools")
            self.assertEqual(res.status_code, 200)

    def test_login_rejects_bad_token(self):
        from backend.main import app

        with patch_chat_api_token("secret-test-token"):
            client = TestClient(app)
            res = client.post("/api/auth/login", json={"token": "wrong"})
            self.assertEqual(res.status_code, 401)

    def test_auth_session_unauthenticated(self):
        from backend.main import app

        with patch_chat_api_token("secret-test-token"):
            client = TestClient(app)
            res = client.get("/api/auth/session")
            self.assertEqual(res.status_code, 200)
            self.assertFalse(res.json()["authenticated"])


class TestRateLimit(unittest.TestCase):
    def test_chat_stream_rate_limited(self):
        import backend.security.rate_limit as rl
        from backend.main import app

        # Recria o limiter: get_rate_limiter ignora max_requests se já existir
        rl._limiter = None

        def mock_chat_stream(*_args, **_kwargs):
            yield 'event: done\ndata: {"message":"ok","tool_executions":[]}\n\n'

        with (
            patch_chat_api_token(""),
            patch("backend.middleware.RATE_LIMIT_REQUESTS", 2),
            patch("backend.middleware.RATE_LIMIT_WINDOW_SEC", 60),
            patch("backend.routes.chat.chat_stream", mock_chat_stream),
        ):
            rl._limiter = None
            client = TestClient(app)
            payload = {"message": "teste", "history": []}

            for _ in range(2):
                res = client.post("/api/chat/stream", json=payload)
                self.assertEqual(res.status_code, 200)

            res = client.post("/api/chat/stream", json=payload)
            self.assertEqual(res.status_code, 429)
            self.assertIn("Retry-After", res.headers)


class TestSessionPersistence(unittest.TestCase):
    def test_sessions_survive_store_reload(self):
        import backend.security.sessions as sessions_mod

        with tempfile.TemporaryDirectory() as tmp:
            sessions_file = Path(tmp) / "sessions.json"
            with patch.object(sessions_mod, "SESSIONS_FILE", sessions_file):
                sessions_mod._store = None
                store1 = sessions_mod.get_session_store(3600)
                session_id = store1.create()
                self.assertTrue(store1.validate(session_id))
                self.assertTrue(sessions_file.is_file())

                sessions_mod._store = None
                store2 = sessions_mod.get_session_store(3600)
                self.assertTrue(store2.validate(session_id))

            sessions_mod._store = None


class TestMissionCancel(unittest.TestCase):
    def test_cancel_unknown_mission(self):
        from backend.main import app

        with patch_chat_api_token(""):
            client = TestClient(app)
            res = client.post("/api/missions/does-not-exist/cancel")
            self.assertEqual(res.status_code, 404)

    def test_cancel_active_mission(self):
        from backend.security.missions import get_mission_registry

        registry = get_mission_registry()
        registry.register("mission-test-1")
        self.assertTrue(registry.cancel("mission-test-1"))
        self.assertTrue(registry.is_cancelled("mission-test-1"))
        registry.cleanup("mission-test-1")


if __name__ == "__main__":
    unittest.main()
