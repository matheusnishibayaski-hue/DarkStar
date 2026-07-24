"""API de troca OpenRouter ↔ Ollama em runtime."""

from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from backend.ai.providers.runtime import clear_provider_override
from backend.main import app


class TestAiProviderApi(unittest.TestCase):
    def setUp(self):
        clear_provider_override()
        self.client = TestClient(app)

    def tearDown(self):
        clear_provider_override()

    def test_get_and_set_provider(self):
        res = self.client.get("/api/ai-provider")
        self.assertEqual(res.status_code, 200)
        self.assertIn(res.json()["provider"], {"openrouter", "ollama"})

        res = self.client.post("/api/ai-provider", json={"provider": "ollama"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["provider"], "ollama")
        self.assertTrue(data["offline"])

        res = self.client.get("/api/models")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json().get("provider"), "ollama")

        res = self.client.post("/api/ai-provider", json={"provider": "openrouter"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["provider"], "openrouter")
        self.assertFalse(res.json()["offline"])

    def test_client_config_reflects_offline(self):
        self.client.post("/api/ai-provider", json={"provider": "ollama"})
        cfg = self.client.get("/api/client-config").json()
        self.assertTrue(cfg.get("ai_offline"))
        self.assertEqual(cfg.get("ai_provider"), "ollama")


if __name__ == "__main__":
    unittest.main()
