"""Contrato OpenAPI — rotas críticas presentes."""

import unittest

from fastapi.testclient import TestClient


class TestOpenApi(unittest.TestCase):
    def test_routes_in_openapi(self):
        from backend.main import app

        client = TestClient(app)
        res = client.get("/openapi.json")
        self.assertEqual(res.status_code, 200)
        paths = res.json().get("paths", {})
        for route in (
            "/api/files",
            "/api/audit",
            "/api/playbooks",
            "/api/playbooks/{playbook_id}/run",
        ):
            self.assertIn(route, paths, f"Rota ausente no OpenAPI: {route}")

    def test_health_version_110(self):
        from backend.main import app

        client = TestClient(app)
        res = client.get("/api/health")
        self.assertEqual(res.json()["version"], "1.1.0")
        self.assertIn("scope_warning", res.json())
