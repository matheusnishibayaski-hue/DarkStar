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
            "/api/metrics",
            "/api/tools",
            "/api/system/tools/update",
            "/api/surface",
            "/api/engagements",
            "/api/engagements/{target}/verify",
            "/api/engagements/{target}/triage",
            "/api/engagements/{target}/report",
            "/api/engagements/{target}/delta",
            "/api/engagements/{target}/baseline",
            "/api/engagements/{target}/risk",
            "/api/intel/sessions",
            "/api/intel/sessions/{session_id}",
            "/api/intel/sessions/{session_id}/report",
            "/api/data/summary",
            "/api/data/purge",
            "/api/mcp/info",
            "/api/mcp/tools",
            "/api/mcp/tools/{name}",
            "/api/mcp/resources",
            "/api/mcp/rpc",
            "/api/intelligence/record",
            "/api/intelligence/suggest/{target}",
            "/api/intelligence/stats",
            "/api/intelligence/similar/{target}",
            "/api/intelligence/threat-model",
            "/api/intelligence/threat-model/{target}",
            "/api/compliance/frameworks",
            "/api/compliance/report",
            "/api/compliance/report/{target}",
        ):
            self.assertIn(route, paths, f"Rota ausente no OpenAPI: {route}")

    def test_health_version_200(self):
        from backend.main import app

        client = TestClient(app)
        res = client.get("/api/health")
        self.assertEqual(res.json()["version"], "2.0.0")
        self.assertIn("scope_warning", res.json())
        body = res.json()
        self.assertIn("status", body)

    def test_tools_and_scan_profiles_smoke(self):
        from backend.main import app

        from tests.auth_patch import patch_chat_api_token

        with patch_chat_api_token(""):
            client = TestClient(app)
            tools = client.get("/api/tools")
            self.assertEqual(tools.status_code, 200)
            data = tools.json()
            # categorias ou lista flat
            self.assertTrue(data, "GET /api/tools vazio")
            profiles = client.get("/api/scan-profiles")
            self.assertEqual(profiles.status_code, 200)
            pdata = profiles.json()
            self.assertTrue(pdata, "GET /api/scan-profiles vazio")
