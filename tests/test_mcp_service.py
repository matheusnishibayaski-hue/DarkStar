"""Testes de backend/mcp_service.py e backend/routes/mcp.py (servidor MCP)."""

from __future__ import annotations

import unittest
from unittest import mock

from fastapi.testclient import TestClient

from backend import mcp_service


class TestServerInfo(unittest.TestCase):
    def test_server_info_shape(self):
        info = mcp_service.server_info()
        self.assertEqual(info["name"], "chat-ia-kali-mcp")
        self.assertIn("protocolVersion", info)
        self.assertIn("capabilities", info)


class TestToolsCatalog(unittest.TestCase):
    def test_list_tools_has_expected_names(self):
        names = {t["name"] for t in mcp_service.list_tools()}
        self.assertEqual(
            names,
            {
                "list_surface_targets",
                "get_surface_graph",
                "get_surface_triage",
                "get_risk_score",
                "list_allowed_tools",
                "run_kali_tool",
                "enrich_target_threat_intel",
                "suggest_next_checks",
            },
        )

    def test_list_tools_no_handler_leak(self):
        for tool in mcp_service.list_tools():
            self.assertNotIn("handler", tool)

    def test_get_tool_found_and_not_found(self):
        self.assertIsNotNone(mcp_service.get_tool("run_kali_tool"))
        self.assertIsNone(mcp_service.get_tool("does_not_exist"))


class TestCallTool(unittest.TestCase):
    def test_call_unknown_tool(self):
        result = mcp_service.call_tool("nope")
        self.assertTrue(result["isError"])

    def test_call_list_surface_targets(self):
        with mock.patch("backend.executor.surface.list_surface_summaries", return_value=[]):
            result = mcp_service.call_tool("list_surface_targets")
        self.assertFalse(result["isError"])
        self.assertEqual(result["content"][0]["json"], {"targets": []})

    def test_call_get_surface_graph_requires_target(self):
        result = mcp_service.call_tool("get_surface_graph", {})
        self.assertTrue(result["isError"])

    def test_call_get_surface_graph_not_found(self):
        with mock.patch("backend.executor.surface.load_surface", return_value={}):
            result = mcp_service.call_tool("get_surface_graph", {"target": "nope.example"})
        self.assertTrue(result["isError"])

    def test_call_list_allowed_tools(self):
        result = mcp_service.call_tool("list_allowed_tools")
        self.assertFalse(result["isError"])
        self.assertIn("tools", result["content"][0]["json"])

    def test_run_kali_tool_blocked_out_of_scope(self):
        with mock.patch(
            "backend.security.scope.validate_command_scope",
            return_value=(False, "Fora do escopo"),
        ):
            result = mcp_service.call_tool(
                "run_kali_tool", {"command": "nmap -sV evil.example"}
            )
        self.assertFalse(result["isError"])
        payload = result["content"][0]["json"]
        self.assertTrue(payload["blocked"])

    def test_run_kali_tool_requires_command(self):
        result = mcp_service.call_tool("run_kali_tool", {})
        self.assertTrue(result["isError"])

    def test_run_kali_tool_success(self):
        fake_result = mock.Mock(
            command="nmap -sV scanme.nmap.org",
            tool="nmap",
            success=True,
            blocked=False,
            block_reason="",
            exit_code=0,
            stdout="ok",
            stderr="",
        )
        with mock.patch(
            "backend.security.scope.validate_command_scope", return_value=(True, "")
        ), mock.patch("backend.executor.kali.execute_kali_command", return_value=fake_result):
            result = mcp_service.call_tool(
                "run_kali_tool", {"command": "nmap -sV scanme.nmap.org", "reason": "teste"}
            )
        self.assertFalse(result["isError"])
        payload = result["content"][0]["json"]
        self.assertTrue(payload["success"])
        self.assertEqual(payload["tool"], "nmap")

    def test_enrich_target_threat_intel_tool(self):
        with mock.patch(
            "backend.ai.threat_intel.enrich_surface_with_threat_intel", return_value=3
        ):
            result = mcp_service.call_tool(
                "enrich_target_threat_intel", {"target": "example.com"}
            )
        self.assertFalse(result["isError"])
        self.assertEqual(result["content"][0]["json"]["findings_enriched"], 3)


class TestResources(unittest.TestCase):
    def test_list_resources_includes_static_and_dynamic(self):
        with mock.patch(
            "backend.executor.surface.list_surface_summaries",
            return_value=[{"target": "example.com"}],
        ):
            resources = mcp_service.list_resources()
        uris = {r["uri"] for r in resources}
        self.assertIn("targets://list", uris)
        self.assertIn("tools://whitelist", uris)
        self.assertIn("surface://example.com", uris)

    def test_read_resource_tools_whitelist(self):
        res = mcp_service.read_resource("tools://whitelist")
        self.assertIn("tools", res["json"])

    def test_read_resource_targets_list(self):
        with mock.patch("backend.executor.surface.list_surface_summaries", return_value=[]):
            res = mcp_service.read_resource("targets://list")
        self.assertEqual(res["json"], {"targets": []})

    def test_read_resource_surface_found_and_missing(self):
        with mock.patch(
            "backend.executor.surface.load_surface", return_value={"target": "example.com"}
        ):
            res = mcp_service.read_resource("surface://example.com")
        self.assertEqual(res["json"]["target"], "example.com")

        with mock.patch("backend.executor.surface.load_surface", return_value={}):
            with self.assertRaises(ValueError):
                mcp_service.read_resource("surface://nope.example")

    def test_read_resource_unknown_uri(self):
        with self.assertRaises(ValueError):
            mcp_service.read_resource("weird://scheme")


class TestJsonRpc(unittest.TestCase):
    def test_initialize(self):
        response = mcp_service.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(response["id"], 1)
        self.assertIn("protocolVersion", response["result"])

    def test_ping(self):
        response = mcp_service.handle_rpc({"jsonrpc": "2.0", "id": 2, "method": "ping"})
        self.assertEqual(response["result"], {})

    def test_tools_list(self):
        response = mcp_service.handle_rpc({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
        self.assertIn("tools", response["result"])

    def test_tools_call(self):
        with mock.patch("backend.executor.surface.list_surface_summaries", return_value=[]):
            response = mcp_service.handle_rpc(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "list_surface_targets", "arguments": {}},
                }
            )
        self.assertFalse(response["result"]["isError"])

    def test_resources_list_and_read(self):
        with mock.patch("backend.executor.surface.list_surface_summaries", return_value=[]):
            list_resp = mcp_service.handle_rpc(
                {"jsonrpc": "2.0", "id": 5, "method": "resources/list"}
            )
        self.assertIn("resources", list_resp["result"])

        read_resp = mcp_service.handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "resources/read",
                "params": {"uri": "tools://whitelist"},
            }
        )
        self.assertIn("contents", read_resp["result"])

    def test_unknown_method(self):
        response = mcp_service.handle_rpc({"jsonrpc": "2.0", "id": 7, "method": "nope/nope"})
        self.assertEqual(response["error"]["code"], -32601)

    def test_notification_returns_none(self):
        response = mcp_service.handle_rpc({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.assertIsNone(response)

    def test_notification_without_id_on_unknown_method_returns_none(self):
        response = mcp_service.handle_rpc({"jsonrpc": "2.0", "method": "nope/nope"})
        self.assertIsNone(response)

    def test_resources_read_error_becomes_rpc_error(self):
        response = mcp_service.handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 8,
                "method": "resources/read",
                "params": {"uri": "weird://scheme"},
            }
        )
        self.assertEqual(response["error"]["code"], -32602)


class TestMcpHttpRoutes(unittest.TestCase):
    def setUp(self):
        from backend.main import app

        self.client = TestClient(app)

    def test_openapi_lists_mcp_routes(self):
        res = self.client.get("/openapi.json")
        self.assertEqual(res.status_code, 200)
        paths = res.json().get("paths", {})
        for route in ("/api/mcp/info", "/api/mcp/tools", "/api/mcp/resources", "/api/mcp/rpc"):
            self.assertIn(route, paths)

    def test_info_endpoint(self):
        res = self.client.get("/api/mcp/info")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["name"], "chat-ia-kali-mcp")

    def test_list_tools_endpoint(self):
        res = self.client.get("/api/mcp/tools")
        self.assertEqual(res.status_code, 200)
        self.assertGreaterEqual(len(res.json()["tools"]), 5)

    def test_get_tool_not_found(self):
        res = self.client.get("/api/mcp/tools/does_not_exist")
        self.assertEqual(res.status_code, 404)

    def test_call_tool_via_http(self):
        with mock.patch("backend.executor.surface.list_surface_summaries", return_value=[]):
            res = self.client.post("/api/mcp/tools/list_surface_targets", json={"arguments": {}})
        self.assertEqual(res.status_code, 200)
        self.assertFalse(res.json()["isError"])

    def test_call_unknown_tool_via_http_404(self):
        res = self.client.post("/api/mcp/tools/does_not_exist", json={})
        self.assertEqual(res.status_code, 404)

    def test_resources_endpoint(self):
        with mock.patch("backend.executor.surface.list_surface_summaries", return_value=[]):
            res = self.client.get("/api/mcp/resources")
        self.assertEqual(res.status_code, 200)

    def test_read_resource_endpoint(self):
        res = self.client.get("/api/mcp/resources/tools://whitelist")
        self.assertEqual(res.status_code, 200)

    def test_rpc_endpoint(self):
        res = self.client.post(
            "/api/mcp/rpc", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["result"], {})

    def test_mcp_disabled_returns_404(self):
        with mock.patch("backend.routes.mcp.MCP_ENABLED", False):
            res = self.client.get("/api/mcp/info")
        self.assertEqual(res.status_code, 404)


if __name__ == "__main__":
    unittest.main()
