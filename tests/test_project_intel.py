"""Testes de project intel + anexos no agent + catálogo de tools ⊆ ALLOWED_TOOLS."""

from __future__ import annotations

import unittest

from backend.ai.agent import _apply_attachments
from backend.ai.project_intel import (
    extract_project_intel,
    operator_text_for_targets,
)
from backend.ai.scan_profiles import BASIC_TOOLS, INTERMEDIATE_TOOLS, resolve_scan_tools
from backend.config_tools import ALLOWED_TOOLS
from backend.tool_catalog import TOOL_CATALOG


class TestProjectIntel(unittest.TestCase):
    def test_extract_stack_and_routes(self):
        attachments = [
            {
                "name": "__project_map.txt",
                "content": "# map\nbackend/routes/chat.py\t100\npackage.json\t50\n",
            },
            {
                "name": "package.json",
                "content": '{"dependencies":{"express":"4.18.0","next":"14.0.0"}}',
            },
            {
                "name": "backend/routes/auth.py",
                "content": '@app.get("/api/login")\ndef login():\n    return {"ok": True}\n',
            },
            {
                "name": "docker-compose.yml",
                "content": "services:\n  web:\n    ports:\n      - '8080:80'\n",
            },
        ]
        intel = extract_project_intel(attachments)
        self.assertIn("[PROJECT INTEL", intel)
        self.assertTrue("Node" in intel or "Express" in intel or "Next" in intel)
        self.assertTrue("8080" in intel or "80" in intel)
        self.assertTrue("/api/login" in intel or "routes" in intel.lower())

    def test_apply_attachments_includes_intel_and_map(self):
        msg = _apply_attachments(
            "Analise o projeto",
            [
                {"name": "__project_map.txt", "content": "src/main.py\t10\n"},
                {"name": "requirements.txt", "content": "fastapi==0.100.0\n"},
            ],
        )
        self.assertIn("[Anexos]", msg)
        self.assertIn("[PROJECT INTEL", msg)
        self.assertIn("Mapa do repositório", msg)
        self.assertIn("FastAPI", msg)

    def test_operator_text_strips_anexos(self):
        raw = (
            "Teste scanme.nmap.org\n\n[Anexos]\n--- arquivo: x ---\n"
            "https://registry.npmjs.org/foo\n"
        )
        op = operator_text_for_targets(raw)
        self.assertIn("scanme.nmap.org", op)
        self.assertNotIn("npmjs", op)


class TestToolsCatalogAllowlist(unittest.TestCase):
    def test_catalog_subset_of_allowed(self):
        allowed = {t.lower() for t in ALLOWED_TOOLS}
        missing = [name for name in TOOL_CATALOG if name.lower() not in allowed]
        self.assertEqual(missing, [], f"TOOLS no catálogo fora do ALLOWED_TOOLS: {missing}")

    def test_profiles_subset_of_allowed(self):
        allowed = {t.lower() for t in ALLOWED_TOOLS}
        for name in BASIC_TOOLS + INTERMEDIATE_TOOLS:
            self.assertIn(name.lower(), allowed, f"perfil contém tool não permitida: {name}")
        for prof in ("basic", "intermediate", "full"):
            tools = resolve_scan_tools(prof, None, include_all_allowed=False)
            for name in tools:
                self.assertIn(name.lower(), allowed, f"{prof}: {name}")


if __name__ == "__main__":
    unittest.main()
