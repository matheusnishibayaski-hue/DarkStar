"""Testes do Provider/Adapter LLM (OpenRouter / Ollama) + heal de tools."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from backend.ai.providers.base import LLMCompletion, LLMMessage, ToolCall
from backend.ai.providers.factory import get_llm_provider, reset_llm_provider_cache
from backend.ai.providers.ollama import OllamaAdapter
from backend.ai.providers.openrouter import OpenRouterAdapter
from backend.ai.providers.runtime import clear_provider_override, set_active_provider
from backend.ai.providers.tool_heal import heal_tool_arguments, resolve_tool_arguments
from backend.ai.providers.tool_parse import (
    extract_tool_calls_from_content,
    parse_tool_arguments,
    try_parse_json,
)


class TestFactory(unittest.TestCase):
    def tearDown(self):
        clear_provider_override()
        reset_llm_provider_cache()

    def test_default_openrouter(self):
        clear_provider_override()
        with patch("backend.ai.providers.runtime.AI_PROVIDER", "openrouter"):
            clear_provider_override()
            p = get_llm_provider()
        self.assertIsInstance(p, OpenRouterAdapter)
        self.assertEqual(p.name, "openrouter")

    def test_ollama_provider(self):
        set_active_provider("ollama")
        p = get_llm_provider()
        self.assertIsInstance(p, OllamaAdapter)
        self.assertEqual(p.name, "ollama")

    def test_explicit_name_bypasses_env(self):
        p = get_llm_provider("ollama")
        self.assertIsInstance(p, OllamaAdapter)

    def test_runtime_switch(self):
        from backend.ai.providers.runtime import get_active_provider_name

        set_active_provider("ollama")
        self.assertEqual(get_active_provider_name(), "ollama")
        self.assertIsInstance(get_llm_provider(), OllamaAdapter)
        set_active_provider("openrouter")
        self.assertEqual(get_active_provider_name(), "openrouter")
        self.assertIsInstance(get_llm_provider(), OpenRouterAdapter)


class TestToolParse(unittest.TestCase):
    def test_parse_valid_json(self):
        data = parse_tool_arguments('{"command":"nmap -V","reason":"ver"}')
        self.assertEqual(data["command"], "nmap -V")

    def test_parse_trailing_comma(self):
        data = parse_tool_arguments('{"command":"nmap -V","reason":"ver",}')
        self.assertIsNotNone(data)
        self.assertEqual(data["command"], "nmap -V")

    def test_extract_from_markdown_fence(self):
        content = (
            "Vou escanear agora:\n"
            "```json\n"
            '{"command":"nmap -sV scanme.nmap.org","reason":"portas"}\n'
            "```"
        )
        calls = extract_tool_calls_from_content(content)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].name, "run_kali_tool")
        args = parse_tool_arguments(calls[0].arguments)
        self.assertEqual(args["command"], "nmap -sV scanme.nmap.org")

    def test_extract_finish_mission(self):
        content = '{"summary":"feito","objective_met":true}'
        calls = extract_tool_calls_from_content(content)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].name, "finish_mission")

    def test_try_parse_embedded_object(self):
        data = try_parse_json('prefix {"a":1} suffix')
        self.assertEqual(data, {"a": 1})


class TestToolHeal(unittest.TestCase):
    def test_heal_succeeds_on_second_try(self):
        provider = MagicMock()
        provider.complete.side_effect = [
            LLMCompletion(message=LLMMessage(content="ainda quebrado")),
            LLMCompletion(
                message=LLMMessage(
                    content='{"command":"nmap -V","reason":"versão do nmap"}'
                )
            ),
        ]
        result = heal_tool_arguments(
            provider,
            model="local",
            tool_name="run_kali_tool",
            broken_arguments="{command: nmap -V",
            max_attempts=2,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["command"], "nmap -V")
        self.assertEqual(provider.complete.call_count, 2)

    def test_heal_gives_up(self):
        provider = MagicMock()
        provider.complete.return_value = LLMCompletion(
            message=LLMMessage(content="not json at all")
        )
        result = heal_tool_arguments(
            provider,
            model="local",
            tool_name="run_kali_tool",
            broken_arguments="<<<",
            max_attempts=2,
        )
        self.assertIsNone(result)
        self.assertEqual(provider.complete.call_count, 2)

    def test_resolve_valid_without_heal(self):
        provider = MagicMock()
        tc = ToolCall(
            id="1",
            name="run_kali_tool",
            arguments='{"command":"whoami","reason":"id"}',
        )
        data, err = resolve_tool_arguments(provider, model="m", tool_call=tc)
        self.assertEqual(data["command"], "whoami")
        self.assertEqual(err, "")
        provider.complete.assert_not_called()


class TestOpenRouterAdapter(unittest.TestCase):
    def test_not_configured_without_key(self):
        p = OpenRouterAdapter(api_key="")
        self.assertFalse(p.is_configured())
        self.assertIn("OPENROUTER", p.configuration_error().upper())

    def test_format_401(self):
        p = OpenRouterAdapter(api_key="sk")
        self.assertIn("inválida", p.format_error("401 invalid key").lower())


class TestOllamaAdapter(unittest.TestCase):
    def test_always_configured(self):
        p = OllamaAdapter()
        self.assertTrue(p.is_configured())

    def test_models_catalog_structure(self):
        p = OllamaAdapter(default_model="llama3.1:8b")
        with patch.object(p, "_list_local_models", return_value=["llama3.1:8b", "qwen2.5:14b"]):
            catalog = p.models_catalog()
        self.assertEqual(catalog["provider"], "ollama")
        self.assertEqual(catalog["tiers"][0]["id"], "local")
        ids = [m["id"] for m in catalog["tiers"][0]["models"]]
        self.assertIn("llama3.1:8b", ids)

    def test_health_down(self):
        p = OllamaAdapter(base_url="http://127.0.0.1:9/v1")
        with patch("urllib.request.urlopen", side_effect=OSError("refused")):
            h = p.health()
        self.assertFalse(h["ok"])


class TestCompatibleCompleteExtractsContentTools(unittest.TestCase):
    def test_content_tool_becomes_tool_calls(self):
        p = OllamaAdapter()
        raw_msg = MagicMock()
        raw_msg.content = (
            '```json\n{"command":"nmap -V","reason":"ver"}\n```'
        )
        raw_msg.tool_calls = None
        choice = MagicMock()
        choice.message = raw_msg
        resp = MagicMock()
        resp.choices = [choice]

        fake_client = MagicMock()
        fake_client.chat.completions.create.return_value = resp
        p._client = fake_client

        out = p.complete(
            model="llama3.1:8b",
            messages=[{"role": "user", "content": "nmap"}],
            tools=[{"type": "function", "function": {"name": "run_kali_tool"}}],
        )
        self.assertTrue(out.message.has_tool_calls)
        self.assertEqual(out.message.tool_calls[0].name, "run_kali_tool")


if __name__ == "__main__":
    unittest.main()
