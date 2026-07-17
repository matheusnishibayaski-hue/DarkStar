"""Cobertura dos módulos executor/models/tools de baixo cover."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from backend.executor.result import ExecutionResult, format_result_for_llm
from backend.executor.summarize import estimate_tokens, summarize_output
from backend.models_catalog import find_model_display, get_models_catalog, resolve_model
from backend.tool_catalog import enrich_categories, get_tool_info


class TestSummarize(unittest.TestCase):
    def test_empty_and_short(self):
        self.assertEqual(summarize_output("", ""), ("", False))
        text, truncated = summarize_output("hello", "")
        self.assertFalse(truncated)
        self.assertEqual(text, "hello")
        self.assertGreaterEqual(estimate_tokens("abcd"), 1)

    def test_truncates_long_output_with_critical(self):
        lines = [f"line-{i}" for i in range(200)]
        lines[50] = "[CRITICAL] vuln found"
        lines[51] = "80/tcp open http"
        lines[52] = "CVE-2024-9999"
        big = "\n".join(lines) + ("x" * 20000)
        with patch("backend.executor.summarize.OUTPUT_TOKEN_LIMIT", 100):
            text, truncated = summarize_output(big, "stderr")
        self.assertTrue(truncated)
        self.assertIn("truncado", text.lower())
        self.assertIn("CRITICAL", text)
        self.assertIn("CVE-2024-9999", text)


class TestModelsCatalog(unittest.TestCase):
    def test_catalog_and_resolve(self):
        cat = get_models_catalog()
        self.assertIn("tiers", cat)
        self.assertIn("default_model", cat)
        primary, fb = resolve_model(None, None)
        self.assertTrue(primary)
        self.assertTrue(fb)
        p2, f2 = resolve_model("google/gemini-2.5-flash", "google/gemini-2.5-flash")
        self.assertEqual(p2, "google/gemini-2.5-flash")
        self.assertNotEqual(f2, p2)
        alias_p, alias_f = resolve_model("deepseek/deepseek-chat-v3.2", None)
        self.assertEqual(alias_p, "deepseek/deepseek-v3.2")
        self.assertIsNotNone(find_model_display("deepseek/deepseek-chat-v3.2"))
        self.assertIsNotNone(find_model_display("google/gemini-2.5-flash"))
        self.assertIsNone(find_model_display("no/such-model"))


class TestLogsAndResult(unittest.TestCase):
    def test_save_and_read_log(self):
        from backend.executor import logs as logs_mod

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(logs_mod, "LOG_DIR", Path(tmp)):
                lid = logs_mod.save_execution_log("nmap", "teste", "out", "err")
                self.assertTrue(lid)
                content = logs_mod.read_execution_log(lid)
                self.assertIn("nmap", content)
                self.assertIsNone(logs_mod.read_execution_log(""))
                self.assertIsNone(logs_mod.read_execution_log("../x"))
                self.assertIsNone(logs_mod.read_execution_log("missingid12"))

    def test_format_result_for_llm(self):
        r = ExecutionResult(
            command="nmap",
            reason="r",
            stdout="a",
            stderr="b",
            exit_code=0,
            success=True,
            truncated_for_llm=True,
        )
        text = format_result_for_llm(r)
        self.assertIn("cmd=nmap", text)
        self.assertIn("(resumo)", text)
        self.assertIn("a", text)
        custom = format_result_for_llm(r, output_text="custom")
        self.assertIn("custom", custom)


class TestToolCatalog(unittest.TestCase):
    def test_unknown_and_enrich(self):
        info = get_tool_info("totally-unknown-tool")
        self.assertIn("totally-unknown-tool", info["example"])
        enriched = enrich_categories([{"id": "x", "name": "X", "tools": ["nmap", "zzz"]}])
        self.assertEqual(len(enriched[0]["tools"]), 2)


class TestWifiScan(unittest.TestCase):
    def test_windows_interfaces_and_scan(self):
        from backend.executor import wifi_scan as wifi

        ok_proc = MagicMock(returncode=0, stdout="Nome : Wi-Fi\n", stderr="")
        net_proc = MagicMock(returncode=0, stdout="SSID 1 : Lab\n", stderr="")
        prof = MagicMock(returncode=0, stdout="Profile\n", stderr="warn")

        with patch.object(wifi, "_run_netsh", side_effect=[ok_proc]), patch.object(
            wifi, "save_execution_log", return_value="w1"
        ):
            r = wifi._scan_windows("wlan-interfaces", "ifaces")
        self.assertTrue(r.success)

        with patch.object(
            wifi, "_run_netsh", side_effect=[ok_proc, net_proc, prof]
        ), patch.object(wifi, "save_execution_log", return_value="w2"):
            r2 = wifi._scan_windows("wlan-scan", "scan")
        self.assertTrue(r2.success)
        self.assertIn("STDERR", r2.stdout)

    def test_windows_errors(self):
        from backend.executor import wifi_scan as wifi

        with patch.object(wifi, "_run_netsh", side_effect=FileNotFoundError):
            r = wifi._scan_windows("wlan-scan", "x")
        self.assertFalse(r.success)
        with patch.object(wifi, "_run_netsh", side_effect=subprocess.TimeoutExpired("netsh", 1)):
            r2 = wifi._scan_windows("wlan-scan", "x")
        self.assertIn("Timeout", r2.stderr)
        with patch.object(wifi, "_run_netsh", side_effect=RuntimeError("boom")):
            r3 = wifi._scan_windows("wlan-scan", "x")
        self.assertIn("boom", r3.stderr)

    def test_linux_scan_paths(self):
        from backend.executor import wifi_scan as wifi

        ok = MagicMock(returncode=0, stdout="wlan0", stderr="")
        with patch.object(wifi.subprocess, "run", return_value=ok), patch.object(
            wifi, "save_execution_log", return_value="l1"
        ):
            r = wifi._scan_linux("wlan-interfaces", "i")
        self.assertTrue(r.success)

        with patch.object(
            wifi.subprocess, "run", side_effect=FileNotFoundError
        ), patch.object(wifi, "save_execution_log", return_value="l2"):
            r2 = wifi._scan_linux("wlan-scan", "s")
        self.assertFalse(r2.success)

        with patch.object(
            wifi.subprocess, "run", side_effect=RuntimeError("x")
        ), patch.object(wifi, "save_execution_log", return_value="l3"):
            r3 = wifi._scan_linux("wlan-scan", "s")
        self.assertIn("x", r3.stderr)

    def test_execute_host_wifi_dispatch(self):
        from backend.executor import wifi_scan as wifi

        with patch.object(wifi.sys, "platform", "win32"), patch.object(
            wifi, "_scan_windows", return_value=ExecutionResult("c", "r", "", "", 0, True)
        ) as w:
            wifi.execute_host_wifi("wlan-scan", "r")
            w.assert_called_once()
        with patch.object(wifi.sys, "platform", "linux"), patch.object(
            wifi, "_scan_linux", return_value=ExecutionResult("c", "r", "", "", 0, True)
        ) as l:
            wifi.execute_host_wifi("wlan-scan", "r")
            l.assert_called_once()

    def test_windows_wifi_health(self):
        from backend.executor import wifi_scan as wifi

        bad = MagicMock(returncode=1, stdout="", stderr="fail")
        with patch.object(wifi, "_run_netsh", return_value=bad):
            ok, ifaces, msg = wifi.windows_wifi_health()
        self.assertFalse(ok)

        good = MagicMock(
            returncode=0,
            stdout="   Nome : Wi-Fi\n",
            stderr="",
        )
        nets = MagicMock(returncode=0, stdout="SSID 1 : x\nSSID 2 : y\n", stderr="")
        with patch.object(wifi, "_run_netsh", side_effect=[good, nets]):
            ok, ifaces, msg = wifi.windows_wifi_health()
        self.assertTrue(ok)
        self.assertEqual(ifaces, ["Wi-Fi"])

        empty = MagicMock(returncode=0, stdout="no iface", stderr="")
        with patch.object(wifi, "_run_netsh", side_effect=[empty, nets]):
            ok, ifaces, msg = wifi.windows_wifi_health()
        self.assertFalse(ok)

        with patch.object(wifi, "_run_netsh", side_effect=RuntimeError("e")):
            ok, ifaces, msg = wifi.windows_wifi_health()
        self.assertEqual(msg, "e")


if __name__ == "__main__":
    unittest.main()
