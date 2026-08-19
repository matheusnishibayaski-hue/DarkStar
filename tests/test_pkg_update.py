"""Testes do atualizador de pacotes Kali (argv fixo)."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient


class TestPkgUpdate(unittest.TestCase):
    def test_update_kali_packages_update_and_upgrade(self):
        from backend.executor import pkg_update

        with (
            patch.object(pkg_update, "_container_running", return_value=(True, "")),
            patch.object(
                pkg_update,
                "_run_docker_streaming",
                side_effect=[
                    (0, "Get:1 http://kali ...\n", ""),
                    (0, "0 upgraded, 0 newly installed.\n", ""),
                ],
            ) as run,
            patch.object(pkg_update, "record_event"),
        ):
            result = pkg_update.update_kali_packages(do_upgrade=True, timeout=120)

        self.assertTrue(result["ok"])
        self.assertEqual(len(result["steps"]), 2)
        self.assertEqual(result["steps"][0]["name"], "update")
        self.assertEqual(result["steps"][1]["name"], "upgrade")
        self.assertEqual(run.call_count, 2)
        first_args = run.call_args_list[0].args[0]
        self.assertEqual(first_args[:4], ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "update"])
        second_args = run.call_args_list[1].args[0]
        self.assertIn("upgrade", second_args)
        self.assertIn("-y", second_args)

    def test_update_only_skips_upgrade(self):
        from backend.executor import pkg_update

        with (
            patch.object(pkg_update, "_container_running", return_value=(True, "")),
            patch.object(
                pkg_update,
                "_run_docker_streaming",
                return_value=(0, "ok\n", ""),
            ) as run,
            patch.object(pkg_update, "record_event"),
        ):
            result = pkg_update.update_kali_packages(do_upgrade=False)

        self.assertTrue(result["ok"])
        self.assertEqual(len(result["steps"]), 1)
        self.assertEqual(run.call_count, 1)

    def test_container_down(self):
        from backend.executor import pkg_update

        with (
            patch.object(
                pkg_update,
                "_container_running",
                return_value=(False, "Container parado"),
            ),
            patch.object(pkg_update, "record_event"),
        ):
            result = pkg_update.update_kali_packages()

        self.assertFalse(result["ok"])
        self.assertIn("parado", result["error"].lower())
        self.assertEqual(result["steps"], [])

    def test_api_requires_elevation(self):
        from backend.main import app

        client = TestClient(app)
        with patch("backend.security.privileges.is_elevated", return_value=False):
            res = client.post("/api/system/tools/update")
        self.assertEqual(res.status_code, 403)

    def test_api_ok_when_elevated(self):
        from backend.main import app

        client = TestClient(app)
        fake = {
            "ok": True,
            "error": "",
            "steps": [{"name": "update", "ok": True, "exit_code": 0}],
            "duration_sec": 1.2,
            "upgrade": True,
        }
        with (
            patch("backend.security.privileges.is_elevated", return_value=True),
            patch(
                "backend.executor.pkg_update.update_kali_packages",
                return_value=fake,
            ),
        ):
            res = client.post("/api/system/tools/update")
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json()["ok"])


if __name__ == "__main__":
    unittest.main()
