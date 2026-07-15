"""Testes do executor Kali com subprocess mockado."""

import unittest
from io import StringIO
from unittest.mock import MagicMock, patch

from backend.security.missions import get_mission_registry


class TestKaliCancelMock(unittest.TestCase):
    def setUp(self):
        registry = get_mission_registry()
        registry._missions.clear()

    def test_cancelled_mission_kills_docker_process(self):
        from backend.executor import kali as kali_mod

        mission_id = "mission-mock-1"
        registry = get_mission_registry()
        registry.register(mission_id)

        mock_proc = MagicMock()
        mock_proc.stdout = StringIO("")
        mock_proc.stderr = StringIO("")
        mock_proc.poll.return_value = None
        mock_proc.wait.return_value = -9

        with patch.object(kali_mod, "KALI_CONTAINER", "kali-test"), patch.object(
            kali_mod.subprocess, "Popen", return_value=mock_proc
        ) as popen_mock:
            registry.cancel(mission_id)
            with self.assertRaises(InterruptedError):
                kali_mod._run_docker_streaming(
                    ["nmap", "-V"],
                    timeout=30,
                    execution_id="exec-mock-1",
                    mission_id=mission_id,
                )

        popen_mock.assert_called_once()
        mock_proc.kill.assert_called()

    def test_process_registered_and_unregistered(self):
        from backend.executor import kali as kali_mod

        mission_id = "mission-mock-2"
        exec_id = "exec-mock-2"
        registry = get_mission_registry()
        registry.register(mission_id)

        mock_proc = MagicMock()
        mock_proc.stdout = StringIO("ok\n")
        mock_proc.stderr = StringIO("")
        mock_proc.poll.side_effect = [None, 0]
        mock_proc.wait.return_value = 0

        with patch.object(kali_mod, "KALI_CONTAINER", "kali-test"), patch.object(
            kali_mod.subprocess, "Popen", return_value=mock_proc
        ):
            code, out, err = kali_mod._run_docker_streaming(
                ["echo", "ok"],
                timeout=30,
                execution_id=exec_id,
                mission_id=mission_id,
            )

        self.assertEqual(code, 0)
        self.assertIn("ok", out)
        ctrl = registry.get(mission_id)
        self.assertIsNotNone(ctrl)
        self.assertEqual(len(ctrl.processes), 0)
        registry.cleanup(mission_id)


if __name__ == "__main__":
    unittest.main()
