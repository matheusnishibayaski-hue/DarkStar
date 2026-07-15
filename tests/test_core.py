"""Testes unitários do core (sem Docker/API externa)."""

import unittest

from backend.ai.healing import healing_prompt, should_attempt_healing
from backend.executor.kali import parse_command_string, validate_command
from backend.executor.recon_db import (
    extract_targets,
    is_recon_target,
    normalize_target,
)


class TestKaliValidation(unittest.TestCase):
    def test_parse_simple_command(self):
        args = parse_command_string("nmap -sV scanme.nmap.org")
        self.assertEqual(args[0], "nmap")
        self.assertIn("scanme.nmap.org", args)

    def test_reject_unknown_binary(self):
        ok, msg = validate_command(["rm", "-rf", "/"])
        self.assertFalse(ok)
        self.assertIn("whitelist", msg.lower())

    def test_reject_path_traversal_in_args(self):
        ok, msg = validate_command(["nmap", "../../../etc/passwd"])
        self.assertFalse(ok)
        self.assertIn("traversal", msg.lower())

    def test_allow_nmap(self):
        ok, _ = validate_command(["nmap", "-sV", "scanme.nmap.org"])
        self.assertTrue(ok)


class TestScopeLock(unittest.TestCase):
    def test_blocks_out_of_scope_command(self):
        import backend.config as cfg
        from backend.security import scope as scope_mod

        with unittest.mock.patch.object(cfg, "ALLOWED_TARGETS", frozenset({"scanme.nmap.org"})):
            with unittest.mock.patch.object(scope_mod, "ALLOWED_TARGETS", frozenset({"scanme.nmap.org"})):
                ok, msg = scope_mod.validate_command_scope(["nmap", "-sV", "evil.com"])
                self.assertFalse(ok)
                self.assertIn("ALLOWED_TARGETS", msg)

    def test_allows_in_scope_command(self):
        import backend.config as cfg
        from backend.security import scope as scope_mod

        with unittest.mock.patch.object(cfg, "ALLOWED_TARGETS", frozenset({"scanme.nmap.org"})):
            with unittest.mock.patch.object(scope_mod, "ALLOWED_TARGETS", frozenset({"scanme.nmap.org"})):
                ok, msg = scope_mod.validate_command_scope(["nmap", "-sV", "scanme.nmap.org"])
                self.assertTrue(ok)
                self.assertEqual(msg, "")

    def test_autonomous_target_validation(self):
        import backend.config as cfg
        from backend.security import scope as scope_mod

        with unittest.mock.patch.object(cfg, "ALLOWED_TARGETS", frozenset({"lab.test"})):
            with unittest.mock.patch.object(scope_mod, "ALLOWED_TARGETS", frozenset({"lab.test"})):
                ok, _ = scope_mod.validate_autonomous_target("lab.test")
                self.assertTrue(ok)
                ok, msg = scope_mod.validate_autonomous_target("other.test")
                self.assertFalse(ok)


class TestReconDb(unittest.TestCase):
    def test_normalize_domain(self):
        self.assertEqual(normalize_target("https://ScanMe.Nmap.org/path"), "scanme.nmap.org")

    def test_extract_targets_filters_examples(self):
        targets = extract_targets("teste em example.com e scanme.nmap.org")
        self.assertNotIn("example.com", targets)
        self.assertIn("scanme.nmap.org", targets)

    def test_is_recon_target_lab_host(self):
        self.assertTrue(is_recon_target("scanme.nmap.org"))
        self.assertFalse(is_recon_target("example.com"))
        self.assertFalse(is_recon_target("localhost"))


class TestHealing(unittest.TestCase):
    class _Exec:
        def __init__(self, success=False, blocked=False, stderr="erro", stdout="", exit_code=1):
            self.success = success
            self.blocked = blocked
            self.stderr = stderr
            self.stdout = stdout
            self.exit_code = exit_code

    def test_should_heal_on_failure(self):
        self.assertTrue(should_attempt_healing(self._Exec(), 0))
        self.assertFalse(should_attempt_healing(self._Exec(), 2))

    def test_no_heal_when_success(self):
        self.assertFalse(should_attempt_healing(self._Exec(success=True), 0))

    def test_healing_prompt_contains_error(self):
        text = healing_prompt(self._Exec(stderr="flag invalid"))
        self.assertIn("flag invalid", text)
        self.assertIn("run_kali_tool", text)


if __name__ == "__main__":
    unittest.main()
