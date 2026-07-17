"""Extratores nmap/nikto → Attack Surface + sync recon."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.executor import recon_db as recon_mod
from backend.executor import surface as surface_mod
from backend.executor.recon_db import is_recon_target, sync_recon_counts_from_surface
from backend.executor.surface import (
    load_surface,
    repair_surface_from_stored_output,
    update_surface_from_execution,
)


NMAP_HTTPONLY = """
Nmap scan report for lab.test
80/tcp  open  http
|_http-server-header: Microsoft-IIS/10.0
| http-cookie-flags:
|   /:
|     ASPSESSIONIDABC:
|_      httponly flag not set
443/tcp open  https
"""

NIKTO_OUT = """
+ Target IP:          1.2.3.4
+ The anti-clickjacking X-Frame-Options header is not present.
+ OSVDB-3092: /admin/: This might be interesting
"""


class TestToolFindingsExtract(unittest.TestCase):
    def test_nmap_httponly_and_banner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with (
                patch.object(surface_mod, "SURFACE_DIR", root / "surface"),
                patch.object(recon_mod, "RECON_DIR", root / "recon"),
            ):
                (root / "surface").mkdir()
                (root / "recon").mkdir()
                data = update_surface_from_execution(
                    "lab.test",
                    command="nmap -sV lab.test",
                    tool="nmap",
                    stdout=NMAP_HTTPONLY,
                    stderr="",
                    success=True,
                    blocked=False,
                )
                titles = [f["title"] for f in data["findings"]]
                self.assertTrue(any("HttpOnly" in t for t in titles))
                self.assertTrue(any("IIS" in t or "banner" in t.lower() for t in titles))
                recon = recon_mod.get_recon_data("lab.test")
                self.assertGreaterEqual(len(recon.get("vulnerabilities") or []), 1)

    def test_nikto_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(surface_mod, "SURFACE_DIR", root):
                data = update_surface_from_execution(
                    "nikto.test",
                    command="nikto -h nikto.test",
                    tool="nikto",
                    stdout=NIKTO_OUT,
                    stderr="",
                    success=True,
                    blocked=False,
                )
                titles = " ".join(f["title"] for f in data["findings"]).lower()
                self.assertIn("x-frame", titles)
                self.assertIn("/admin", titles)

    def test_repair_from_recon_blob(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with (
                patch.object(surface_mod, "SURFACE_DIR", root / "surface"),
                patch.object(recon_mod, "RECON_DIR", root / "recon"),
            ):
                (root / "surface").mkdir()
                (root / "recon").mkdir()
                # surface vazio + recon com blob nmap
                surface_mod.get_or_create_surface("old.test")
                recon_mod.merge_recon_update(
                    "old.test",
                    {"open_ports": [NMAP_HTTPONLY], "last_tool": "nmap"},
                )
                repaired = repair_surface_from_stored_output("old.test")
                self.assertTrue(repaired.get("findings"))
                sync_recon_counts_from_surface("old.test", repaired)
                recon = recon_mod.get_recon_data("old.test")
                self.assertGreater(len(recon.get("vulnerabilities") or []), 0)

    def test_rejects_filelike_hosts(self):
        self.assertFalse(is_recon_target("bootstrap.min.css"))
        self.assertFalse(is_recon_target("jquery.min.js"))
        self.assertFalse(is_recon_target("window.location.href"))
        self.assertTrue(is_recon_target("korbil.com.br"))


if __name__ == "__main__":
    unittest.main()
