"""HTTP(S)-only urlopen wrapper."""

from __future__ import annotations

import unittest
import urllib.request
from unittest.mock import MagicMock, patch

from backend.security.http_client import http_urlopen


class TestHttpUrlopen(unittest.TestCase):
    def test_rejects_file_scheme(self):
        req = urllib.request.Request("file:///tmp/x")
        with self.assertRaises(ValueError):
            http_urlopen(req, timeout=1)

    def test_https_ok(self):
        req = urllib.request.Request("https://example.com/hook")
        with patch("urllib.request.urlopen", return_value=MagicMock()) as mocked:
            http_urlopen(req, timeout=2)
        mocked.assert_called_once()
