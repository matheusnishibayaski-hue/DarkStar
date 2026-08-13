"""urllib HTTP(S) only — evita file: e esquemas custom (bandit B310)."""

from __future__ import annotations

import urllib.parse
import urllib.request
from typing import Any


def http_urlopen(req: urllib.request.Request, timeout: float) -> Any:
    url = getattr(req, "full_url", None) or str(req)
    scheme = urllib.parse.urlparse(str(url)).scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("URL scheme not allowed")
    return urllib.request.urlopen(req, timeout=timeout)  # nosec B310
