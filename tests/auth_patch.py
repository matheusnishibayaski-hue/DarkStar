"""Helper para mockar CHAT_API_TOKEN nos módulos que o importam."""

from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import patch

_AUTH_TARGETS = (
    "backend.config.CHAT_API_TOKEN",
    "backend.deps.CHAT_API_TOKEN",
    "backend.middleware.CHAT_API_TOKEN",
    "backend.routes.auth.CHAT_API_TOKEN",
)


@contextmanager
def patch_chat_api_token(value: str):
    patches = [patch(t, value) for t in _AUTH_TARGETS]
    for p in patches:
        p.start()
    try:
        yield
    finally:
        for p in patches:
            p.stop()
