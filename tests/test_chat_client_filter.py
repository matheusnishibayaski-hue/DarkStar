"""Conversas filtradas por client_id."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.database import chat_store as cs
from backend.database import db as db_mod


class TestChatSessionsClientFilter(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        db_mod.reset_engine_for_tests()
        self._url = f"sqlite:///{(self.root / 't.db').as_posix()}"
        self.patches = [
            patch.object(db_mod, "DATABASE_URL", ""),
            patch.object(db_mod, "_SQLITE_PATH", self.root / "t.db"),
            patch.object(db_mod, "resolve_database_url", return_value=self._url),
        ]
        for p in self.patches:
            p.start()
        db_mod.reset_engine_for_tests()
        db_mod.init_db()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        db_mod.reset_engine_for_tests()
        self.tmp.cleanup()

    def test_list_filters_by_client(self):
        cs.upsert_chat_session(
            {
                "id": "sess-default-01",
                "title": "padrao",
                "messages": [],
                "client_id": "default",
            }
        )
        cs.upsert_chat_session(
            {
                "id": "sess-empresa-01",
                "title": "empresa",
                "messages": [],
                "client_id": "empresa-de-teste",
            }
        )
        default_rows = cs.list_chat_sessions(client_id="default")
        empresa_rows = cs.list_chat_sessions(client_id="empresa-de-teste")
        self.assertEqual({r["id"] for r in default_rows}, {"sess-default-01"})
        self.assertEqual({r["id"] for r in empresa_rows}, {"sess-empresa-01"})
        all_rows = cs.list_chat_sessions()
        self.assertEqual(len(all_rows), 2)
