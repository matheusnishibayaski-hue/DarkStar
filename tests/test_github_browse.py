"""Browse GitHub tree/file (mocks, sem rede)."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from backend.integrations.github import GitHubClient
from fastapi.testclient import TestClient

from tests.auth_patch import patch_chat_api_token


def _file_item(*, name="a.py", path="a.py", kind="file", size=3, decoded=b"abc"):
    item = MagicMock()
    item.name = name
    item.path = path
    item.type = kind
    item.size = size
    item.decoded_content = decoded
    return item


class TestGitHubBrowseClient(unittest.TestCase):
    def test_for_browse_anonymous_ok_and_fail(self):
        gh = MagicMock()
        with (
            patch("backend.integrations.github.GITHUB_TOKEN", ""),
            patch("github.Github", return_value=gh, create=True),
        ):
            client = GitHubClient.for_browse()
            self.assertTrue(client.is_available())
        with (
            patch("backend.integrations.github.GITHUB_TOKEN", ""),
            patch("github.Github", side_effect=RuntimeError("x"), create=True),
        ):
            client = GitHubClient.for_browse()
            self.assertFalse(client.is_available())

    def test_for_browse_keeps_token_client(self):
        mock_gh = MagicMock()
        with (
            patch("backend.integrations.github.GITHUB_TOKEN", "tok"),
            patch("github.Auth", create=True) as auth_mod,
            patch("github.Github", return_value=mock_gh, create=True),
        ):
            auth_mod.Token.return_value = "auth"
            client = GitHubClient.for_browse()
            self.assertTrue(client.is_available())

    def test_list_tree_paths(self):
        client = GitHubClient(token="")
        self.assertIsNone(client.list_tree("o/r"))
        repo = MagicMock()
        client._client = MagicMock()
        file_only = _file_item()
        repo.get_contents.return_value = file_only
        with patch.object(client, "get_repo", return_value=repo):
            items = client.list_tree("o/r", "")
            self.assertEqual(items[0]["type"], "file")
            repo.get_contents.return_value = [_file_item(kind="dir", name="src", path="src")]
            dirs = client.list_tree("o/r", "src")
            self.assertEqual(dirs[0]["type"], "dir")
            repo.get_contents.side_effect = RuntimeError("boom")
            self.assertIsNone(client.list_tree("o/r"))

    def test_read_file_paths(self):
        client = GitHubClient(token="")
        self.assertIsNone(client.read_file("o/r", "a.py"))
        repo = MagicMock()
        with patch.object(client, "get_repo", return_value=repo):
            self.assertIsNone(client.read_file("o/r", "  "))
            repo.get_contents.return_value = [_file_item()]
            self.assertIsNone(client.read_file("o/r", "src"))
            repo.get_contents.return_value = _file_item(kind="dir")
            self.assertIsNone(client.read_file("o/r", "src"))
            repo.get_contents.return_value = _file_item(decoded=b"x" * 10)
            data = client.read_file("o/r", "a.py", max_bytes=3)
            self.assertTrue(data["truncated"])
            self.assertEqual(len(data["content"]), 3)
            repo.get_contents.return_value = _file_item(decoded=b"\xff")
            data = client.read_file("o/r", "b.bin")
            self.assertIn("content", data)
            repo.get_contents.side_effect = RuntimeError("nope")
            self.assertIsNone(client.read_file("o/r", "a.py"))


class TestChatModePassThrough(unittest.TestCase):
    def test_api_chat_passes_mode_and_attachments(self):
        from backend.ai.agent import ChatResponse
        from backend.config import RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SEC
        from backend.main import app
        from backend.security.rate_limit import get_rate_limiter

        get_rate_limiter(RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SEC).reset()
        captured = {}

        def fake_chat(*_args, **kwargs):
            captured.update(kwargs)
            return ChatResponse(message="ok", tool_executions=[])

        with patch_chat_api_token(""):
            http = TestClient(app)
            with patch("backend.routes.chat.chat", side_effect=fake_chat):
                r = http.post(
                    "/api/chat",
                    json={
                        "message": "hi there",
                        "chat_mode": "ask",
                        "attachments": [{"name": "a.txt", "content": "x"}],
                    },
                )
            self.assertEqual(r.status_code, 200)
            self.assertEqual(captured.get("chat_mode"), "ask")
            self.assertEqual(captured.get("attachments")[0]["name"], "a.txt")


class TestProjectIngestRules(unittest.TestCase):
    def test_ignore_and_score(self):
        from backend.integrations.project_ingest import (
            build_project_map,
            path_ignored,
            pick_content_paths,
            score_path,
        )

        self.assertTrue(path_ignored("node_modules/x/index.js"))
        self.assertTrue(path_ignored("src/logo.png"))
        self.assertFalse(path_ignored("backend/routes/chat.py"))
        self.assertGreater(score_path("package.json", 100), score_path("readme.md", 100))
        self.assertGreater(
            score_path("backend/routes/auth.py", 100),
            score_path("tests/test_x.py", 100),
        )
        entries = [
            {"path": "node_modules/a/b.js", "size": 10},
            {"path": "package.json", "size": 50},
            {"path": "src/app.ts", "size": 80},
            {"path": "dist/out.js", "size": 90},
            {"path": "backend/api/main.py", "size": 120},
        ]
        m = build_project_map(entries)
        self.assertIn("package.json", m.text)
        self.assertNotIn("node_modules", m.text)
        picks = pick_content_paths(entries, limit=2)
        self.assertEqual(picks[0]["path"], "package.json")
        self.assertLessEqual(len(picks), 2)


class TestGitHubProjectIngest(unittest.TestCase):
    def test_list_recursive_and_ingest(self):
        client = GitHubClient(token="")
        self.assertIsNone(client.list_recursive_tree("o/r"))

        blob = MagicMock()
        blob.type = "blob"
        blob.path = "package.json"
        blob.size = 20
        blob2 = MagicMock()
        blob2.type = "blob"
        blob2.path = "node_modules/x/index.js"
        blob2.size = 5
        blob3 = MagicMock()
        blob3.type = "tree"
        blob3.path = "src"
        blob3.size = 0
        tree = MagicMock()
        tree.tree = [blob, blob2, blob3]
        branch = MagicMock()
        branch.commit.sha = "abc"
        repo = MagicMock()
        repo.default_branch = "main"
        repo.get_branch.return_value = branch
        repo.get_git_tree.return_value = tree
        client._client = MagicMock()
        with patch.object(client, "get_repo", return_value=repo):
            items = client.list_recursive_tree("o/r")
            self.assertEqual(len(items), 2)
            self.assertEqual(items[0]["path"], "package.json")

            with patch.object(
                client,
                "read_file",
                return_value={"path": "package.json", "content": "{}", "truncated": False},
            ):
                data = client.ingest_project("o/r")
                self.assertIsNotNone(data)
                self.assertIn("package.json", data["map_text"])
                self.assertEqual(data["files"][0]["path"], "package.json")
                self.assertEqual(data["stats"]["attached"], 1)

        repo.get_git_tree.side_effect = RuntimeError("boom")
        with patch.object(client, "get_repo", return_value=repo):
            self.assertIsNone(client.list_recursive_tree("o/r"))

    def test_project_route(self):
        from backend.main import app

        with patch_chat_api_token(""):
            http = TestClient(app)
            self.assertEqual(http.get("/api/github/project?repo=bad").status_code, 400)
            browse = MagicMock()
            with patch("backend.routes.github.GitHubClient.for_browse", return_value=browse):
                browse.is_available.return_value = False
                self.assertEqual(http.get("/api/github/project?repo=o/r").status_code, 501)
                browse.is_available.return_value = True
                browse.ingest_project.return_value = None
                self.assertEqual(http.get("/api/github/project?repo=o/r").status_code, 404)
                browse.ingest_project.return_value = {
                    "repo": "o/r",
                    "map_name": "__project_map.txt",
                    "map_text": "# map",
                    "files": [{"path": "a.py", "content": "x", "truncated": False}],
                    "stats": {"total_seen": 1, "kept": 1, "ignored": 0, "attached": 1},
                }
                ok = http.get("/api/github/project?repo=o/r")
                self.assertEqual(ok.status_code, 200)
                self.assertEqual(ok.json()["files"][0]["path"], "a.py")


class TestApplyAttachmentsMap(unittest.TestCase):
    def test_map_prefix_and_cap(self):
        from backend.ai.agent import _apply_attachments

        out = _apply_attachments(
            "scan",
            [
                {"name": "__project_map.txt", "content": "pkg\t1"},
                {"name": "a.py", "content": "print(1)"},
            ],
        )
        self.assertIn("[Mapa do repositório", out)
        self.assertIn("--- arquivo: a.py ---", out)


class TestGitHubBrowseRoutes(unittest.TestCase):
    def test_tree_and_file_routes(self):
        from backend.main import app

        with patch_chat_api_token(""):
            http = TestClient(app)
            self.assertEqual(http.get("/api/github/tree?repo=bad").status_code, 400)
            self.assertEqual(http.get("/api/github/file?repo=o/r").status_code, 400)
            self.assertEqual(http.get("/api/github/file?repo=bad&path=a").status_code, 400)
            browse = MagicMock()
            with patch("backend.routes.github.GitHubClient.for_browse", return_value=browse):
                browse.is_available.return_value = False
                self.assertEqual(http.get("/api/github/tree?repo=o/r").status_code, 501)
                self.assertEqual(http.get("/api/github/file?repo=o/r&path=a.py").status_code, 501)
                browse.is_available.return_value = True
                browse.list_tree.return_value = None
                self.assertEqual(http.get("/api/github/tree?repo=o/r").status_code, 404)
                browse.list_tree.return_value = [{"name": "a.py", "path": "a.py", "type": "file"}]
                ok = http.get("/api/github/tree?repo=o/r")
                self.assertEqual(ok.status_code, 200)
                self.assertEqual(len(ok.json()["items"]), 1)
                browse.read_file.return_value = None
                self.assertEqual(http.get("/api/github/file?repo=o/r&path=a.py").status_code, 404)
                browse.read_file.return_value = {
                    "path": "a.py",
                    "content": "print(1)",
                    "truncated": False,
                }
                f = http.get("/api/github/file?repo=o/r&path=a.py")
                self.assertEqual(f.status_code, 200)
                self.assertEqual(f.json()["content"], "print(1)")


if __name__ == "__main__":
    unittest.main()
