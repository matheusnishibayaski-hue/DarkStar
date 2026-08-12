"""Testes da integração GitHub (sem rede)."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from backend.integrations.formatters import CommentStyle, GitHubCommentFormatter, group_by_severity
from backend.integrations.github import GitHubClient, parse_repo_nwo
from fastapi.testclient import TestClient

from tests.auth_patch import patch_chat_api_token

SAMPLE_FINDINGS = [
    {
        "id": "FIND_001",
        "title": "SQL Injection",
        "severity": "critical",
        "evidence": "Error in query",
        "remediation": "Use parameterized queries",
        "host": "app.example.com",
        "tool": "nuclei",
    },
    {
        "id": "FIND_002",
        "title": "XSS",
        "severity": "high",
        "evidence": "script tag",
        "remediation": "Escape output",
        "url": "https://app.example.com/x",
        "tool": "nuclei",
    },
]


class TestFormatters(unittest.TestCase):
    def test_group_and_summary(self):
        grouped = group_by_severity(SAMPLE_FINDINGS)
        self.assertEqual(len(grouped["critical"]), 1)
        self.assertEqual(len(grouped["high"]), 1)
        comment = GitHubCommentFormatter.format(
            SAMPLE_FINDINGS,
            CommentStyle.SUMMARY,
            title="Test Title",
            target="app.example.com",
        )
        self.assertIn("Test Title", comment)
        self.assertIn("SQL Injection", comment)
        self.assertIn("Total issues:** 2", comment)


class TestGitHubClientHelpers(unittest.TestCase):
    def test_parse_repo_urls(self):
        self.assertEqual(parse_repo_nwo("owner/repo"), "owner/repo")
        self.assertEqual(parse_repo_nwo("https://github.com/owner/repo"), "owner/repo")
        self.assertEqual(parse_repo_nwo("https://github.com/owner/repo.git"), "owner/repo")
        self.assertEqual(parse_repo_nwo("git@github.com:owner/repo.git"), "owner/repo")
        self.assertIsNone(parse_repo_nwo(""))

    def test_labels_and_comment(self):
        client = GitHubClient(token="")
        self.assertFalse(client.is_available())
        labels = client.issue_labels(SAMPLE_FINDINGS[0])
        self.assertIn("security", labels)
        self.assertIn("severity/critical", labels)
        self.assertIn("tool/nuclei", labels)
        block = client._format_finding_block(SAMPLE_FINDINGS[0])
        self.assertTrue(any("SQL Injection" in line for line in block))
        comment = client._format_pr_comment(SAMPLE_FINDINGS, "Title")
        self.assertIn("Title", comment)

    def test_comment_on_pr_mocked(self):
        client = GitHubClient(token="x")
        mock_repo = MagicMock()
        mock_pr = MagicMock()
        mock_repo.get_pull.return_value = mock_pr
        with patch.object(client, "get_repo", return_value=mock_repo):
            # force available
            client._client = MagicMock()
            ok = client.comment_on_pr("owner/repo", 1, SAMPLE_FINDINGS)
            self.assertTrue(ok)
            mock_pr.create_issue_comment.assert_called_once()


class TestGitHubRoutes(unittest.TestCase):
    def test_status_and_501(self):
        from backend.main import app

        with patch_chat_api_token(""):
            with patch("backend.config.GITHUB_TOKEN", ""):
                with patch("backend.integrations.github.GITHUB_TOKEN", ""):
                    client = TestClient(app)
                    r = client.get("/api/github/status")
                    self.assertEqual(r.status_code, 200)
                    self.assertFalse(r.json().get("available"))
                    r2 = client.post(
                        "/api/github/comment-pr",
                        json={
                            "repo_url": "o/r",
                            "pr_number": 1,
                            "findings": [],
                        },
                    )
                    self.assertEqual(r2.status_code, 501)


if __name__ == "__main__":
    unittest.main()
