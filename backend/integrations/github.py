"""Cliente sync GitHub (PyGithub) — PR comments, issues, commit status."""

from __future__ import annotations

import logging
import re
from typing import Any

from backend.config import GITHUB_TOKEN
from backend.integrations.formatters import (
    CommentStyle,
    GitHubCommentFormatter,
    group_by_severity,
)
from backend.security.audit import record_event

logger = logging.getLogger(__name__)


def parse_repo_nwo(repo_url: str) -> str | None:
    """Normaliza owner/repo a partir de URL ou NWO."""
    raw = (repo_url or "").strip()
    if not raw:
        return None
    if raw.startswith("git@"):
        raw = raw.replace("git@github.com:", "").replace(".git", "")
    elif "github.com" in raw:
        raw = (
            raw.replace("https://github.com/", "")
            .replace("http://github.com/", "")
            .replace(".git", "")
            .strip("/")
        )
    parts = [p for p in raw.split("/") if p]
    if len(parts) < 2:
        return None
    return f"{parts[0]}/{parts[1]}"


def parse_pr_ref(value: str) -> tuple[str | None, int | None]:
    """Aceita owner/repo#123 ou só #123 (repo None)."""
    text = (value or "").strip()
    m = re.match(r"^(?:([^#\s]+))?#(\d+)$", text)
    if not m:
        return None, None
    repo = m.group(1)
    return repo, int(m.group(2))


class GitHubClient:
    """Cliente síncrono. Sem token = no-op (is_available False)."""

    def __init__(self, token: str | None = None) -> None:
        self.token = (token if token is not None else GITHUB_TOKEN) or ""
        self._client = None
        if self.token:
            try:
                from github import Auth, Github

                auth = Auth.Token(self.token)
                self._client = Github(auth=auth)
            except Exception as exc:  # noqa: BLE001
                logger.warning("github_client_init_failed: %s", exc)
                self._client = None

    def is_available(self) -> bool:
        return self._client is not None

    @classmethod
    def for_browse(cls) -> GitHubClient:
        inst = cls()
        if inst._client is not None:
            return inst
        try:
            from github import Github

            inst._client = Github()
        except Exception as exc:  # noqa: BLE001
            logger.warning("github_browse_init_failed: %s", exc)
        return inst

    def list_tree(self, repo_url: str, path: str = "") -> list[dict[str, Any]] | None:
        repo = self.get_repo(repo_url)
        if not repo:
            return None
        try:
            contents = repo.get_contents(path or "")
            if not isinstance(contents, list):
                contents = [contents]
            items: list[dict[str, Any]] = []
            for item in contents:
                kind = "dir" if getattr(item, "type", "") == "dir" else "file"
                items.append(
                    {
                        "name": str(getattr(item, "name", "") or ""),
                        "path": str(getattr(item, "path", "") or ""),
                        "type": kind,
                        "size": int(getattr(item, "size", 0) or 0),
                    }
                )
            return items
        except Exception as exc:  # noqa: BLE001
            logger.error("github_list_tree_failed: %s", exc)
            return None

    def list_recursive_tree(self, repo_url: str) -> list[dict[str, Any]] | None:
        """Lista arquivos do repo via Git Trees API (recursive=1)."""
        repo = self.get_repo(repo_url)
        if not repo:
            return None
        try:
            branch = repo.get_branch(repo.default_branch)
            sha = branch.commit.sha
            tree = repo.get_git_tree(sha, recursive=True)
            items: list[dict[str, Any]] = []
            for entry in getattr(tree, "tree", []) or []:
                if getattr(entry, "type", "") != "blob":
                    continue
                items.append(
                    {
                        "name": str(getattr(entry, "path", "") or "").rsplit("/", 1)[-1],
                        "path": str(getattr(entry, "path", "") or ""),
                        "type": "file",
                        "size": int(getattr(entry, "size", 0) or 0),
                    }
                )
            return items
        except Exception as exc:  # noqa: BLE001
            logger.error("github_list_recursive_tree_failed: %s", exc)
            return None

    def ingest_project(self, repo_url: str) -> dict[str, Any] | None:
        """Mapa + amostra priorizada (mesmas regras da Pasta local)."""
        from backend.integrations.project_ingest import (
            MAX_CONTENT_CHARS,
            MAX_FILE_BYTES,
            PROJECT_MAP_NAME,
            build_project_map,
            pick_content_paths,
        )

        entries = self.list_recursive_tree(repo_url)
        if entries is None:
            return None
        proj_map = build_project_map(entries)
        picks = pick_content_paths(entries)
        files_out: list[dict[str, Any]] = []
        for pick in picks:
            path = pick["path"]
            size = int(pick.get("size") or 0)
            if size > MAX_FILE_BYTES:
                continue
            data = self.read_file(repo_url, path, max_bytes=MAX_FILE_BYTES)
            if not data or not data.get("content"):
                continue
            content = str(data["content"])[:MAX_CONTENT_CHARS]
            files_out.append(
                {
                    "path": data.get("path") or path,
                    "content": content,
                    "truncated": bool(data.get("truncated")),
                }
            )
        return {
            "repo": parse_repo_nwo(repo_url) or repo_url,
            "map_name": PROJECT_MAP_NAME,
            "map_text": proj_map.text[:MAX_CONTENT_CHARS],
            "files": files_out,
            "stats": {
                "total_seen": proj_map.total_seen,
                "kept": proj_map.kept_count,
                "ignored": proj_map.ignored_count,
                "attached": len(files_out),
            },
        }

    def read_file(self, repo_url: str, path: str, max_bytes: int = 200000) -> dict[str, Any] | None:
        repo = self.get_repo(repo_url)
        if not repo or not (path or "").strip():
            return None
        try:
            content = repo.get_contents(path)
            if isinstance(content, list):
                return None
            if getattr(content, "type", "") == "dir":
                return None
            raw = content.decoded_content or b""
            truncated = len(raw) > max_bytes
            if truncated:
                raw = raw[:max_bytes]
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = raw.decode("utf-8", errors="replace")
            return {
                "path": str(getattr(content, "path", path) or path),
                "content": text,
                "truncated": truncated,
            }
        except Exception as exc:  # noqa: BLE001
            logger.error("github_read_file_failed: %s", exc)
            return None

    def get_repo(self, repo_url: str):
        if not self._client:
            return None
        nwo = parse_repo_nwo(repo_url)
        if not nwo:
            return None
        try:
            return self._client.get_repo(nwo)
        except Exception as exc:  # noqa: BLE001
            logger.error("github_get_repo_failed: %s", exc)
            return None

    def comment_on_pr(
        self,
        repo_url: str,
        pr_number: int,
        findings: list[dict[str, Any]],
        title: str = "DarkStar Security Review",
        *,
        target: str = "",
        risk_profile: str = "",
        add_labels: bool = True,
    ) -> bool:
        try:
            repo = self.get_repo(repo_url)
            if not repo:
                return False
            pr = repo.get_pull(int(pr_number))
            body = GitHubCommentFormatter.format(
                findings,
                CommentStyle.SUMMARY,
                title=title,
                target=target,
                risk_profile=risk_profile,
            )
            pr.create_issue_comment(body)
            if add_labels:
                self._add_severity_labels(pr, findings)
            record_event(
                "github_pr_comment",
                {"repo": parse_repo_nwo(repo_url), "pr": pr_number, "count": len(findings)},
            )
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("github_comment_pr_failed: %s", exc)
            record_event("github_pr_comment_failed", {"error": str(exc)[:200]})
            return False

    def create_issue(
        self,
        repo_url: str,
        finding: dict[str, Any],
        assignee: str | None = None,
    ) -> str | None:
        try:
            repo = self.get_repo(repo_url)
            if not repo:
                return None
            severity = str(finding.get("severity") or "unknown").upper()
            title = f"[{severity}] {finding.get('title') or 'Security issue'}"
            body = self._format_issue_body(finding)
            labels = self.issue_labels(finding)
            kwargs: dict[str, Any] = {"title": title[:256], "body": body, "labels": labels}
            if assignee:
                kwargs["assignee"] = assignee
            issue = repo.create_issue(**kwargs)
            record_event(
                "github_issue_created",
                {"repo": parse_repo_nwo(repo_url), "url": issue.html_url},
            )
            return issue.html_url
        except Exception as exc:  # noqa: BLE001
            logger.error("github_create_issue_failed: %s", exc)
            record_event("github_issue_failed", {"error": str(exc)[:200]})
            return None

    def update_commit_status(
        self,
        repo_url: str,
        commit_sha: str,
        state: str,
        description: str,
        context: str = "DarkStar Security",
        target_url: str | None = None,
    ) -> bool:
        if state not in {"pending", "success", "failure", "error"}:
            return False
        try:
            repo = self.get_repo(repo_url)
            if not repo:
                return False
            commit = repo.get_commit(commit_sha)
            commit.create_status(
                state=state,
                description=(description or "")[:140],
                context=context,
                target_url=target_url,
            )
            record_event(
                "github_commit_status",
                {"repo": parse_repo_nwo(repo_url), "sha": commit_sha[:12], "state": state},
            )
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("github_status_failed: %s", exc)
            return False

    def issue_labels(self, finding: dict[str, Any]) -> list[str]:
        labels = ["security", "darkstar"]
        severity = str(finding.get("severity") or "low").lower()
        if severity in {"critical", "high", "medium", "low"}:
            labels.append(f"severity/{severity}")
        tool = str(finding.get("tool") or "").strip().lower()
        if tool and re.match(r"^[a-z0-9._-]{1,32}$", tool):
            labels.append(f"tool/{tool}")
        return labels

    def _add_severity_labels(self, pr: Any, findings: list[dict[str, Any]]) -> None:
        labels: set[str] = set()
        for finding in findings:
            severity = str(finding.get("severity") or "").lower()
            if severity == "critical":
                labels.add("severity/critical")
            elif severity == "high":
                labels.add("severity/high")
        if not labels:
            return
        try:
            pr.add_to_labels(*sorted(labels))
        except Exception as exc:  # noqa: BLE001
            logger.warning("github_labels_failed: %s", exc)

    def _format_issue_body(self, finding: dict[str, Any]) -> str:
        title = finding.get("title") or "Security issue"
        severity = str(finding.get("severity") or "unknown").upper()
        evidence = finding.get("evidence") or "N/A"
        rem = finding.get("remediation") or finding.get("remediation_title") or "N/A"
        tool = finding.get("tool") or "N/A"
        host = finding.get("host") or finding.get("url") or finding.get("matched_at") or "N/A"
        cmd = finding.get("command") or finding.get("command_used") or "N/A"
        return (
            f"## {title}\n\n"
            f"**Severity:** {severity}\n\n"
            f"### Evidence\n```\n{evidence}\n```\n\n"
            f"### Remediation\n{rem}\n\n"
            f"### Technical\n"
            f"- Tool: `{tool}`\n"
            f"- Host/URL: `{host}`\n"
            f"- Command: `{cmd}`\n\n"
            f"---\n*Reported by DarkStar Security Scanner*\n"
        )

    # Compat helpers used by tests
    def _group_by_severity(self, findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        return group_by_severity(findings)

    def _format_pr_comment(self, findings: list[dict[str, Any]], title: str) -> str:
        return GitHubCommentFormatter.format(findings, CommentStyle.SUMMARY, title=title)

    def _format_finding_block(self, finding: dict[str, Any]) -> list[str]:
        from backend.integrations.formatters import format_finding_block

        return format_finding_block(finding)

    def _get_issue_labels(self, finding: dict[str, Any]) -> list[str]:
        return self.issue_labels(finding)
