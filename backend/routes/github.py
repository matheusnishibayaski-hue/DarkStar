"""Rotas HTTP para integração GitHub (sync)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.integrations.github import GitHubClient, parse_repo_nwo

router = APIRouter(prefix="/api/github", tags=["github"])


class CommentPrRequest(BaseModel):
    repo_url: str = Field(..., min_length=3, max_length=256)
    pr_number: int = Field(..., ge=1)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    title: str = Field(default="DarkStar Security Review", max_length=200)
    target: str = Field(default="", max_length=256)
    risk_profile: str = Field(default="", max_length=32)


class CreateIssueRequest(BaseModel):
    repo_url: str = Field(..., min_length=3, max_length=256)
    finding: dict[str, Any]
    assignee: str | None = Field(default=None, max_length=64)


class UpdateStatusRequest(BaseModel):
    repo_url: str = Field(..., min_length=3, max_length=256)
    commit_sha: str = Field(..., min_length=7, max_length=64)
    state: str = Field(..., max_length=16)
    description: str = Field(default="", max_length=140)
    target_url: str | None = Field(default=None, max_length=512)


def _client_or_501() -> GitHubClient:
    client = GitHubClient()
    if not client.is_available():
        raise HTTPException(
            status_code=501,
            detail="GitHub integration not configured (GITHUB_TOKEN not set)",
        )
    return client


@router.post("/comment-pr")
def comment_on_pr(req: CommentPrRequest):
    client = _client_or_501()
    ok = client.comment_on_pr(
        repo_url=req.repo_url,
        pr_number=req.pr_number,
        findings=req.findings,
        title=req.title,
        target=req.target,
        risk_profile=req.risk_profile,
    )
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to comment on PR")
    return {
        "status": "commented",
        "pr": req.pr_number,
        "findings_count": len(req.findings),
    }


@router.post("/create-issue")
def create_issue(req: CreateIssueRequest):
    client = _client_or_501()
    url = client.create_issue(
        repo_url=req.repo_url,
        finding=req.finding,
        assignee=req.assignee,
    )
    if not url:
        raise HTTPException(status_code=500, detail="Failed to create issue")
    return {
        "status": "created",
        "issue_url": url,
        "finding": (req.finding or {}).get("title", "Unknown"),
    }


@router.post("/update-status")
def update_commit_status(req: UpdateStatusRequest):
    if req.state not in {"pending", "success", "failure", "error"}:
        raise HTTPException(status_code=400, detail="Invalid state")
    client = _client_or_501()
    ok = client.update_commit_status(
        repo_url=req.repo_url,
        commit_sha=req.commit_sha,
        state=req.state,
        description=req.description,
        target_url=req.target_url,
    )
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to update status")
    return {"status": "updated", "state": req.state, "description": req.description}


@router.get("/tree")
def github_tree(repo: str = "", path: str = ""):
    nwo = parse_repo_nwo(repo)
    if not nwo:
        raise HTTPException(status_code=400, detail="repo inválido (use owner/repo)")
    client = GitHubClient.for_browse()
    if not client.is_available():
        raise HTTPException(status_code=501, detail="GitHub client unavailable")
    items = client.list_tree(nwo, path)
    if items is None:
        raise HTTPException(status_code=404, detail="repositório ou caminho não encontrado")
    return {"repo": nwo, "path": path, "items": items}


@router.get("/file")
def github_file(repo: str = "", path: str = ""):
    nwo = parse_repo_nwo(repo)
    if not nwo:
        raise HTTPException(status_code=400, detail="repo inválido (use owner/repo)")
    if not (path or "").strip():
        raise HTTPException(status_code=400, detail="path obrigatório")
    client = GitHubClient.for_browse()
    if not client.is_available():
        raise HTTPException(status_code=501, detail="GitHub client unavailable")
    data = client.read_file(nwo, path)
    if data is None:
        raise HTTPException(status_code=404, detail="arquivo não encontrado")
    return {"repo": nwo, **data}


@router.get("/project")
def github_project(repo: str = ""):
    """Inventário + amostra priorizada (mesmas regras da Pasta local)."""
    nwo = parse_repo_nwo(repo)
    if not nwo:
        raise HTTPException(status_code=400, detail="repo inválido (use owner/repo)")
    client = GitHubClient.for_browse()
    if not client.is_available():
        raise HTTPException(status_code=501, detail="GitHub client unavailable")
    data = client.ingest_project(nwo)
    if data is None:
        raise HTTPException(status_code=404, detail="repositório não encontrado")
    return data


@router.get("/status")
def github_status():
    """Disponibilidade da integração (sem chamar a API)."""
    client = GitHubClient()
    return {"available": client.is_available()}
