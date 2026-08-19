"""Regras de ingest de repositório (espelho de frontend/js/project-ingest.js)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

PROJECT_MAP_NAME = "__project_map.txt"
MAX_CONTENT_FILES = 12
MAX_FILE_BYTES = 200 * 1024
MAX_CONTENT_CHARS = 200_000
MAX_MAP_LINES = 4000
MAX_ATTACHMENTS = MAX_CONTENT_FILES + 1

IGNORE_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        "dist",
        "build",
        "vendor",
        "__pycache__",
        ".next",
        "coverage",
        ".venv",
        "venv",
        "target",
        "out",
        ".turbo",
        ".cache",
        ".idea",
        ".vscode",
        "eggs",
        ".eggs",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
    }
)

IGNORE_EXT = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ico",
        ".svg",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".mp3",
        ".mp4",
        ".wav",
        ".zip",
        ".gz",
        ".tar",
        ".7z",
        ".rar",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bin",
        ".pdf",
        ".pyc",
        ".class",
        ".o",
        ".a",
        ".wasm",
        ".map",
    }
)

HIGH_NAMES = frozenset(
    {
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "requirements.txt",
        "requirements-lock.txt",
        "pyproject.toml",
        "poetry.lock",
        "cargo.toml",
        "go.mod",
        "go.sum",
        "pom.xml",
        "composer.json",
        "composer.lock",
        "gemfile",
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "vercel.json",
        "next.config.js",
        "next.config.mjs",
        "next.config.ts",
        "nuxt.config.ts",
        "nuxt.config.js",
        "vite.config.ts",
        "vite.config.js",
        "tsconfig.json",
        "nginx.conf",
        ".env.example",
        ".env.sample",
        "openapi.yaml",
        "openapi.json",
        "swagger.yaml",
        "swagger.json",
    }
)

SOURCE_EXT = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".rb",
        ".php",
        ".cs",
        ".swift",
        ".c",
        ".cpp",
        ".h",
        ".hpp",
        ".vue",
        ".svelte",
        ".sql",
        ".sh",
        ".ps1",
        ".yml",
        ".yaml",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".json",
        ".md",
        ".html",
        ".css",
        ".scss",
    }
)


def normalize_path(path: str) -> str:
    text = str(path or "").replace("\\", "/").lstrip("./").lstrip("/")
    return text


def path_ignored(path: str) -> bool:
    norm = normalize_path(path)
    parts = [p for p in norm.split("/") if p]
    if not parts:
        return True
    for p in parts[:-1]:
        if p in IGNORE_DIRS:
            return True
    base = parts[-1]
    lower = base.lower()
    dot = lower.rfind(".")
    if dot >= 0 and lower[dot:] in IGNORE_EXT:
        return True
    if lower.endswith(".min.js") or lower.endswith(".min.css"):
        return True
    return False


def score_path(path: str, size: int = 0) -> int:
    norm = normalize_path(path)
    if not norm or path_ignored(norm):
        return -1
    if size > MAX_FILE_BYTES:
        return -1

    parts = norm.split("/")
    base = (parts[-1] or "").lower()
    score = 10

    if base in HIGH_NAMES:
        score += 100
    if base.startswith("dockerfile"):
        score += 90
    if base.startswith("docker-compose"):
        score += 90
    if base.endswith(".env.example") or base.endswith(".env.sample"):
        score += 85
    if "nginx" in base:
        score += 70

    segs = set(parts)
    if segs & {"routes", "api", "auth", "middleware", "controllers", "handlers"}:
        score += 60
    if segs & {"src", "app", "backend", "frontend", "server", "web"}:
        score += 25
    if len(parts) <= 2:
        score += 20

    dot = base.rfind(".")
    ext = base[dot:] if dot >= 0 else ""
    if ext in SOURCE_EXT:
        score += 15

    if segs & {"test", "tests", "__tests__", "spec", "docs", "doc", "examples", "fixtures"}:
        score -= 40
    if base.endswith(".test.js") or base.endswith(".spec.ts") or base.endswith("_test.py"):
        score -= 35
    if base.endswith(".lock") or base in {"yarn.lock", "pnpm-lock.yaml"}:
        score -= 50

    return score


@dataclass
class MapResult:
    text: str
    kept_count: int
    ignored_count: int
    total_seen: int


def build_project_map(
    entries: list[dict[str, Any]], *, max_lines: int = MAX_MAP_LINES
) -> MapResult:
    kept: list[tuple[str, int]] = []
    ignored = 0
    for e in entries:
        path = normalize_path(str(e.get("path") or ""))
        if not path or path_ignored(path):
            ignored += 1
            continue
        kept.append((path, int(e.get("size") or 0)))
    kept.sort(key=lambda x: x[0])
    shown = kept[:max_lines]
    omitted = len(kept) - len(shown)
    lines = [
        f"# Mapa do repositório ({len(kept)} arquivos após filtros; {ignored} ignorados)",
        "# Amostra de conteúdo anexada à parte (arquivos prioritários para pentest).",
        "",
    ]
    for path, size in shown:
        lines.append(f"{path}\t{size}")
    if omitted > 0:
        lines.append(f"… (+{omitted} omitidos do mapa)")
    return MapResult(
        text="\n".join(lines),
        kept_count=len(kept),
        ignored_count=ignored,
        total_seen=len(entries),
    )


def pick_content_paths(
    entries: list[dict[str, Any]], *, limit: int = MAX_CONTENT_FILES
) -> list[dict[str, Any]]:
    scored: list[tuple[int, str, int]] = []
    for e in entries:
        path = normalize_path(str(e.get("path") or ""))
        size = int(e.get("size") or 0)
        sc = score_path(path, size)
        if sc < 0:
            continue
        scored.append((sc, path, size))
    scored.sort(key=lambda t: (-t[0], t[1]))
    picked: list[dict[str, Any]] = []
    seen: set[str] = set()
    for sc, path, size in scored:
        if path in seen:
            continue
        seen.add(path)
        picked.append({"path": path, "size": size, "score": sc})
        if len(picked) >= limit:
            break
    return picked
