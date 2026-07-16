"""Listagem segura de artefatos em backend/outputs (volume /tools/output no Kali)."""

from __future__ import annotations

import mimetypes
from datetime import datetime, timezone
from pathlib import Path

from backend.config import OUTPUTS_DIR

ALLOWED_EXTENSIONS = frozenset(
    {
        ".txt",
        ".log",
        ".json",
        ".xml",
        ".html",
        ".htm",
        ".md",
        ".csv",
        ".tsv",
        ".pcap",
        ".pcapng",
        ".cap",
        ".nmap",
        ".gnmap",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".tgz",
        ".7z",
        ".bz2",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".svg",
        ".py",
        ".sh",
        ".rb",
        ".yml",
        ".yaml",
        ".conf",
        ".cfg",
        ".dat",
        ".bin",
        ".out",
        ".results",
    }
)

MAX_LIST_FILES = 500


def ensure_outputs_dir() -> None:
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)


def _file_kind(suffix: str) -> str:
    ext = suffix.lower()
    if ext in {".pcap", ".pcapng", ".cap"}:
        return "pcap"
    if ext in {".html", ".htm"}:
        return "html"
    if ext == ".json":
        return "json"
    if ext == ".md":
        return "markdown"
    if ext in {".zip", ".tar", ".gz", ".tgz", ".7z", ".bz2"}:
        return "archive"
    if ext in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg"}:
        return "image"
    if ext in {".xml", ".nmap", ".gnmap"}:
        return "scan"
    if ext in {".log", ".txt", ".out"}:
        return "text"
    return "file"


def is_allowed_extension(path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix in ALLOWED_EXTENSIONS:
        return True
    return path.name.lower() in {"report", "output", "results", "readme"}


def resolve_output_file(rel_path: str) -> Path | None:
    if not rel_path or len(rel_path) > 256:
        return None
    if "\\" in rel_path or rel_path.startswith("/"):
        return None
    parts = [p for p in rel_path.split("/") if p and p != "."]
    if not parts or any(p == ".." for p in parts):
        return None

    root = OUTPUTS_DIR.resolve()
    path = root.joinpath(*parts).resolve()
    try:
        if not path.is_relative_to(root):
            return None
    except AttributeError:
        if root not in path.parents and path != root:
            return None
    return path


def list_output_files() -> list[dict]:
    ensure_outputs_dir()
    root = OUTPUTS_DIR.resolve()
    if not root.is_dir():
        return []

    entries: list[dict] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if not is_allowed_extension(path):
            continue
        rel = path.relative_to(root).as_posix()
        stat = path.stat()
        entries.append(
            {
                "name": rel,
                "size": stat.st_size,
                "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                "kind": _file_kind(path.suffix),
                "extension": path.suffix.lower().lstrip("."),
            }
        )
        if len(entries) >= MAX_LIST_FILES:
            break
    return entries


def guess_media_type(path: Path) -> str:
    media_type, _ = mimetypes.guess_type(path.name)
    return media_type or "application/octet-stream"
