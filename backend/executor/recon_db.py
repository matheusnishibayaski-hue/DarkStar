"""Banco local de reconhecimento por alvo (JSON em backend/recon/)."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from backend.config import RECON_DIR, RECON_TTL_DAYS

RECON_DIR.mkdir(parents=True, exist_ok=True)

_DOMAIN_RE = re.compile(
    r"\b(?:https?://)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
    re.I,
)
_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
_PORT_RE = re.compile(r"(\d+/tcp\s+open\s+\S+(?:\s+\S+)*)", re.I)
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)
_SEV_RE = re.compile(r"\[(critical|high|medium|low|info)\][^\n]*", re.I)

# Domínios genéricos / exemplos — não persistir recon
IGNORED_RECON_TARGETS = frozenset(
    {
        "example.com",
        "example.org",
        "example.net",
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "google.com",
        "github.com",
        "openrouter.ai",
        "aistudio.google.com",
        "docker.com",
        "wikipedia.org",
    }
)


def is_recon_target(alvo: str) -> bool:
    normalized = normalize_target(alvo)
    if not normalized or normalized == "unknown":
        return False
    if normalized in IGNORED_RECON_TARGETS:
        return False
    if normalized.endswith(".local"):
        return False
    return True


def normalize_target(alvo: str) -> str:
    value = alvo.strip().lower()
    value = re.sub(r"^https?://", "", value)
    value = value.split("/")[0].split(":")[0].strip(".")
    value = re.sub(r"[^\w.\-]", "_", value)
    return value[:128] or "unknown"


def _path_for(alvo: str) -> Path:
    return RECON_DIR / f"{normalize_target(alvo)}.json"


def extract_targets(*texts: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for text in texts:
        if not text:
            continue
        for pattern in (_DOMAIN_RE, _IP_RE):
            for match in pattern.finditer(text):
                raw = match.group(0)
                target = normalize_target(raw)
                if not is_recon_target(target):
                    continue
                if target not in seen:
                    seen.add(target)
                    found.append(target)
    return found


def _parse_updated_at(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _is_recon_expired(data: dict[str, Any]) -> bool:
    if RECON_TTL_DAYS <= 0:
        return False
    updated = _parse_updated_at(str(data.get("updated_at", "")))
    if not updated:
        return False
    return datetime.now(timezone.utc) - updated > timedelta(days=RECON_TTL_DAYS)


def get_recon_data(alvo: str) -> dict[str, Any]:
    path = _path_for(alvo)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    if _is_recon_expired(data):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        return {}
    return data


def save_recon_data(alvo: str, chave: str, valor: Any) -> dict[str, Any]:
    path = _path_for(alvo)
    data = get_recon_data(alvo)
    data["target"] = normalize_target(alvo)
    data["updated_at"] = datetime.now(timezone.utc).isoformat()

    if isinstance(valor, list) and isinstance(data.get(chave), list):
        merged = list(dict.fromkeys([*data[chave], *valor]))
        data[chave] = merged
    elif isinstance(valor, dict) and isinstance(data.get(chave), dict):
        data[chave] = {**data[chave], **valor}
    else:
        data[chave] = valor

    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return data


def merge_recon_update(alvo: str, patch: dict[str, Any]) -> dict[str, Any]:
    for key, value in patch.items():
        save_recon_data(alvo, key, value)
    return get_recon_data(alvo)


def extract_recon_from_output(stdout: str, stderr: str, tool: str = "") -> dict[str, Any]:
    output = "\n".join(filter(None, [stdout, stderr]))
    patch: dict[str, Any] = {
        "last_tool": tool,
        "last_scan_at": datetime.now(timezone.utc).isoformat(),
    }

    ports = list(dict.fromkeys(_PORT_RE.findall(output)))
    if ports:
        patch["open_ports"] = ports

    cves = list(dict.fromkeys(m.upper() for m in _CVE_RE.findall(output)))
    if cves:
        patch["cves"] = cves

    findings = []
    for match in _SEV_RE.finditer(output):
        line = match.group(0).strip()
        if line not in findings:
            findings.append(line)
    if findings:
        patch["vulnerabilities"] = findings[:50]

    return patch


def build_recon_context(targets: list[str]) -> str:
    if not targets:
        return ""

    blocks: list[str] = []
    for target in targets:
        data = get_recon_data(target)
        if not data:
            continue
        compact = {k: v for k, v in data.items() if k not in ("target",) and v}
        if not compact:
            continue
        blocks.append(
            f"[CONTEXTO DE RECONHECIMENTO ANTERIOR PARA O ALVO {target}]:\n"
            f"{json.dumps(compact, ensure_ascii=False, indent=2)}"
        )

    return "\n\n".join(blocks)


def list_recon_summaries() -> list[dict[str, Any]]:
    """Lista alvos com recon persistido (não expirado)."""
    summaries: list[dict[str, Any]] = []
    if not RECON_DIR.is_dir():
        return summaries

    for path in RECON_DIR.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if _is_recon_expired(data):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
            continue
        target = str(data.get("target") or path.stem)
        summaries.append(
            {
                "target": target,
                "updated_at": data.get("updated_at"),
                "last_tool": data.get("last_tool"),
                "open_ports_count": len(data.get("open_ports") or []),
                "cves_count": len(data.get("cves") or []),
                "vulnerabilities_count": len(data.get("vulnerabilities") or []),
            }
        )

    summaries.sort(key=lambda x: str(x.get("updated_at") or ""), reverse=True)
    return summaries
