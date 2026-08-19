"""Probe de presença de binários no Kali (command -v) com cache TTL."""

from __future__ import annotations

import logging
import subprocess
import threading
import time
from typing import Any

from backend.config import HOST_WIFI_TOOLS, KALI_CONTAINER

logger = logging.getLogger(__name__)

_TTL_SEC = 600.0
_lock = threading.Lock()
# name -> (available: bool, checked_at: float)
_cache: dict[str, tuple[bool, float]] = {}


def invalidate_tool_presence_cache() -> None:
    with _lock:
        _cache.clear()


def mark_tool_unavailable(name: str) -> None:
    key = (name or "").strip().lower()
    if not key:
        return
    with _lock:
        _cache[key] = (False, time.monotonic())


def mark_tool_available(name: str) -> None:
    key = (name or "").strip().lower()
    if not key:
        return
    with _lock:
        _cache[key] = (True, time.monotonic())


def _cache_get(name: str) -> bool | None:
    with _lock:
        row = _cache.get(name)
    if not row:
        return None
    ok, checked = row
    if time.monotonic() - checked > _TTL_SEC:
        return None
    return ok


def _container_running() -> bool:
    try:
        proc = subprocess.run(
            ["docker", "ps", "--filter", f"name={KALI_CONTAINER}", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=8,
        )
        return proc.returncode == 0 and KALI_CONTAINER in (proc.stdout or "")
    except Exception:
        return False


def _probe_batch_docker(names: list[str]) -> dict[str, bool]:
    """Um docker exec: imprime tool\\t0|1 por linha."""
    if not names:
        return {}
    # script portátil: for each name, command -v
    parts = ["set +e"]
    for n in names:
        safe = n.replace("'", "")
        parts.append(
            f"if command -v '{safe}' >/dev/null 2>&1; then echo '{safe}\\t1'; else echo '{safe}\\t0'; fi"
        )
    script = "; ".join(parts)
    try:
        proc = subprocess.run(
            ["docker", "exec", KALI_CONTAINER, "sh", "-c", script],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception as exc:
        logger.warning("tool_presence_probe_failed: %s", exc)
        return {n: False for n in names}

    out: dict[str, bool] = {n: False for n in names}
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if "\t" not in line:
            continue
        name, flag = line.split("\t", 1)
        out[name.strip().lower()] = flag.strip() == "1"
    return out


def probe_tools(names: list[str] | None = None, *, force: bool = False) -> dict[str, bool]:
    """Retorna {tool: available}. Usa cache; force=True ignora TTL."""
    from backend.config_tools import ALLOWED_TOOLS

    wanted = [str(n).strip().lower() for n in (names or sorted(ALLOWED_TOOLS)) if n]
    wanted = list(dict.fromkeys(wanted))

    result: dict[str, bool] = {}
    need_probe: list[str] = []

    for name in wanted:
        if name in HOST_WIFI_TOOLS:
            # Host-only: disponível no Windows via executor dedicado — marcar True no win32
            import sys

            result[name] = sys.platform == "win32"
            continue
        if not force:
            cached = _cache_get(name)
            if cached is not None:
                result[name] = cached
                continue
        need_probe.append(name)

    if need_probe:
        if not _container_running():
            for n in need_probe:
                result[n] = False
                with _lock:
                    _cache[n] = (False, time.monotonic())
        else:
            probed = _probe_batch_docker(need_probe)
            now = time.monotonic()
            with _lock:
                for n in need_probe:
                    ok = bool(probed.get(n, False))
                    _cache[n] = (ok, now)
                    result[n] = ok

    return result


def filter_available(names: list[str], *, force: bool = False) -> tuple[list[str], list[str]]:
    """(available_ordered, missing)."""
    presence = probe_tools(names, force=force)
    ok: list[str] = []
    missing: list[str] = []
    for n in names:
        key = n.strip().lower()
        if presence.get(key, False):
            ok.append(key)
        else:
            missing.append(key)
    return ok, missing


def presence_summary(names: list[str] | None = None) -> dict[str, Any]:
    presence = probe_tools(names)
    missing = [k for k, v in presence.items() if not v]
    return {
        "tools_probed": len(presence),
        "tools_available": sum(1 for v in presence.values() if v),
        "tools_missing_count": len(missing),
        "tools_missing_sample": missing[:15],
    }


def looks_like_missing_binary(exit_code: int, stderr: str, stdout: str = "") -> bool:
    if exit_code == 127:
        return True
    blob = f"{stderr or ''}\n{stdout or ''}".lower()
    needles = (
        "command not found",
        "not found",
        "no such file or directory",
        "executable file not found",
    )
    return any(n in blob for n in needles)
