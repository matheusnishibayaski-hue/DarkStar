"""Observabilidade mínima: request/correlation IDs, logs JSON e métricas leves."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

_request_id: ContextVar[str] = ContextVar("request_id", default="")
_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")
_client_ip: ContextVar[str] = ContextVar("client_ip", default="")

_lock = threading.Lock()
_metrics: dict[str, int | float] = {
    "requests_total": 0,
    "errors_total": 0,
    "tool_executions_total": 0,
    "cancellations_total": 0,
    "llm_calls_total": 0,
    "docker_ops_total": 0,
}

_LOGGER_NAME = "chat_ia_kali"
_configured = False


def _redact_secrets(value: str) -> str:
    import re

    value = re.sub(
        r"(?i)(api[_-]?key|token|password|secret|authorization|OPENROUTER_API_KEY|CHAT_API_TOKEN)\s*[:=]\s*\S+",
        r"\1=***",
        value,
    )
    value = re.sub(r"(?i)bearer\s+\S+", "Bearer ***", value)
    value = re.sub(r"(?i)sk-[a-z0-9]{20,}", "sk-***", value)
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "module": record.name,
            "message": _redact_secrets(record.getMessage()),
            "request_id": get_request_id(),
            "correlation_id": get_correlation_id(),
        }
        for key in ("duration_ms", "path", "method", "status_code", "tool", "op"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging() -> None:
    global _configured
    if _configured:
        return
    default_level = "WARNING" if "unittest" in __import__("sys").modules else "INFO"
    level_name = os.getenv("LOG_LEVEL", default_level).upper()
    level = getattr(logging, level_name, logging.INFO)
    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(level)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    logger.propagate = False
    _configured = True


def get_logger() -> logging.Logger:
    configure_logging()
    return logging.getLogger(_LOGGER_NAME)


def new_request_id() -> str:
    return uuid.uuid4().hex[:16]


def set_request_id(value: str) -> None:
    _request_id.set(value or "")


def get_request_id() -> str:
    return _request_id.get()


def set_correlation_id(value: str | None) -> None:
    _correlation_id.set(value or get_request_id())


def get_correlation_id() -> str:
    return _correlation_id.get() or get_request_id()


def set_client_ip(value: str | None) -> None:
    _client_ip.set((value or "").strip()[:64])


def get_client_ip() -> str:
    return _client_ip.get()


def incr(metric: str, amount: int = 1) -> None:
    with _lock:
        current = _metrics.get(metric, 0)
        _metrics[metric] = int(current) + amount


def get_metrics() -> dict[str, Any]:
    with _lock:
        data = dict(_metrics)
    # Memória/CPU: preferir psutil; fallback resource (Unix) ou ctypes (Windows)
    try:
        import psutil  # type: ignore

        proc = psutil.Process()
        data["cpu_percent"] = proc.cpu_percent(interval=None)
        data["memory_mb"] = round(proc.memory_info().rss / (1024 * 1024), 2)
    except Exception:
        try:
            import resource
            import sys

            usage = resource.getrusage(resource.RUSAGE_SELF)
            rss = int(usage.ru_maxrss)
            # Linux: KB; macOS: bytes
            data["memory_mb"] = (
                round(rss / (1024 * 1024), 2) if sys.platform == "darwin" else round(rss / 1024, 2)
            )
            data["ru_maxrss"] = rss
        except Exception:
            try:
                import ctypes
                import sys

                if sys.platform == "win32":

                    class _PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                        _fields_ = [
                            ("cb", ctypes.c_ulong),
                            ("PageFaultCount", ctypes.c_ulong),
                            ("PeakWorkingSetSize", ctypes.c_size_t),
                            ("WorkingSetSize", ctypes.c_size_t),
                            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                            ("PagefileUsage", ctypes.c_size_t),
                            ("PeakPagefileUsage", ctypes.c_size_t),
                        ]

                    counters = _PROCESS_MEMORY_COUNTERS()
                    counters.cb = ctypes.sizeof(counters)
                    handle = ctypes.windll.kernel32.GetCurrentProcess()
                    if ctypes.windll.psapi.GetProcessMemoryInfo(
                        handle, ctypes.byref(counters), counters.cb
                    ):
                        data["memory_mb"] = round(counters.WorkingSetSize / (1024 * 1024), 2)
            except Exception:
                pass
    data["request_id"] = get_request_id()
    data["correlation_id"] = get_correlation_id()
    return data


def log_event(level: str, message: str, **fields: Any) -> None:
    logger = get_logger()
    log_level = getattr(logging, level.upper(), logging.INFO)
    if not logger.isEnabledFor(log_level):
        return
    record = logger.makeRecord(
        logger.name,
        log_level,
        "(observability)",
        0,
        message,
        (),
        None,
    )
    for key, value in fields.items():
        setattr(record, key, value)
    logger.handle(record)


@contextmanager
def timed(op: str, **fields: Any) -> Iterator[None]:
    started = time.perf_counter()
    try:
        yield
    finally:
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        log_event("INFO", f"{op} completed", op=op, duration_ms=duration_ms, **fields)
