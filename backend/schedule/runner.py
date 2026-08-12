"""Ticker em thread + execução de jobs (monitor leve / remind / full hint)."""

from __future__ import annotations

import logging
import threading
from typing import Any

from backend.config import SCHEDULE_ENABLED, SCHEDULE_TICK_SEC
from backend.schedule.store import advance_job, due_jobs

logger = logging.getLogger(__name__)

_stop = threading.Event()
_thread: threading.Thread | None = None


def execute_job(job: dict[str, Any], *, force: bool = False) -> dict[str, Any]:
    """Executa um job e avança next_run."""
    from backend.ai.delta import compute_delta
    from backend.ai.risk_history import previous_score, record_risk_snapshot
    from backend.ai.risk_score import risk_score_for_target
    from backend.alerts.webhook import maybe_alert_delta, send_webhook

    target = str(job.get("target") or "")
    job_type = str(job.get("job_type") or "monitor")
    result: dict[str, Any] = {
        "job_id": job.get("id"),
        "target": target,
        "job_type": job_type,
        "ok": False,
    }

    try:
        if job_type == "remind":
            send_webhook(
                f"[DarkStar] Lembrete: scan recorrente devido para {target} "
                f"(cliente {job.get('client_id')})",
                payload=job,
            )
            result["ok"] = True
            result["action"] = "remind"
        elif job_type == "full":
            # Não dispara Piloto automático em background (evitar corridas).
            # Notifica + marca due; operador/API pode chamar Piloto.
            send_webhook(
                f"[DarkStar] Scan full agendado para {target} — inicie o Piloto "
                f"(perfil {job.get('scan_profile')}/{job.get('risk_profile')}).",
                payload=job,
            )
            result["ok"] = True
            result["action"] = "full_notify"
        else:
            # monitor — nmap leve
            mon = run_light_monitor(target)
            result.update(mon)
            result["ok"] = bool(mon.get("ok"))
            result["action"] = "monitor"

        risk = risk_score_for_target(target) if target else {}
        prev = previous_score(target)
        if risk:
            record_risk_snapshot(target, risk, source=f"schedule:{job_type}")
        delta = compute_delta(target) if target else {}
        alerts = maybe_alert_delta(
            target, delta=delta, risk=risk, previous_score=prev
        )
        result["alerts"] = alerts
        if target and job_type in {"monitor", "full"}:
            try:
                from backend.database.db import record_scan_from_target

                record_scan_from_target(
                    target,
                    risk_profile=str(job.get("risk_profile") or ""),
                    scan_profile=str(job.get("scan_profile") or ""),
                    scan_type=f"schedule:{job_type}",
                    status="completed" if result.get("ok") else "failed",
                )
            except Exception:  # noqa: BLE001
                pass
        advance_job(job, status="ok" if result["ok"] else "error", error="")
    except Exception as exc:  # noqa: BLE001
        logger.exception("schedule_job_failed id=%s", job.get("id"))
        advance_job(job, status="error", error=str(exc))
        result["ok"] = False
        result["error"] = str(exc)[:300]
    return result


def run_light_monitor(target: str) -> dict[str, Any]:
    """Re-scan rápido de portas (nmap -Pn -F) e ingestão no surface."""
    from backend.executor.kali import execute_in_kali
    from backend.executor.surface import get_or_create_surface, update_surface_from_execution

    get_or_create_surface(target)
    cmd = f"nmap -Pn -F --open {target}"
    exec_result = execute_in_kali(cmd, reason="monitor recorrente (portas)")

    stdout = getattr(exec_result, "stdout", "") or ""
    stderr = getattr(exec_result, "stderr", "") or ""
    success = bool(getattr(exec_result, "success", False))
    exit_code = int(getattr(exec_result, "exit_code", 1) or 1)
    blocked = bool(getattr(exec_result, "blocked", False))

    update_surface_from_execution(
        target,
        tool="nmap",
        command=cmd,
        stdout=stdout,
        stderr=stderr,
        success=success,
        blocked=blocked,
        exit_code=exit_code,
    )
    return {
        "ok": success or bool(stdout),
        "command": cmd,
        "exit_code": exit_code,
        "stdout_preview": stdout[:400],
    }


def _tick() -> None:
    while not _stop.wait(SCHEDULE_TICK_SEC):
        if not SCHEDULE_ENABLED:
            continue
        try:
            for job in due_jobs():
                logger.info("schedule_due job=%s target=%s", job.get("id"), job.get("target"))
                execute_job(job)
        except Exception:  # noqa: BLE001
            logger.exception("schedule_tick_failed")


def start_scheduler() -> None:
    global _thread
    if not SCHEDULE_ENABLED:
        logger.info("scheduler_disabled")
        return
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_tick, name="darkstar-scheduler", daemon=True)
    _thread.start()
    logger.info("scheduler_started tick=%ss", SCHEDULE_TICK_SEC)


def stop_scheduler() -> None:
    _stop.set()
