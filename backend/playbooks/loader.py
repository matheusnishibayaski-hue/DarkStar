"""Carregamento e execução de playbooks YAML."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from backend.executor.kali import execute_kali_command
from backend.security.scope import validate_autonomous_target, validate_command_scope

PLAYBOOKS_DIR = Path(__file__).resolve().parent


def _normalize_target_for_path(target: str) -> str:
    import re

    v = target.strip().lower()
    v = re.sub(r"^https?://", "", v)
    v = v.split("/")[0].split(":")[0].strip(".")
    v = re.sub(r"[^\w.\-]", "_", v)
    return v[:64] or "target"


def list_playbooks() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for path in sorted(PLAYBOOKS_DIR.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not data.get("id"):
            continue
        items.append(
            {
                "id": data["id"],
                "name": data.get("name", data["id"]),
                "description": data.get("description", ""),
                "steps_count": len(data.get("steps") or []),
            }
        )
    return items


def load_playbook(playbook_id: str) -> dict[str, Any] | None:
    for path in PLAYBOOKS_DIR.glob("*.yaml"):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if data.get("id") == playbook_id:
            return data
    return None


def _expand_args(args: list[str], target: str) -> list[str]:
    safe = _normalize_target_for_path(target)
    return [a.replace("{target}", target).replace("{target_safe}", safe) for a in args]


def run_playbook(
    playbook_id: str, target: str, mission_id: str | None = None, chat_session_id: str | None = None
) -> dict[str, Any]:
    playbook = load_playbook(playbook_id)
    if not playbook:
        raise ValueError(f"Playbook '{playbook_id}' não encontrado.")

    scope_ok, scope_err = validate_autonomous_target(target)
    if not scope_ok:
        raise PermissionError(scope_err)

    steps = playbook.get("steps") or []
    results: list[dict[str, Any]] = []

    for i, step in enumerate(steps, 1):
        tool = step.get("tool", "")
        raw_args = step.get("args") or []
        args = [tool, *_expand_args(list(raw_args), target)]

        scope_cmd_ok, scope_cmd_err = validate_command_scope(args)
        if not scope_cmd_ok:
            results.append(
                {
                    "step": i,
                    "command": " ".join(args),
                    "success": False,
                    "blocked": True,
                    "stderr": scope_cmd_err,
                }
            )
            break

        result = execute_kali_command(
            args,
            reason=f"Playbook {playbook_id} passo {i}",
            execution_id=None,
            chat_session_id=chat_session_id,
        )
        # Alimenta Attack Surface Graph + auto-verify leve
        try:
            from backend.ai.findings import auto_verify_from_execution
            from backend.executor.surface import (
                get_or_create_surface,
                update_surface_from_execution,
            )

            get_or_create_surface(target, mission_id=mission_id or "")
            update_surface_from_execution(
                target,
                command=result.command,
                tool=tool,
                stdout=result.stdout or "",
                stderr=result.stderr or "",
                success=bool(result.success),
                blocked=bool(result.blocked),
                exit_code=int(result.exit_code or 0),
                chat_session_id=chat_session_id,
            )
            auto_verify_from_execution(
                target,
                command=result.command,
                tool=tool,
                stdout=result.stdout or "",
                stderr=result.stderr or "",
                success=bool(result.success),
            )
        except (OSError, ValueError, TypeError, KeyError):
            pass

        results.append(
            {
                "step": i,
                "command": result.command,
                "success": result.success,
                "blocked": result.blocked,
                "exit_code": result.exit_code,
                "log_file_id": result.log_file_id,
                "stderr": (result.stderr or "")[:500],
            }
        )
        if not result.success or result.blocked:
            break

    verify_summary: dict[str, Any] = {}
    # Pipeline PoC ao final (se houve passos OK)
    if any(r.get("success") for r in results):
        try:
            from backend.ai.verify import run_verification_pipeline
            from backend.config import VERIFY_MAX_FINDINGS

            vr = run_verification_pipeline(
                target,
                max_findings=VERIFY_MAX_FINDINGS,
                mission_id=mission_id,
            )
            verify_summary = {
                "confirmed": vr.confirmed,
                "false_positive": vr.false_positive,
                "discarded": vr.discarded,
                "verify_commands_run": vr.verify_commands_run,
            }
        except (OSError, ValueError, TypeError, KeyError, RuntimeError):
            verify_summary = {}

    # Intelligence Hub — best-effort (nunca falha o playbook)
    try:
        from backend.intelligence.hub import try_record_from_surface

        try_record_from_surface(target)
    except Exception:
        pass

    return {
        "playbook_id": playbook_id,
        "target": target,
        "mission_id": mission_id or "",
        "steps_run": len(results),
        "results": results,
        "verify": verify_summary,
    }
