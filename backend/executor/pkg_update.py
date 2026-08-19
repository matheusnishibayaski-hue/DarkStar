"""Atualização automatizada de pacotes no container Kali (apt-get fixo).

Não passa pela whitelist de ferramentas — argv é constante e não aceita input do usuário.
"""

from __future__ import annotations

import subprocess
import time
from typing import Any

from backend.config import KALI_CONTAINER
from backend.executor.kali import _run_docker_streaming
from backend.security.audit import record_event

# Upgrade completo pode demorar; timeout generoso (segundos).
TOOLS_UPDATE_TIMEOUT = 900

_UPDATE_ENV = ["env", "DEBIAN_FRONTEND=noninteractive"]

_APT_UPDATE = [
    *_UPDATE_ENV,
    "apt-get",
    "update",
]

_APT_UPGRADE = [
    *_UPDATE_ENV,
    "apt-get",
    "upgrade",
    "-y",
    "--allow-downgrades",
    "-o",
    "Dpkg::Options::=--force-confdef",
    "-o",
    "Dpkg::Options::=--force-confold",
]


def _container_running() -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["docker", "ps", "--filter", f"name={KALI_CONTAINER}", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode != 0:
            return False, (proc.stderr or "Docker indisponível.").strip()
        if KALI_CONTAINER not in (proc.stdout or ""):
            return False, (
                f"Container '{KALI_CONTAINER}' não está rodando. Execute start.bat ou ./start.sh"
            )
        return True, ""
    except FileNotFoundError:
        return False, "Docker não instalado ou não está no PATH."
    except Exception as e:
        return False, str(e)


def _run_step(name: str, args: list[str], timeout: int) -> dict[str, Any]:
    started = time.time()
    try:
        code, stdout, stderr = _run_docker_streaming(args, timeout=timeout, execution_id=None)
        return {
            "name": name,
            "command": " ".join(args),
            "exit_code": code,
            "ok": code == 0,
            "stdout": (stdout or "")[-8000:],
            "stderr": (stderr or "")[-4000:],
            "duration_sec": round(time.time() - started, 2),
        }
    except subprocess.TimeoutExpired:
        return {
            "name": name,
            "command": " ".join(args),
            "exit_code": -1,
            "ok": False,
            "stdout": "",
            "stderr": f"Timeout após {timeout}s.",
            "duration_sec": round(time.time() - started, 2),
        }
    except InterruptedError as e:
        return {
            "name": name,
            "command": " ".join(args),
            "exit_code": -1,
            "ok": False,
            "stdout": "",
            "stderr": str(e),
            "duration_sec": round(time.time() - started, 2),
        }
    except Exception as e:
        return {
            "name": name,
            "command": " ".join(args),
            "exit_code": -1,
            "ok": False,
            "stdout": "",
            "stderr": str(e),
            "duration_sec": round(time.time() - started, 2),
        }


def update_kali_packages(*, do_upgrade: bool = True, timeout: int | None = None) -> dict[str, Any]:
    """Roda apt-get update (+ upgrade -y) no container Kali.

    Retorna resumo estruturado; nunca aceita argumentos do operador.
    """
    t0 = time.time()
    ok_container, err = _container_running()
    if not ok_container:
        payload = {
            "ok": False,
            "error": err,
            "steps": [],
            "duration_sec": 0.0,
        }
        record_event("tools_update", {"ok": False, "error": err})
        return payload

    limit = int(timeout or TOOLS_UPDATE_TIMEOUT)
    steps: list[dict[str, Any]] = []

    update_step = _run_step("update", list(_APT_UPDATE), timeout=min(limit, 300))
    steps.append(update_step)

    if update_step["ok"] and do_upgrade:
        remaining = max(60, limit - int(update_step["duration_sec"]))
        steps.append(_run_step("upgrade", list(_APT_UPGRADE), timeout=remaining))

    overall_ok = all(s.get("ok") for s in steps) and bool(steps)
    result = {
        "ok": overall_ok,
        "error": ""
        if overall_ok
        else next(
            (s.get("stderr") or "Falha no apt-get" for s in steps if not s.get("ok")),
            "Falha no apt-get",
        ),
        "steps": steps,
        "duration_sec": round(time.time() - t0, 2),
        "upgrade": do_upgrade,
    }
    record_event(
        "tools_update",
        {
            "ok": overall_ok,
            "upgrade": do_upgrade,
            "duration_sec": result["duration_sec"],
            "steps": [{"name": s["name"], "exit_code": s["exit_code"]} for s in steps],
        },
    )
    return result
