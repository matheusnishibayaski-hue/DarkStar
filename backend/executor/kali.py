import re
import subprocess

from backend.config import (
    ALLOWED_TOOLS,
    BLOCKED_PATTERNS,
    COMMAND_TIMEOUT,
    HOST_WIFI_TOOLS,
    KALI_CONTAINER,
    WIFI_COMMAND_TIMEOUT,
    WIFI_TOOLS,
)
from backend.executor.result import ExecutionResult
from backend.executor.wifi_scan import execute_host_wifi


def validate_command(command: str) -> tuple[bool, str]:
    command = command.strip()
    if not command:
        return False, "Comando vazio."

    if len(command) > 500:
        return False, "Comando excede o limite de 500 caracteres."

    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return False, f"Padrão bloqueado detectado: {pattern}"

    parts = command.split()
    binary = parts[0].split("/")[-1]

    if binary not in ALLOWED_TOOLS:
        return False, (
            f"Ferramenta '{binary}' não está na whitelist. "
            f"Permitidas: {', '.join(sorted(ALLOWED_TOOLS))}"
        )

    return True, ""


def _is_wifi_tool(command: str) -> bool:
    binary = command.strip().split()[0].split("/")[-1]
    return binary in WIFI_TOOLS


def execute_in_kali(command: str, reason: str) -> ExecutionResult:
    valid, error = validate_command(command)
    if not valid:
        return ExecutionResult(
            command=command,
            reason=reason,
            stdout="",
            stderr=error,
            exit_code=-1,
            success=False,
            blocked=True,
            block_reason=error,
        )

    binary = command.strip().split()[0].split("/")[-1]
    if binary in HOST_WIFI_TOOLS:
        return execute_host_wifi(command, reason)

    wifi = _is_wifi_tool(command)
    exec_command = command
    if wifi:
        exec_command = f"rfkill unblock all 2>/dev/null; {command}"

    docker_cmd = [
        "docker", "exec",
        "--user", "root",
        KALI_CONTAINER,
        "bash", "-c", exec_command,
    ]

    timeout = WIFI_COMMAND_TIMEOUT if wifi else COMMAND_TIMEOUT

    try:
        proc = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        stdout = proc.stdout[:50000]
        stderr = proc.stderr[:10000]
        return ExecutionResult(
            command=command,
            reason=reason,
            stdout=stdout,
            stderr=stderr,
            exit_code=proc.returncode,
            success=proc.returncode == 0,
        )
    except subprocess.TimeoutExpired:
        limit = WIFI_COMMAND_TIMEOUT if wifi else COMMAND_TIMEOUT
        return ExecutionResult(
            command=command,
            reason=reason,
            stdout="",
            stderr=f"Timeout após {limit}s",
            exit_code=-1,
            success=False,
        )
    except FileNotFoundError:
        return ExecutionResult(
            command=command,
            reason=reason,
            stdout="",
            stderr="Docker não encontrado. Instale o Docker Desktop e inicie o container kali-tools.",
            exit_code=-1,
            success=False,
        )
    except Exception as e:
        return ExecutionResult(
            command=command,
            reason=reason,
            stdout="",
            stderr=str(e),
            exit_code=-1,
            success=False,
        )
