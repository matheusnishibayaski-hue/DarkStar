import shlex
import subprocess

from backend.config import (
    ALLOWED_TOOLS,
    COMMAND_TIMEOUT,
    HOST_WIFI_TOOLS,
    KALI_CONTAINER,
    WIFI_COMMAND_TIMEOUT,
    WIFI_TOOLS,
)
from backend.executor.logs import save_execution_log
from backend.executor.result import ExecutionResult
from backend.executor.wifi_scan import execute_host_wifi

NON_INTERACTIVE_FLAGS: dict[str, list[str]] = {
    "sqlmap": ["--batch"],
    "apt-get": ["-y"],
    "apt": ["-y"],
    "dpkg": ["--force-confdef", "--force-confold"],
    "hydra": ["-I"],
    "nikto": ["-ask", "no"],
    "wpscan": ["--no-update"],
    "ffuf": ["-noninteractive"],
}


def parse_command_string(command: str) -> list[str]:
    command = command.strip()
    if not command:
        return []
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()


def args_to_display(args: list[str]) -> str:
    return " ".join(args)


def validate_command(args: list[str]) -> tuple[bool, str]:
    if not args:
        return False, "Comando vazio."

    binary = args[0].split("/")[-1]
    if binary not in ALLOWED_TOOLS:
        return False, (
            f"Ferramenta '{binary}' não está na whitelist. "
            f"Permitidas: {', '.join(sorted(ALLOWED_TOOLS))}"
        )

    total_len = sum(len(arg) for arg in args)
    if total_len > 500:
        return False, "Comando excede o limite de 500 caracteres."

    for arg in args[1:]:
        if ".." in arg:
            return False, "Path traversal não permitido."

    return True, ""


def apply_non_interactive_flags(args: list[str]) -> list[str]:
    if not args:
        return args

    binary = args[0].split("/")[-1]
    extra = NON_INTERACTIVE_FLAGS.get(binary, [])
    if not extra:
        return list(args)

    result = list(args)
    insert_at = 1
    for flag in extra:
        if flag not in result:
            result.insert(insert_at, flag)
            insert_at += 1
    return result


def _is_wifi_tool(args: list[str]) -> bool:
    if not args:
        return False
    return args[0].split("/")[-1] in WIFI_TOOLS


def _run_docker_vector(args: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    docker_cmd = [
        "docker", "exec",
        "--user", "root",
        KALI_CONTAINER,
        *args,
    ]
    return subprocess.run(
        docker_cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        encoding="utf-8",
        errors="replace",
        stdin=subprocess.DEVNULL,
    )


def execute_kali_command(args: list[str], reason: str) -> ExecutionResult:
    args = apply_non_interactive_flags(list(args))
    command_display = args_to_display(args)
    binary = args[0].split("/")[-1] if args else ""

    valid, error = validate_command(args)
    if not valid:
        return ExecutionResult(
            command=command_display,
            reason=reason,
            stdout="",
            stderr=error,
            exit_code=-1,
            success=False,
            blocked=True,
            block_reason=error,
            tool=binary,
        )

    if binary in HOST_WIFI_TOOLS:
        return execute_host_wifi(command_display, reason)

    wifi = _is_wifi_tool(args)
    timeout = WIFI_COMMAND_TIMEOUT if wifi else COMMAND_TIMEOUT

    try:
        if wifi:
            subprocess.run(
                ["docker", "exec", "--user", "root", KALI_CONTAINER, "rfkill", "unblock", "all"],
                capture_output=True,
                text=True,
                timeout=30,
                stdin=subprocess.DEVNULL,
            )

        proc = _run_docker_vector(args, timeout)
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        log_id = save_execution_log(command_display, reason, stdout, stderr)

        return ExecutionResult(
            command=command_display,
            reason=reason,
            stdout=stdout,
            stderr=stderr,
            exit_code=proc.returncode,
            success=proc.returncode == 0,
            log_file_id=log_id,
            tool=binary,
        )
    except subprocess.TimeoutExpired:
        limit = timeout
        return ExecutionResult(
            command=command_display,
            reason=reason,
            stdout="",
            stderr=f"Timeout após {limit}s",
            exit_code=-1,
            success=False,
            tool=binary,
        )
    except FileNotFoundError:
        return ExecutionResult(
            command=command_display,
            reason=reason,
            stdout="",
            stderr="Docker não encontrado. Instale o Docker Desktop e inicie o container kali-tools.",
            exit_code=-1,
            success=False,
            tool=binary,
        )
    except Exception as e:
        return ExecutionResult(
            command=command_display,
            reason=reason,
            stdout="",
            stderr=str(e),
            exit_code=-1,
            success=False,
            tool=binary,
        )


def execute_in_kali(command: str, reason: str) -> ExecutionResult:
    """Compatibilidade: converte string da IA em argv e executa sem shell."""
    args = parse_command_string(command)
    return execute_kali_command(args, reason)
