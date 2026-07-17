import shlex
import subprocess
import threading
import time
from collections.abc import Generator
from queue import Empty, Queue
from typing import Any

from backend.config import (
    ALLOWED_TOOLS,
    COMMAND_TIMEOUT,
    HOST_WIFI_TOOLS,
    KALI_CONTAINER,
    WIFI_COMMAND_TIMEOUT,
    WIFI_TOOLS,
)
from backend.executor.logs import new_log_id, save_execution_log
from backend.executor.recon_db import extract_targets
from backend.executor.result import ExecutionResult
from backend.executor.stream_hub import get_stream_hub
from backend.executor.wifi_scan import execute_host_wifi
from backend.observability import get_client_ip, incr, timed
from backend.security.audit import record_tool_execution
from backend.security.missions import get_mission_registry
from backend.security.scope import validate_command_scope

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


def _audit_result(
    result: ExecutionResult,
    args: list[str],
    reason: str,
    mission_id: str | None = None,
) -> None:
    targets = extract_targets(" ".join(args)) if args else []
    record_tool_execution(
        command=result.command,
        tool=result.tool,
        targets=targets,
        success=result.success,
        blocked=result.blocked,
        exit_code=result.exit_code,
        log_file_id=result.log_file_id or "",
        mission_id=mission_id,
        reason=reason,
        client_ip=get_client_ip() or None,
    )


def _finalize_stream_result(
    *,
    result: ExecutionResult,
    args: list[str],
    reason: str,
    mission_id: str | None,
    execution_id: str | None,
    hub,
    save_log: bool = False,
    chat_session_id: str | None = None,
) -> dict[str, Any]:
    """Fecha hub SSE, persiste log opcional e registra auditoria."""
    if save_log:
        save_execution_log(
            result.command,
            reason,
            result.stdout,
            result.stderr,
            log_id=result.log_file_id or None,
            chat_session_id=chat_session_id,
        )
    if execution_id:
        hub.finish(
            execution_id,
            exit_code=result.exit_code,
            success=result.success,
            blocked=result.blocked,
        )
        hub.cleanup(execution_id)
    _audit_result(result, args, reason, mission_id)
    return {"type": "done", "result": result}


def _emit_line(
    execution_id: str | None,
    stream_name: str,
    text: str,
) -> dict[str, Any]:
    if execution_id:
        get_stream_hub().push_line(execution_id, stream_name, text)
    return {"type": "line", "stream": stream_name, "text": text}


def _stream_text_lines(
    execution_id: str | None,
    stream_name: str,
    text: str,
) -> Generator[dict[str, Any], None, None]:
    for line in text.splitlines():
        yield _emit_line(execution_id, stream_name, line)


def _run_docker_streaming(
    args: list[str],
    timeout: int,
    execution_id: str | None,
    mission_id: str | None = None,
) -> tuple[int, str, str]:
    docker_cmd = [
        "docker",
        "exec",
        "--user",
        "root",
        KALI_CONTAINER,
        *args,
    ]
    proc = subprocess.Popen(
        docker_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdin=subprocess.DEVNULL,
        bufsize=1,
    )

    registry = get_mission_registry()
    if execution_id and mission_id:
        registry.register_process(mission_id, execution_id, proc)

    stdout_parts: list[str] = []
    stderr_parts: list[str] = []
    line_queue: Queue[tuple[str, str | None]] = Queue()
    open_pipes = 2

    def read_pipe(pipe, name: str) -> None:
        nonlocal open_pipes
        try:
            for line in iter(pipe.readline, ""):
                line_queue.put((name, line))
        finally:
            pipe.close()
            line_queue.put((name, None))

    threading.Thread(target=read_pipe, args=(proc.stdout, "stdout"), daemon=True).start()
    threading.Thread(target=read_pipe, args=(proc.stderr, "stderr"), daemon=True).start()

    start = time.time()
    closed: set[str] = set()

    while open_pipes > 0 or proc.poll() is None:
        if mission_id and registry.is_cancelled(mission_id):
            proc.kill()
            raise InterruptedError("Execução cancelada pelo usuário.")

        if time.time() - start > timeout:
            proc.kill()
            raise subprocess.TimeoutExpired(docker_cmd, timeout)

        try:
            stream_name, line = line_queue.get(timeout=0.1)
        except Empty:
            continue

        if line is None:
            if stream_name not in closed:
                closed.add(stream_name)
                open_pipes -= 1
            continue

        if stream_name == "stdout":
            stdout_parts.append(line)
        else:
            stderr_parts.append(line)

        if execution_id:
            get_stream_hub().push_line(execution_id, stream_name, line.rstrip("\n"))

    if execution_id and mission_id:
        registry.unregister_process(mission_id, execution_id)

    return proc.wait(), "".join(stdout_parts), "".join(stderr_parts)


def execute_kali_command(
    args: list[str],
    reason: str,
    execution_id: str | None = None,
    chat_session_id: str | None = None,
) -> ExecutionResult:
    """Executa comando e consome o gerador interno, retornando o resultado final."""
    result: ExecutionResult | None = None
    for event in execute_kali_command_stream(
        args, reason, execution_id=execution_id, chat_session_id=chat_session_id
    ):
        if event.get("type") == "done":
            result = event["result"]
    if result is None:
        return ExecutionResult(
            command=args_to_display(args),
            reason=reason,
            stdout="",
            stderr="Falha interna na execução.",
            exit_code=-1,
            success=False,
            tool=args[0].split("/")[-1] if args else "",
        )
    return result


def execute_kali_command_stream(
    args: list[str],
    reason: str,
    execution_id: str | None = None,
    mission_id: str | None = None,
    chat_session_id: str | None = None,
) -> Generator[dict[str, Any], None, None]:
    args = apply_non_interactive_flags(list(args))
    command_display = args_to_display(args)
    binary = args[0].split("/")[-1] if args else ""
    log_id = execution_id or new_log_id()
    hub = get_stream_hub()

    if execution_id:
        if not hub.get(execution_id):
            hub.create(execution_id, command_display)

    yield {
        "type": "start",
        "execution_id": log_id,
        "command": command_display,
    }

    valid, error = validate_command(args)
    if not valid:
        result = ExecutionResult(
            command=command_display,
            reason=reason,
            stdout="",
            stderr=error,
            exit_code=-1,
            success=False,
            blocked=True,
            block_reason=error,
            tool=binary,
            log_file_id=log_id,
        )
        for line in _stream_text_lines(execution_id, "stderr", error):
            yield line
        yield _finalize_stream_result(
            result=result,
            args=args,
            reason=reason,
            mission_id=mission_id,
            execution_id=execution_id,
            hub=hub,
            chat_session_id=chat_session_id,
        )
        return

    scope_ok, scope_error = validate_command_scope(args)
    if not scope_ok:
        result = ExecutionResult(
            command=command_display,
            reason=reason,
            stdout="",
            stderr=scope_error,
            exit_code=-1,
            success=False,
            blocked=True,
            block_reason=scope_error,
            tool=binary,
            log_file_id=log_id,
        )
        for line in _stream_text_lines(execution_id, "stderr", scope_error):
            yield line
        yield _finalize_stream_result(
            result=result,
            args=args,
            reason=reason,
            mission_id=mission_id,
            execution_id=execution_id,
            hub=hub,
            chat_session_id=chat_session_id,
        )
        return

    if binary in HOST_WIFI_TOOLS:
        result = execute_host_wifi(command_display, reason, log_id=log_id)
        combined = "\n".join(filter(None, [result.stdout, result.stderr]))
        for line in _stream_text_lines(execution_id, "stdout", combined):
            yield line
        result.log_file_id = log_id
        yield _finalize_stream_result(
            result=result,
            args=args,
            reason=reason,
            mission_id=mission_id,
            execution_id=execution_id,
            hub=hub,
            save_log=True,
            chat_session_id=chat_session_id,
        )
        return

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

        incr("docker_ops_total")
        with timed("docker_exec", tool=binary):
            exit_code, stdout, stderr = _run_docker_streaming(
                args, timeout, execution_id, mission_id
            )
        result = ExecutionResult(
            command=command_display,
            reason=reason,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            success=exit_code == 0,
            log_file_id=log_id,
            tool=binary,
        )
        yield _finalize_stream_result(
            result=result,
            args=args,
            reason=reason,
            mission_id=mission_id,
            execution_id=execution_id,
            hub=hub,
            save_log=True,
            chat_session_id=chat_session_id,
        )

    except InterruptedError as e:
        msg = str(e)
        for line in _stream_text_lines(execution_id, "stderr", msg):
            yield line
        result = ExecutionResult(
            command=command_display,
            reason=reason,
            stdout="",
            stderr=msg,
            exit_code=-1,
            success=False,
            tool=binary,
            log_file_id=log_id,
        )
        yield _finalize_stream_result(
            result=result,
            args=args,
            reason=reason,
            mission_id=mission_id,
            execution_id=execution_id,
            hub=hub,
            save_log=True,
            chat_session_id=chat_session_id,
        )

    except subprocess.TimeoutExpired:
        msg = f"Timeout após {timeout}s"
        for line in _stream_text_lines(execution_id, "stderr", msg):
            yield line
        result = ExecutionResult(
            command=command_display,
            reason=reason,
            stdout="",
            stderr=msg,
            exit_code=-1,
            success=False,
            tool=binary,
            log_file_id=log_id,
        )
        yield _finalize_stream_result(
            result=result,
            args=args,
            reason=reason,
            mission_id=mission_id,
            execution_id=execution_id,
            hub=hub,
            save_log=True,
            chat_session_id=chat_session_id,
        )

    except FileNotFoundError:
        msg = "Docker não encontrado. Instale o Docker Desktop e inicie o container kali-tools."
        for line in _stream_text_lines(execution_id, "stderr", msg):
            yield line
        result = ExecutionResult(
            command=command_display,
            reason=reason,
            stdout="",
            stderr=msg,
            exit_code=-1,
            success=False,
            tool=binary,
            log_file_id=log_id,
        )
        yield _finalize_stream_result(
            result=result,
            args=args,
            reason=reason,
            mission_id=mission_id,
            execution_id=execution_id,
            hub=hub,
            chat_session_id=chat_session_id,
        )

    except Exception as e:
        msg = str(e)
        for line in _stream_text_lines(execution_id, "stderr", msg):
            yield line
        result = ExecutionResult(
            command=command_display,
            reason=reason,
            stdout="",
            stderr=msg,
            exit_code=-1,
            success=False,
            tool=binary,
            log_file_id=log_id,
        )
        yield _finalize_stream_result(
            result=result,
            args=args,
            reason=reason,
            mission_id=mission_id,
            execution_id=execution_id,
            hub=hub,
            chat_session_id=chat_session_id,
        )


def execute_in_kali(
    command: str,
    reason: str,
    execution_id: str | None = None,
    mission_id: str | None = None,
    chat_session_id: str | None = None,
) -> ExecutionResult:
    """Compatibilidade: converte string da IA em argv e executa sem shell."""
    args = parse_command_string(command)
    result: ExecutionResult | None = None
    for event in execute_kali_command_stream(
        args, reason, execution_id=execution_id, mission_id=mission_id, chat_session_id=chat_session_id
    ):
        if event.get("type") == "done":
            result = event["result"]
    if result is None:
        return ExecutionResult(
            command=args_to_display(args),
            reason=reason,
            stdout="",
            stderr="Falha interna na execução.",
            exit_code=-1,
            success=False,
            tool=args[0].split("/")[-1] if args else "",
        )
    return result
