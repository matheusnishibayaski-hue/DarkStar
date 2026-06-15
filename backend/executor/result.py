from dataclasses import dataclass


@dataclass
class ExecutionResult:
    command: str
    reason: str
    stdout: str
    stderr: str
    exit_code: int
    success: bool
    blocked: bool = False
    block_reason: str = ""


def format_result_for_llm(result: ExecutionResult) -> str:
    parts = [
        f"Comando: {result.command}",
        f"Motivo: {result.reason}",
        f"Exit code: {result.exit_code}",
    ]
    if result.stdout:
        parts.append(f"STDOUT:\n{result.stdout}")
    if result.stderr:
        parts.append(f"STDERR:\n{result.stderr}")
    return "\n\n".join(parts)
