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
    log_file_id: str = ""
    tool: str = ""
    truncated_for_llm: bool = False


def format_result_for_llm(result: ExecutionResult, output_text: str | None = None) -> str:
    body = output_text if output_text is not None else "\n".join(
        part for part in (result.stdout, result.stderr) if part
    )
    parts = [f"cmd={result.command}", f"exit={result.exit_code}"]
    if result.truncated_for_llm:
        parts.append("(resumo)")
    if body:
        parts.append(body)
    return "\n".join(parts)
