"""Smart Healing — auto-correção de comandos com limite de tentativas."""

from backend.config import MAX_HEALING_ATTEMPTS


def healing_prompt(execution) -> str:
    err = (execution.stderr or execution.stdout or f"exit code {execution.exit_code}").strip()
    return (
        f"[ERRO DE EXECUÇÃO DETECTADO]: O comando falhou com o erro: {err}. "
        "Analise o erro, corrija a sintaxe ou os parâmetros, e execute o comando corrigido "
        "IMEDIATAMENTE usando a ferramenta run_kali_tool."
    )


def should_attempt_healing(execution, healing_attempts: int) -> bool:
    if execution.success or execution.blocked:
        return False
    return healing_attempts < MAX_HEALING_ATTEMPTS
