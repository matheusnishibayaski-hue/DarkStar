import json
import time
from dataclasses import dataclass, field

from openai import OpenAI

from backend.ai.agent import (
    KALI_TOOL_DEFINITION,
    OPENROUTER_BASE_URL,
    OPENROUTER_HEADERS,
    ToolExecution,
    _assistant_message_dict,
    _is_retryable_error,
    _openrouter_error_message,
    _record_execution,
    generate_report,
)
from backend.config import (
    AUTONOMOUS_SYSTEM_PROMPT,
    GEMINI_MODEL,
    MAX_AUTONOMOUS_ROUNDS,
    MAX_AUTONOMOUS_TOOLS,
    MAX_TOOL_ITERATIONS,
    OPENROUTER_API_KEY,
)
from backend.models_catalog import resolve_model

FINISH_MISSION_TOOL = {
    "type": "function",
    "function": {
        "name": "finish_mission",
        "description": (
            "Encerra a missão autônoma quando o objetivo foi atingido, parcialmente cumprido "
            "ou não há mais passos técnicos úteis a executar."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "Relatório final em português: achados, evidências e conclusão.",
                },
                "objective_met": {
                    "type": "boolean",
                    "description": "True se o objetivo principal foi atingido.",
                },
            },
            "required": ["summary", "objective_met"],
        },
    },
}

AUTONOMOUS_TOOLS = [KALI_TOOL_DEFINITION, FINISH_MISSION_TOOL]


@dataclass
class AutonomousResponse:
    message: str
    tool_executions: list[ToolExecution] = field(default_factory=list)
    report: str = ""
    objective_met: bool = False
    rounds: int = 0
    stopped_reason: str = "max_rounds"
    tools_executed: int = 0


def _create_client() -> OpenAI:
    return OpenAI(base_url=OPENROUTER_BASE_URL, api_key=OPENROUTER_API_KEY)


def _completion(client: OpenAI, model: str, messages: list[dict], tools: list[dict]):
    return client.chat.completions.create(
        model=model,
        messages=messages,
        tools=tools,
        tool_choice="auto",
        extra_headers=OPENROUTER_HEADERS,
    )


def _run_autonomous_cycle(
    client: OpenAI,
    messages: list[dict],
    executions: list[ToolExecution],
    model_to_use: str,
    fallback_model: str,
    max_tool_calls: int,
) -> tuple[str, bool, bool, str]:
    """
    Uma rodada do auto-pilot.
    Retorna: (texto, missão_finalizada, objective_met, model_to_use)
    """
    tool_calls_budget = max_tool_calls
    nudged = False

    while tool_calls_budget > 0:
        try:
            response = _completion(client, model_to_use, messages, AUTONOMOUS_TOOLS)
        except Exception as e:
            err = str(e)
            if model_to_use != fallback_model and _is_retryable_error(err):
                time.sleep(1)
                model_to_use = fallback_model
                continue
            raise RuntimeError(_openrouter_error_message(err)) from e

        assistant_message = response.choices[0].message

        if not assistant_message.tool_calls:
            if not nudged and not executions:
                nudged = True
                messages.append({
                    "role": "user",
                    "content": (
                        "Inicie AGORA executando run_kali_tool com o primeiro comando da missão. "
                        "Não descreva o plano — execute."
                    ),
                })
                continue

            text = assistant_message.content or ""
            messages.append({"role": "assistant", "content": text or "(aguardando próxima etapa)"})
            return text, False, False, model_to_use

        messages.append(_assistant_message_dict(assistant_message))

        for tool_call in assistant_message.tool_calls:
            name = tool_call.function.name

            if name == "finish_mission":
                try:
                    args = json.loads(tool_call.function.arguments)
                    summary = args.get("summary", "Missão encerrada.")
                    objective_met = bool(args.get("objective_met", False))
                except Exception:
                    summary = "Missão encerrada (erro ao ler parâmetros)."
                    objective_met = False

                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps({"status": "mission_finished", "objective_met": objective_met}),
                })
                return summary, True, objective_met, model_to_use

            if name == "run_kali_tool":
                try:
                    args = json.loads(tool_call.function.arguments)
                    command = args.get("command", "")
                    reason = args.get("reason", "")
                except Exception:
                    command = ""
                    reason = "Falha ao decodificar argumentos."

                result_text = _record_execution(command, reason, executions)
                tool_calls_budget -= 1
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": result_text,
                })

                if tool_calls_budget <= 0:
                    messages.append({
                        "role": "user",
                        "content": (
                            "Limite de comandos nesta rodada atingido. "
                            "Resuma o progresso e prossiga na próxima rodada ou chame finish_mission."
                        ),
                    })
                    return "", False, False, model_to_use

    return "", False, False, model_to_use


def run_autonomous(
    target: str,
    objective: str,
    model: str | None = None,
    fallback_model: str | None = None,
) -> AutonomousResponse:
    if not OPENROUTER_API_KEY:
        return AutonomousResponse(
            message=(
                "Configure OPENROUTER_API_KEY no arquivo .env.\n\n"
                "Obtenha uma chave em: https://openrouter.ai/keys"
            ),
            stopped_reason="error",
        )

    target = target.strip()
    objective = objective.strip()
    if not target or not objective:
        return AutonomousResponse(
            message="Alvo e objetivo são obrigatórios para o Modo Autônomo.",
            stopped_reason="error",
        )

    client = _create_client()
    system = AUTONOMOUS_SYSTEM_PROMPT.format(target=target, objective=objective)
    messages: list[dict] = [{"role": "system", "content": system}]

    executions: list[ToolExecution] = []
    model_to_use, fallback_to_use = resolve_model(model, fallback_model)
    final_message = ""
    objective_met = False
    stopped_reason = "max_rounds"
    rounds_completed = 0
    remaining_tools = MAX_AUTONOMOUS_TOOLS

    for round_idx in range(MAX_AUTONOMOUS_ROUNDS):
        if remaining_tools <= 0:
            stopped_reason = "max_tools"
            break

        per_round = min(MAX_TOOL_ITERATIONS, remaining_tools)

        if round_idx == 0:
            kickoff = (
                f"Missão autônoma iniciada.\n"
                f"Alvo: {target}\n"
                f"Objetivo: {objective}\n\n"
                "Execute o primeiro comando via run_kali_tool agora."
            )
        else:
            kickoff = (
                f"Rodada {round_idx + 1}/{MAX_AUTONOMOUS_ROUNDS}. "
                f"Comandos executados até agora: {len(executions)}.\n"
                "Analise os resultados anteriores, execute a próxima ferramenta necessária "
                "ou chame finish_mission se o objetivo foi atingido."
            )

        messages.append({"role": "user", "content": kickoff})

        try:
            text, finished, met, model_to_use = _run_autonomous_cycle(
                client, messages, executions, model_to_use, fallback_to_use, per_round,
            )
        except RuntimeError as e:
            return AutonomousResponse(
                message=str(e),
                tool_executions=executions,
                rounds=round_idx,
                tools_executed=len(executions),
                stopped_reason="error",
            )

        rounds_completed = round_idx + 1
        remaining_tools = MAX_AUTONOMOUS_TOOLS - len(executions)

        if finished:
            final_message = text
            objective_met = met
            stopped_reason = "objective_met" if met else "finished_early"
            break

        if text:
            final_message = text

    if not final_message and executions:
        final_message = (
            f"Missão encerrada após {rounds_completed} rodada(s) e {len(executions)} comando(s). "
            "Consulte o relatório para detalhes."
        )
    elif not final_message:
        final_message = "Nenhum comando foi executado durante a missão autônoma."

    history = [
        {"role": "user", "content": f"[Auto-Pilot] Alvo: {target}\nObjetivo: {objective}"},
        {"role": "assistant", "content": final_message},
    ]
    exec_dicts = [
        {
            "command": e.command,
            "reason": e.reason,
            "stdout": e.stdout,
            "stderr": e.stderr,
            "exit_code": e.exit_code,
            "success": e.success,
            "blocked": e.blocked,
            "log_file_id": e.log_file_id,
            "tool": e.tool,
        }
        for e in executions
    ]
    report = generate_report(
        history,
        exec_dicts,
        title=f"Relatório Auto-Pilot — {target}",
    )

    status_line = (
        f"\n\n---\n**Auto-Pilot:** {rounds_completed} rodada(s) · "
        f"{len(executions)} comando(s) · "
        f"{'objetivo atingido' if objective_met else stopped_reason}"
    )
    final_message = final_message + status_line

    return AutonomousResponse(
        message=final_message,
        tool_executions=executions,
        report=report,
        objective_met=objective_met,
        rounds=rounds_completed,
        stopped_reason=stopped_reason,
        tools_executed=len(executions),
    )
