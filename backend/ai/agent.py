import threading
import time
from collections.abc import Callable, Generator
from dataclasses import asdict, dataclass, field
from queue import Queue

from backend.ai.healing import healing_prompt, should_attempt_healing
from backend.ai.openrouter_common import (
    assistant_message_dict,
    is_retryable_error,
    openrouter_error_message,
)
from backend.ai.providers import get_llm_provider
from backend.ai.providers.tool_heal import assistant_dict_from_message, resolve_tool_arguments
from backend.ai.report import generate_report
from backend.ai.sse import format_sse
from backend.config import (
    MAX_HISTORY_MESSAGES,
    MAX_TOOL_ITERATIONS,
    SYSTEM_PROMPT,
)
from backend.config_prompts import CHAT_FINALIZE_NUDGE, CHAT_POST_TOOL_NUDGE
from backend.executor.kali import execute_in_kali
from backend.executor.logs import new_log_id
from backend.executor.recon_db import (
    build_recon_context,
    extract_recon_from_output,
    extract_targets,
    merge_recon_update,
)
from backend.executor.result import ExecutionResult, format_result_for_llm
from backend.executor.stream_hub import get_stream_hub
from backend.executor.summarize import summarize_output
from backend.observability import incr, log_event, timed
from backend.security.missions import get_mission_registry

# Reexports — compatibilidade com autopilot/testes/rotas que importam de agent
_assistant_message_dict = assistant_message_dict
_is_retryable_error = is_retryable_error
_openrouter_error_message = openrouter_error_message
__all__ = ["chat", "chat_stream", "generate_report", "ChatResponse", "ToolExecution"]

KALI_TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "run_kali_tool",
        "description": (
            "Executa um comando real no container Kali Linux. "
            "Use quando o usuário pedir scan, teste, enumeração ou dado que exija saída real do terminal. "
            "Não use para perguntas só explicativas ou conversa geral."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": (
                        "Comando com argumentos separados por espaço "
                        "(ex: 'nmap -sV scanme.nmap.org'). Não use ; | & ou redirecionamentos."
                    ),
                },
                "reason": {
                    "type": "string",
                    "description": (
                        "Breve justificativa técnica (também exibida nos logs): "
                        "o que vai fazer e por quê, em tom de assistente."
                    ),
                },
            },
            "required": ["command", "reason"],
        },
    },
}


@dataclass
class ToolExecution:
    command: str
    reason: str
    stdout: str
    stderr: str
    exit_code: int
    success: bool
    blocked: bool = False
    log_file_id: str = ""
    tool: str = ""


@dataclass
class ChatResponse:
    message: str
    tool_executions: list[ToolExecution] = field(default_factory=list)
    stopped_reason: str = "completed"


EmitFn = Callable[[str, dict], None]


def _apply_recon_context(user_message: str, history: list[dict]) -> tuple[str, list[str]]:
    from backend.ai.project_intel import operator_text_for_targets
    from backend.executor.recon_db import is_recon_target
    from backend.executor.surface import build_surface_context

    # Preferir texto do operador (sem anexos/intel) para não poluir com deps/URLs de libs
    op_text = operator_text_for_targets(user_message)
    history_text = " ".join(m.get("content", "") for m in history if m.get("role") == "user")
    targets = [t for t in extract_targets(op_text, history_text) if is_recon_target(t)]
    # Se o operador não deu alvo, tentar no texto completo (fallback)
    if not targets:
        targets = [t for t in extract_targets(user_message, history_text) if is_recon_target(t)]
    parts: list[str] = []
    recon = build_recon_context(targets)
    if recon:
        parts.append(recon)
    for target in targets[:3]:
        surface = build_surface_context(target)
        if surface:
            parts.append(surface)
    if not parts:
        return user_message, targets
    return f"{chr(10).join(parts)}\n\n{user_message}", targets


def _persist_recon(
    result: ExecutionResult,
    session_targets: list[str],
    *,
    chat_session_id: str | None = None,
) -> None:
    from backend.ai.findings import auto_verify_from_execution
    from backend.executor.recon_db import extract_targets, is_recon_target, normalize_target
    from backend.executor.session_intel import touch_session
    from backend.executor.surface import update_surface_from_execution

    command_targets = [
        normalize_target(t)
        for t in extract_targets(result.command, result.stdout, result.stderr)
        if is_recon_target(t)
    ]
    session_norm = [normalize_target(t) for t in session_targets if is_recon_target(t)]
    targets: list[str] = []
    for t in command_targets + session_norm:
        if t and t not in targets:
            targets.append(t)

    if chat_session_id:
        for t in targets:
            touch_session(chat_session_id, t)

    if not targets:
        return

    # Attack Surface Graph: atualiza mesmo em falha (hipóteses / tools_run)
    if not result.blocked:
        for target in targets:
            update_surface_from_execution(
                target,
                command=result.command,
                tool=result.tool,
                stdout=result.stdout,
                stderr=result.stderr,
                success=result.success,
                blocked=result.blocked,
                exit_code=result.exit_code,
                chat_session_id=chat_session_id,
            )
            if result.success:
                auto_verify_from_execution(
                    target,
                    command=result.command,
                    tool=result.tool,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    success=True,
                )

    if not result.success or result.blocked:
        return
    patch = extract_recon_from_output(result.stdout, result.stderr, result.tool)
    if len(patch) <= 2:
        return
    for target in targets:
        merge_recon_update(target, patch)


def _apply_preferred_tool(user_message: str, preferred_tool: str | None) -> str:
    if not preferred_tool or preferred_tool == "auto":
        return user_message
    return (
        f"[O usuário fixou a ferramenta '{preferred_tool}' no painel. "
        f"Priorize executá-la via run_kali_tool se o pedido for operacional; "
        f"se for só dúvida conceitual sobre ela, responda em texto.]\n\n"
        f"{user_message}"
    )


_AUTO_WHITEBOX_MARKER = "[Pentest white-box automático]"


def _apply_auto_whitebox_mission(user_message: str) -> str:
    if _AUTO_WHITEBOX_MARKER not in (user_message or ""):
        return user_message
    return (
        "[Sistema] Missão automática white-box. Use [Anexos] e [PROJECT INTEL] como fonte "
        "primária. Responda ao usuário SOMENTE com o relatório de achados (sem saudação, "
        "sem pedir alvo se o intel já tiver host/URL do app). Se houver alvo de rede no "
        "intel, pode usar run_kali_tool e incorporar no relatório.\n\n" + user_message
    )


_CHAT_MODE_PREFIX = {
    "plan": (
        "[Modo Plan: monte um plano passo a passo. Não execute ferramentas Kali "
        "nesta resposta; descreva o que faria e por quê.]\n\n"
    ),
    "ask": (
        "[Modo Ask: responda só com explicação. Não chame ferramentas Kali nesta resposta.]\n\n"
    ),
    "review": (
        "[Modo Review: revise achados, evidências e o relatório desta conversa. "
        "Seja crítico e objetivo; só sugira novo scan se faltar evidência.]\n\n"
    ),
}


def _apply_chat_mode(user_message: str, chat_mode: str | None) -> str:
    mode = (chat_mode or "agent").strip().lower()
    prefix = _CHAT_MODE_PREFIX.get(mode)
    if not prefix:
        return user_message
    return prefix + user_message


def _apply_attachments(user_message: str, attachments: list | None) -> str:
    if not attachments:
        return user_message
    from backend.ai.project_intel import apply_project_intel, attachments_as_dicts

    items = attachments_as_dicts(attachments)
    chunks: list[str] = []
    for item in items[:13]:
        name = str(item.get("name") or "file")[:256]
        content = str(item.get("content") or "")[:200000]
        if not content:
            continue
        if name == "__project_map.txt":
            chunks.append(
                "[Mapa do repositório — inventário do projeto]\n"
                "Use para: superfície de ataque, entrypoints, configs, portas/URLs implícitas, "
                "stack e priorização de ferramentas. Cite paths ao planejar scans.\n"
                + content
                + "\n"
            )
        else:
            chunks.append(
                f"--- arquivo: {name} ---\n"
                "(Conteúdo white-box — derive rotas, auth, configs e possíveis alvos.)\n"
                + content
                + "\n"
            )
    if not chunks:
        return user_message
    with_files = user_message + "\n\n[Anexos]\n" + "".join(chunks)
    return apply_project_intel(with_files, items)


def _convert_history(history: list[dict]) -> list[dict]:
    messages = []
    trimmed = history[-MAX_HISTORY_MESSAGES:] if len(history) > MAX_HISTORY_MESSAGES else history
    for msg in trimmed:
        role = msg.get("role", "user")
        if role not in ("system", "user", "assistant"):
            role = "user"
        messages.append({"role": role, "content": msg.get("content", "")})
    return messages


def _result_to_tool_execution(result: ExecutionResult) -> ToolExecution:
    return ToolExecution(
        command=result.command,
        reason=result.reason,
        stdout=result.stdout,
        stderr=result.stderr,
        exit_code=result.exit_code,
        success=result.success,
        blocked=result.blocked,
        log_file_id=result.log_file_id,
        tool=result.tool,
    )


def _record_execution(
    command: str,
    reason: str,
    executions: list[ToolExecution],
    *,
    recon_targets: list[str] | None = None,
    emit: EmitFn | None = None,
    mission_id: str | None = None,
    chat_session_id: str | None = None,
) -> str:
    execution_id = new_log_id()
    get_stream_hub().create(execution_id, command or "(comando vazio)")
    if emit:
        emit(
            "tool_start",
            {
                "execution_id": execution_id,
                "command": command,
                "reason": reason,
            },
        )

    incr("tool_executions_total")
    with timed("tool_execution", tool=(command.split() or [""])[0]):
        result = execute_in_kali(
            command,
            reason,
            execution_id=execution_id,
            mission_id=mission_id,
            chat_session_id=chat_session_id,
        )
    summarized, truncated = summarize_output(result.stdout, result.stderr)
    result.truncated_for_llm = truncated
    execution = _result_to_tool_execution(result)
    executions.append(execution)
    _persist_recon(result, recon_targets or [], chat_session_id=chat_session_id)

    if emit:
        emit(
            "tool_done",
            {
                "execution_id": execution_id,
                "command": execution.command,
                "success": execution.success,
                "blocked": execution.blocked,
                "exit_code": execution.exit_code,
                "log_file_id": execution.log_file_id,
                "tool": execution.tool,
                "stdout": (execution.stdout or "")[:2000],
                "stderr": (execution.stderr or "")[:800],
                "reason": execution.reason or "",
            },
        )

    return format_result_for_llm(result, output_text=summarized if truncated else None)


def _run_openrouter(
    history: list[dict],
    user_message: str,
    model: str | None = None,
    fallback_model: str | None = None,
    recon_targets: list[str] | None = None,
    emit: EmitFn | None = None,
    mission_id: str | None = None,
    chat_session_id: str | None = None,
    *,
    force_tool_use: bool = False,
) -> ChatResponse:
    provider = get_llm_provider()
    if not provider.is_configured():
        return ChatResponse(message=provider.configuration_error())

    registry = get_mission_registry()
    if mission_id:
        registry.register(mission_id)

    try:
        return _run_openrouter_body(
            history,
            user_message,
            model,
            fallback_model,
            recon_targets,
            emit,
            mission_id,
            chat_session_id,
            force_tool_use=force_tool_use,
        )
    finally:
        if mission_id:
            registry.cleanup(mission_id)


def _run_openrouter_body(
    history: list[dict],
    user_message: str,
    model: str | None,
    fallback_model: str | None,
    recon_targets: list[str] | None,
    emit: EmitFn | None,
    mission_id: str | None,
    chat_session_id: str | None = None,
    *,
    force_tool_use: bool = False,
) -> ChatResponse:
    provider = get_llm_provider()

    messages: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages.extend(_convert_history(history))
    messages.append({"role": "user", "content": user_message})

    executions: list[ToolExecution] = []
    model_to_use, fallback_to_use = provider.resolve_models(model, fallback_model)
    nudged = False
    healing_attempts = 0
    final_text = ""

    for _ in range(MAX_TOOL_ITERATIONS):
        if get_mission_registry().is_cancelled(mission_id):
            return ChatResponse(
                message="Operação cancelada pelo usuário.",
                tool_executions=executions,
                stopped_reason="cancelled",
            )

        try:
            incr("llm_calls_total")
            with timed("llm_call", tool=model_to_use):
                completion = provider.complete(
                    model=model_to_use,
                    messages=messages,
                    tools=[KALI_TOOL_DEFINITION],
                    tool_choice="auto",
                )
        except Exception as e:
            err = str(e)
            log_event("WARNING", "llm_call_failed", tool=model_to_use)
            if model_to_use != fallback_to_use and provider.is_retryable_error(err):
                time.sleep(1)
                model_to_use = fallback_to_use
                continue
            return ChatResponse(message=provider.format_error(err))

        assistant_message = completion.message

        if not assistant_message.tool_calls:
            if not nudged and not executions and force_tool_use:
                nudged = True
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "O usuário escolheu uma ferramenta fixa ou pediu execução. "
                            "Use run_kali_tool agora se o pedido for operacional; "
                            "caso contrário responda em texto."
                        ),
                    }
                )
                continue

            final_text = assistant_message.content or "Sem resposta da IA."
            return ChatResponse(message=final_text, tool_executions=executions)

        messages.append(assistant_dict_from_message(assistant_message))

        batch_ran_kali = False
        batch_needs_healing = False
        for tool_call in assistant_message.tool_calls:
            if tool_call.name != "run_kali_tool":
                continue

            batch_ran_kali = True
            arguments, heal_err = resolve_tool_arguments(
                provider,
                model=model_to_use,
                tool_call=tool_call,
                messages=messages,
            )
            if arguments is None:
                command = ""
                reason = heal_err or "Falha ao decodificar os argumentos fornecidos pela IA."
            else:
                command = arguments.get("command", "")
                reason = arguments.get("reason", "")

            result_text = _record_execution(
                command,
                reason,
                executions,
                recon_targets=recon_targets,
                emit=emit,
                mission_id=mission_id,
                chat_session_id=chat_session_id,
            )
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": result_text,
                }
            )

            last = executions[-1]
            if should_attempt_healing(last, healing_attempts):
                healing_attempts += 1
                batch_needs_healing = True
                messages.append(
                    {
                        "role": "user",
                        "content": healing_prompt(last),
                    }
                )

        if batch_ran_kali and not batch_needs_healing:
            messages.append(
                {
                    "role": "user",
                    "content": CHAT_POST_TOOL_NUDGE,
                }
            )

    messages.append(
        {
            "role": "user",
            "content": CHAT_FINALIZE_NUDGE,
        }
    )

    try:
        final_completion = provider.complete(
            model=model_to_use,
            messages=messages,
            tools=None,
            tool_choice=None,
        )
        final_text = (
            final_completion.message.content or "Limite de iterações de ferramentas atingido."
        )
    except Exception as e:
        final_text = f"Limite de iterações atingido. Erro na finalização: {e}"

    return ChatResponse(message=final_text, tool_executions=executions)


def chat(
    history: list[dict],
    user_message: str,
    preferred_tool: str | None = None,
    model: str | None = None,
    fallback_model: str | None = None,
    emit: EmitFn | None = None,
    mission_id: str | None = None,
    chat_session_id: str | None = None,
    chat_mode: str | None = None,
    attachments: list | None = None,
) -> ChatResponse:
    user_message = _apply_chat_mode(user_message, chat_mode)
    user_message = _apply_auto_whitebox_mission(user_message)
    user_message = _apply_attachments(user_message, attachments)
    user_message = _apply_preferred_tool(user_message, preferred_tool)
    enriched, targets = _apply_recon_context(user_message, history)
    force_tool_use = bool(preferred_tool and preferred_tool != "auto")
    return _run_openrouter(
        history,
        enriched,
        model=model,
        fallback_model=fallback_model,
        recon_targets=targets,
        emit=emit,
        mission_id=mission_id,
        chat_session_id=chat_session_id,
        force_tool_use=force_tool_use,
    )


def chat_stream(
    history: list[dict],
    user_message: str,
    preferred_tool: str | None = None,
    model: str | None = None,
    fallback_model: str | None = None,
    mission_id: str | None = None,
    chat_session_id: str | None = None,
    chat_mode: str | None = None,
    attachments: list | None = None,
) -> Generator[str, None, None]:
    """Gera eventos SSE durante o processamento do chat."""
    event_queue: Queue[str | None] = Queue()

    def emit(event: str, data: dict) -> None:
        event_queue.put(format_sse(event, data))

    def worker() -> None:
        try:
            result = chat(
                history,
                user_message,
                preferred_tool=preferred_tool,
                model=model,
                fallback_model=fallback_model,
                emit=emit,
                mission_id=mission_id,
                chat_session_id=chat_session_id,
                chat_mode=chat_mode,
                attachments=attachments,
            )
            event_queue.put(
                format_sse(
                    "done",
                    {
                        "message": result.message,
                        "tool_executions": [asdict(e) for e in result.tool_executions],
                        "stopped_reason": result.stopped_reason,
                    },
                )
            )
        except Exception as e:
            event_queue.put(format_sse("error", {"detail": str(e)}))
        finally:
            event_queue.put(None)

    threading.Thread(target=worker, daemon=True).start()

    while True:
        item = event_queue.get()
        if item is None:
            break
        yield item
