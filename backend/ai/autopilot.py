import json
import threading
import time
from collections.abc import Callable, Generator
from dataclasses import dataclass, field
from queue import Queue

from backend.ai.agent import (
    KALI_TOOL_DEFINITION,
    ToolExecution,
    _record_execution,
    generate_report,
)
from backend.ai.findings import findings_for_report
from backend.ai.healing import healing_prompt, should_attempt_healing
from backend.ai.openrouter_common import (
    is_retryable_error,
)
from backend.ai.phases import (
    advance_surface_phase,
    is_tool_allowed,
    kickoff_for_phase,
    normalize_risk_profile,
    phase_prompt_block,
)
from backend.ai.providers import get_llm_provider
from backend.ai.providers.base import BaseLLMProvider
from backend.ai.providers.tool_heal import assistant_dict_from_message, resolve_tool_arguments
from backend.ai.scan_profiles import (
    max_tool_budget,
    pending_scan_tools,
    resolve_scan_tools,
    scan_profile_prompt_block,
)
from backend.ai.scan_profiles import (
    normalize_profile as normalize_scan_profile,
)
from backend.ai.sse import format_sse
from backend.ai.verify import run_verification_pipeline
from backend.config import (
    AUTONOMOUS_SYSTEM_PROMPT,
    MAX_AUTONOMOUS_ROUNDS,
    MAX_AUTONOMOUS_TOOLS,
    MAX_TOOL_ITERATIONS,
    RISK_PROFILE,
)
from backend.executor.recon_db import build_recon_context, normalize_target
from backend.executor.surface import (
    build_surface_context,
    get_or_create_surface,
    load_surface,
    save_surface,
    surface_summary,
)
from backend.observability import timed
from backend.security.missions import get_mission_registry

EmitFn = Callable[[str, dict], None]

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


def _create_client() -> BaseLLMProvider:
    """Compat: retorna o provider ativo (antes retornava OpenAI)."""
    return get_llm_provider()


def _completion(provider: BaseLLMProvider, model: str, messages: list[dict], tools: list[dict]):
    from backend.observability import incr

    incr("llm_calls_total")
    with timed("llm_call", tool=model):
        return provider.complete(
            model=model,
            messages=messages,
            tools=tools,
            tool_choice="auto",
        )


def _run_autonomous_cycle(
    provider: BaseLLMProvider,
    messages: list[dict],
    executions: list[ToolExecution],
    model_to_use: str,
    fallback_model: str,
    max_tool_calls: int,
    recon_targets: list[str] | None = None,
    emit: EmitFn | None = None,
    mission_id: str | None = None,
    chat_session_id: str | None = None,
    *,
    phase: str = "recon",
    risk_profile: str = "safe-active",
) -> tuple[str, bool, bool, str]:
    """
    Uma rodada do auto-pilot.
    Retorna: (texto, missão_finalizada, objective_met, model_to_use)
    """
    tool_calls_budget = max_tool_calls
    nudged = False
    healing_attempts = 0

    while tool_calls_budget > 0:
        if get_mission_registry().is_cancelled(mission_id):
            return "Missão cancelada pelo usuário.", True, False, model_to_use

        try:
            completion = _completion(provider, model_to_use, messages, AUTONOMOUS_TOOLS)
        except Exception as e:
            err = str(e)
            if model_to_use != fallback_model and (
                provider.is_retryable_error(err) or is_retryable_error(err)
            ):
                time.sleep(1)
                model_to_use = fallback_model
                continue
            raise RuntimeError(provider.format_error(err)) from e

        assistant_message = completion.message

        if not assistant_message.tool_calls:
            if not nudged and not executions:
                nudged = True
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "Inicie AGORA executando run_kali_tool com o primeiro comando da missão. "
                            "Não descreva o plano — execute."
                        ),
                    }
                )
                continue

            text = assistant_message.content or ""
            messages.append({"role": "assistant", "content": text or "(aguardando próxima etapa)"})
            return text, False, False, model_to_use

        messages.append(assistant_dict_from_message(assistant_message))

        for tool_call in assistant_message.tool_calls:
            name = tool_call.name

            if name == "finish_mission":
                args, heal_err = resolve_tool_arguments(
                    provider,
                    model=model_to_use,
                    tool_call=tool_call,
                    messages=messages,
                )
                if args is None:
                    summary = heal_err or "Missão encerrada (erro ao ler parâmetros)."
                    objective_met = False
                else:
                    summary = args.get("summary", "Missão encerrada.")
                    objective_met = bool(args.get("objective_met", False))

                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": json.dumps(
                            {"status": "mission_finished", "objective_met": objective_met}
                        ),
                    }
                )
                return summary, True, objective_met, model_to_use

            if name == "run_kali_tool":
                args, heal_err = resolve_tool_arguments(
                    provider,
                    model=model_to_use,
                    tool_call=tool_call,
                    messages=messages,
                )
                if args is None:
                    command = ""
                    reason = heal_err or "Falha ao decodificar argumentos."
                else:
                    command = args.get("command", "")
                    reason = args.get("reason", "")

                allowed, block_msg = is_tool_allowed(
                    command, phase=phase, risk_profile=risk_profile
                )
                if not allowed:
                    tool_calls_budget -= 1
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": (
                                f"[BLOQUEADO PELA METODOLOGIA] {block_msg}\n"
                                "Escolha outra ferramenta adequada à fase/perfil "
                                "ou avance com finish_mission se estiver na fase report."
                            ),
                        }
                    )
                    if tool_calls_budget <= 0:
                        return "", False, False, model_to_use
                    continue

                result_text = _record_execution(
                    command,
                    reason,
                    executions,
                    recon_targets=recon_targets,
                    emit=emit,
                    mission_id=mission_id,
                    chat_session_id=chat_session_id,
                )
                tool_calls_budget -= 1
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
                    messages.append(
                        {
                            "role": "user",
                            "content": healing_prompt(last),
                        }
                    )

                if tool_calls_budget <= 0:
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                "Limite de comandos nesta rodada atingido. "
                                "Resuma o progresso e prossiga na próxima rodada ou chame finish_mission."
                            ),
                        }
                    )
                    return "", False, False, model_to_use

    return "", False, False, model_to_use


def run_autonomous(
    target: str,
    objective: str,
    model: str | None = None,
    fallback_model: str | None = None,
    emit: EmitFn | None = None,
    mission_id: str | None = None,
    risk_profile: str | None = None,
    chat_session_id: str | None = None,
    scan_profile: str | None = None,
    custom_tools: list[str] | None = None,
    attachments: list | None = None,
) -> AutonomousResponse:
    registry = get_mission_registry()
    if mission_id:
        registry.register(mission_id)

    try:
        return _run_autonomous_body(
            target,
            objective,
            model,
            fallback_model,
            emit,
            mission_id,
            risk_profile=risk_profile,
            chat_session_id=chat_session_id,
            scan_profile=scan_profile,
            custom_tools=custom_tools,
            attachments=attachments,
        )
    finally:
        if mission_id:
            registry.cleanup(mission_id)


def _run_autonomous_body(
    target: str,
    objective: str,
    model: str | None,
    fallback_model: str | None,
    emit: EmitFn | None,
    mission_id: str | None,
    risk_profile: str | None = None,
    chat_session_id: str | None = None,
    scan_profile: str | None = None,
    custom_tools: list[str] | None = None,
    attachments: list | None = None,
) -> AutonomousResponse:
    provider = get_llm_provider()
    if not provider.is_configured():
        return AutonomousResponse(
            message=provider.configuration_error(),
            stopped_reason="error",
        )

    target = target.strip()
    objective = objective.strip()
    if not target or not objective:
        return AutonomousResponse(
            message="Alvo e objetivo são obrigatórios para o Modo Autônomo.",
            stopped_reason="error",
        )

    scan_prof = normalize_scan_profile(scan_profile or "basic")
    profile = normalize_risk_profile(risk_profile or RISK_PROFILE)
    try:
        from backend.security.privileges import effective_risk_profile

        profile = effective_risk_profile(profile)
    except Exception:
        pass
    scan_tools = resolve_scan_tools(
        scan_prof,
        custom_tools,
        include_all_allowed=(profile == "full" and scan_prof == "full"),
        available_only=True,
    )
    if not scan_tools:
        # Fallback sem filtro se probe falhou / container down
        scan_tools = resolve_scan_tools(
            scan_prof,
            custom_tools,
            include_all_allowed=(profile == "full" and scan_prof == "full"),
            available_only=False,
        )
    if scan_prof == "custom" and not scan_tools:
        return AutonomousResponse(
            message="Perfil personalizado: selecione ao menos uma ferramenta.",
            stopped_reason="error",
        )

    client = provider
    recon_target = normalize_target(target)
    surface = get_or_create_surface(
        recon_target,
        objective=objective,
        risk_profile=profile,
        mission_id=mission_id or "",
    )
    recon_context = build_recon_context([recon_target])
    surface_context = build_surface_context(recon_target)
    system = AUTONOMOUS_SYSTEM_PROMPT.format(
        target=target,
        objective=objective,
        risk_profile=profile,
    )
    system = f"{system}\n\n{phase_prompt_block(surface.get('phase') or 'recon', surface_summary(surface))}"
    if recon_context:
        system = f"{system}\n\n{recon_context}"
    if surface_context:
        system = f"{system}\n\n{surface_context}"
    scan_block = scan_profile_prompt_block(scan_prof, scan_tools, target=target)
    if scan_block:
        system = f"{system}\n\n{scan_block}"

    # White-box: mapa/arquivos da Pasta/GitHub (mesmo pipeline do chat)
    if attachments:
        from backend.ai.agent import _apply_attachments
        from backend.ai.project_intel import attachments_as_dicts, extract_project_intel

        items = attachments_as_dicts(attachments)
        intel = extract_project_intel(items)
        if intel:
            # Preferir pendentes do perfil ∩ fase, não trio fixo
            system = (
                f"{system}\n\n[Cobertura sugerida] Use PROJECT INTEL + ferramentas "
                "ainda pendentes do perfil nesta fase (varie — não repita só httpx/nuclei/nikto)."
            )
        attach_blob = _apply_attachments("", items)
        if attach_blob.strip():
            clipped = attach_blob.strip()
            if len(clipped) > 120000:
                clipped = clipped[:120000] + "\n… [anexos truncados]"
            system = f"{system}\n\n{clipped}"

    messages: list[dict] = [{"role": "system", "content": system}]

    executions: list[ToolExecution] = []
    model_to_use, fallback_to_use = provider.resolve_models(model, fallback_model)
    final_message = ""
    objective_met = False
    stopped_reason = "max_rounds"
    rounds_completed = 0
    mission_budget = (
        max_tool_budget(scan_prof, len(scan_tools)) if scan_tools else MAX_AUTONOMOUS_TOOLS
    )
    remaining_tools = mission_budget
    max_rounds = MAX_AUTONOMOUS_ROUNDS
    if scan_prof == "full":
        max_rounds = max(MAX_AUTONOMOUS_ROUNDS, 50 if len(scan_tools) > 100 else 40)
    elif scan_prof == "intermediate":
        max_rounds = max(MAX_AUTONOMOUS_ROUNDS, 20)
    elif scan_prof == "custom" and len(scan_tools) > 25:
        max_rounds = max(MAX_AUTONOMOUS_ROUNDS, 25)

    if emit:
        payload = {
            "target": target,
            "objective": objective,
            "phase": surface.get("phase") or "recon",
            "risk_profile": profile,
            "scan_profile": scan_prof,
            "scan_tool_count": len(scan_tools),
        }
        if mission_id:
            payload["mission_id"] = mission_id
        emit("mission_start", payload)

    for round_idx in range(max_rounds):
        if get_mission_registry().is_cancelled(mission_id):
            stopped_reason = "cancelled"
            final_message = "Missão cancelada pelo usuário."
            break

        if remaining_tools <= 0:
            stopped_reason = "max_tools"
            break

        surface = load_surface(recon_target) or surface
        current_phase = surface.get("phase") or "recon"
        summary = surface_summary(surface)
        per_round = min(MAX_TOOL_ITERATIONS, remaining_tools)

        used = list(surface.get("tools_run") or [])
        pending = pending_scan_tools(scan_tools, used)
        # Preferidos da fase ∩ pendentes
        from backend.ai.phases import PHASE_PREFERRED_TOOLS

        phase_pref = PHASE_PREFERRED_TOOLS.get(current_phase, frozenset())
        pending_phase = [t for t in pending if t in phase_pref] or pending[:8]

        kickoff = kickoff_for_phase(
            phase=current_phase,
            target=target,
            objective=objective,
            round_idx=round_idx,
            max_rounds=max_rounds,
            tools_executed=len(executions),
            surface_summary_data=summary,
        )
        if pending_phase and current_phase != "report":
            sample = ", ".join(pending_phase[:8])
            kickoff = (
                f"{kickoff}\n\n[Pendentes do perfil — rode UMA agora]: {sample}"
                f"{'…' if len(pending) > 8 else ''} "
                f"({len(pending)} restantes). Varie as ferramentas; não repita as já usadas."
            )
        messages.append({"role": "user", "content": kickoff})

        if emit:
            emit(
                "round_start",
                {
                    "round": round_idx + 1,
                    "max_rounds": max_rounds,
                    "tools_executed": len(executions),
                    "phase": current_phase,
                    "risk_profile": profile,
                },
            )

        try:
            text, finished, met, model_to_use = _run_autonomous_cycle(
                client,
                messages,
                executions,
                model_to_use,
                fallback_to_use,
                per_round,
                recon_targets=[recon_target],
                emit=emit,
                mission_id=mission_id,
                chat_session_id=chat_session_id,
                phase=current_phase,
                risk_profile=profile,
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
        remaining_tools = max(0, mission_budget - len(executions))

        # Marcar tools ausentes (exit 127 / not found)
        from backend.executor.tool_presence import looks_like_missing_binary, mark_tool_unavailable

        for ex in executions[-per_round:]:
            if looks_like_missing_binary(ex.exit_code, ex.stderr or "", ex.stdout or ""):
                bin_name = (ex.tool or "").strip().lower()
                if not bin_name and ex.command:
                    bin_name = ex.command.strip().split()[0].split("/")[-1].lower()
                if bin_name:
                    mark_tool_unavailable(bin_name)

        # Avanço de fase após a rodada
        surface = load_surface(recon_target) or surface
        prev_phase = surface.get("phase") or "recon"
        surface, decision = advance_surface_phase(surface)
        save_surface(recon_target, surface)
        if decision.advanced:
            if emit:
                emit(
                    "phase_change",
                    {
                        "from": prev_phase,
                        "to": decision.phase,
                        "reason": decision.reason,
                        "can_finish": decision.can_finish,
                        "surface": surface_summary(surface),
                    },
                )
            pend_after = pending_scan_tools(scan_tools, surface.get("tools_run") or [])
            messages.append(
                {
                    "role": "user",
                    "content": (
                        f"[METODOLOGIA] Fase avançou: {prev_phase} → {decision.phase}. "
                        f"{decision.reason}\n"
                        f"{phase_prompt_block(decision.phase, surface_summary(surface), pending_tools=pend_after)}"
                    ),
                }
            )

        if finished:
            # Soft-block: ainda há pendentes e budget — peça mais uma tool
            pend_now = pending_scan_tools(scan_tools, (load_surface(recon_target) or {}).get("tools_run") or [])
            if pend_now and remaining_tools > 0 and len(pend_now) > 3 and current_phase != "report":
                sample = ", ".join(pend_now[:8])
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            f"[Cobertura] Ainda faltam {len(pend_now)} ferramentas do perfil "
                            f"e há orçamento ({remaining_tools}). "
                            f"Não finalize ainda — rode UMA de: {sample}. "
                            "Só chame finish_mission depois ou na fase report."
                        ),
                    }
                )
                finished = False
                objective_met = False
            else:
                final_message = text
                objective_met = met
                if get_mission_registry().is_cancelled(mission_id):
                    stopped_reason = "cancelled"
                elif met:
                    stopped_reason = "objective_met"
                else:
                    stopped_reason = "finished_early"
                surface = load_surface(recon_target) or surface
                surface["phase"] = "report"
                save_surface(recon_target, surface)
                break

        if text:
            final_message = text

        # Se já pode finalizar e a IA não chamou finish, injeta nudge
        if decision.can_finish and not finished:
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "Fase report: chame finish_mission agora com resumo dos achados "
                        "confirmados, candidatos restantes e conclusão do objetivo."
                    ),
                }
            )

    if not final_message and executions:
        final_message = (
            f"Missão encerrada após {rounds_completed} rodada(s) e {len(executions)} comando(s). "
            "Consulte o relatório para detalhes."
        )
    elif not final_message:
        final_message = "Nenhum comando foi executado durante a missão autônoma."

    # Pipeline assertivo: PoC + re-verificação antes do relatório
    if not get_mission_registry().is_cancelled(mission_id):
        if emit:
            emit("verify_pipeline_start", {"target": recon_target})
        from backend.config import VERIFY_MAX_FINDINGS

        verify_result = run_verification_pipeline(
            recon_target,
            emit=emit,
            mission_id=mission_id,
            max_findings=VERIFY_MAX_FINDINGS,
        )
    else:
        verify_result = None

    bucket = findings_for_report(recon_target)
    lines_sum: list[str] = []
    if bucket["confirmed"]:
        lines_sum.append("**Confirmados:**")
        lines_sum.extend(
            f"- [{f.get('severity', '?').upper()}] {f.get('title')} "
            f"(confiança: {f.get('confidence', '—')})"
            for f in bucket["confirmed"][:15]
        )
    if bucket["false_positive"]:
        lines_sum.append("**Falsos positivos:**")
        lines_sum.extend(
            f"- [{f.get('severity', '?').upper()}] {f.get('title')}"
            for f in bucket["false_positive"][:10]
        )
    if bucket["discarded"]:
        lines_sum.append("**Descartados (não reproduzíveis):**")
        lines_sum.extend(
            f"- [{f.get('severity', '?').upper()}] {f.get('title')}"
            for f in bucket["discarded"][:10]
        )
    if lines_sum:
        final_message += "\n\n### Achados verificados\n" + "\n".join(lines_sum)
    if verify_result:
        final_message += (
            f"\n\n_Pipeline: {verify_result.verify_commands_run} PoC(s) · "
            f"{verify_result.confirmed} confirmado(s) · "
            f"{verify_result.false_positive} FP · "
            f"{verify_result.discarded} descartado(s)._"
        )

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
        surface_target=recon_target,
    )

    surface = load_surface(recon_target) or {}
    status_line = (
        f"\n\n---\n**Auto-Pilot:** {rounds_completed} rodada(s) · "
        f"{len(executions)} comando(s) · "
        f"fase={surface.get('phase', '?')} · risco={profile} · scan={scan_prof} · "
        f"{'objetivo atingido' if objective_met else stopped_reason}"
    )
    final_message = final_message + status_line

    try:
        from backend.database.db import record_scan_from_target

        record_scan_from_target(
            recon_target or target,
            risk_profile=str(profile or ""),
            scan_profile=str(scan_prof or ""),
            rounds=rounds_completed,
            status="completed",
            scan_type="autonomous",
            chat_session_id=str(chat_session_id or ""),
        )
    except Exception:  # noqa: BLE001
        pass

    return AutonomousResponse(
        message=final_message,
        tool_executions=executions,
        report=report,
        objective_met=objective_met,
        rounds=rounds_completed,
        stopped_reason=stopped_reason,
        tools_executed=len(executions),
    )


def _execution_dict(e: ToolExecution) -> dict:
    return {
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


def run_autonomous_stream(
    target: str,
    objective: str,
    model: str | None = None,
    fallback_model: str | None = None,
    mission_id: str | None = None,
    risk_profile: str | None = None,
    chat_session_id: str | None = None,
    scan_profile: str | None = None,
    custom_tools: list[str] | None = None,
    attachments: list | None = None,
) -> Generator[str, None, None]:
    event_queue: Queue[str | None] = Queue()

    def emit(event: str, data: dict) -> None:
        event_queue.put(format_sse(event, data))

    def worker() -> None:
        try:
            result = run_autonomous(
                target,
                objective,
                model=model,
                fallback_model=fallback_model,
                emit=emit,
                mission_id=mission_id,
                risk_profile=risk_profile,
                chat_session_id=chat_session_id,
                scan_profile=scan_profile,
                custom_tools=custom_tools,
                attachments=attachments,
            )
            event_queue.put(
                format_sse(
                    "done",
                    {
                        "message": result.message,
                        "tool_executions": [_execution_dict(e) for e in result.tool_executions],
                        "report": result.report,
                        "objective_met": result.objective_met,
                        "rounds": result.rounds,
                        "stopped_reason": result.stopped_reason,
                        "tools_executed": result.tools_executed,
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
