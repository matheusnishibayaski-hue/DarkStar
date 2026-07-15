import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from openai import OpenAI

from backend.config import (
    GEMINI_FALLBACK_MODEL,
    GEMINI_MODEL,
    MAX_HISTORY_MESSAGES,
    MAX_TOOL_ITERATIONS,
    OPENROUTER_API_KEY,
    SYSTEM_PROMPT,
)
from backend.models_catalog import resolve_model
from backend.executor.kali import execute_in_kali
from backend.executor.result import ExecutionResult, format_result_for_llm
from backend.executor.summarize import summarize_output

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

OPENROUTER_HEADERS = {
    "HTTP-Referer": "https://github.com/matheusnishibayaski-hue/Chat-IA-Kali",
    "X-Title": "Chat IA Kali",
}

KALI_TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "run_kali_tool",
        "description": (
            "Executa comandos reais em um contêiner Kali Linux isolado para varreduras, "
            "análises, consultas técnicas ou reconhecimento. Use sempre esta ferramenta em vez "
            "de apenas sugerir comandos em texto livre."
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
                        "A justificativa técnica de por que este comando está sendo "
                        "executado nesta etapa."
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


def _apply_preferred_tool(user_message: str, preferred_tool: str | None) -> str:
    if not preferred_tool or preferred_tool == "auto":
        return user_message
    return (
        f"[Ferramenta obrigatória: '{preferred_tool}'. "
        f"Execute o comando com esta ferramenta via run_kali_tool e mostre o resultado.]\n\n"
        f"{user_message}"
    )


def _convert_history(history: list[dict]) -> list[dict]:
    messages = []
    trimmed = history[-MAX_HISTORY_MESSAGES:] if len(history) > MAX_HISTORY_MESSAGES else history
    for msg in trimmed:
        role = msg.get("role", "user")
        if role not in ("system", "user", "assistant"):
            role = "user"
        messages.append({"role": role, "content": msg.get("content", "")})
    return messages


def _assistant_message_dict(message) -> dict:
    data: dict = {"role": "assistant", "content": message.content}
    if message.tool_calls:
        data["tool_calls"] = [
            {
                "id": tc.id,
                "type": "function",
                "function": {
                    "name": tc.function.name,
                    "arguments": tc.function.arguments,
                },
            }
            for tc in message.tool_calls
        ]
    return data


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


def _record_execution(command: str, reason: str, executions: list[ToolExecution]) -> str:
    result = execute_in_kali(command, reason)
    summarized, truncated = summarize_output(result.stdout, result.stderr)
    result.truncated_for_llm = truncated
    executions.append(_result_to_tool_execution(result))
    return format_result_for_llm(result, output_text=summarized if truncated else None)


def _is_retryable_error(error: str) -> bool:
    lowered = error.lower()
    return "429" in error or "rate" in lowered or "quota" in lowered or " overloaded" in lowered


def _openrouter_error_message(error: str) -> str:
    lowered = error.lower()
    if "401" in error or "invalid" in lowered and "key" in lowered:
        return (
            "Chave OpenRouter inválida. Configure OPENROUTER_API_KEY no arquivo .env.\n\n"
            "Obtenha uma chave em: https://openrouter.ai/keys"
        )
    if _is_retryable_error(error):
        return (
            "Cota ou limite de requisições atingido no OpenRouter.\n\n"
            "O que fazer:\n"
            "• Aguarde alguns minutos se enviou muitas mensagens seguidas\n"
            "• Verifique saldo/cota em https://openrouter.ai/\n"
            "• O fallback tentará deepseek/deepseek-chat-v3.2 automaticamente\n"
            "• Cada comando no chat gera 2–6 chamadas à API (ferramentas + resposta)"
        )
    return f"Erro ao chamar OpenRouter: {error}"


def _extract_vulnerabilities(tool_executions: list[dict]) -> list[dict]:
    vulns: list[dict] = []
    seen: set[str] = set()

    for ex in tool_executions:
        output = "\n".join(filter(None, [ex.get("stdout", ""), ex.get("stderr", "")]))
        command = ex.get("command", "")

        for match in re.finditer(
            r"\[(critical|high|medium|low|info)\][^\n]*",
            output,
            re.I,
        ):
            line = match.group(0).strip()
            if line not in seen:
                seen.add(line)
                vulns.append({"severity": match.group(1).upper(), "detail": line, "source": command})

        for match in re.finditer(
            r"(\d+/tcp\s+open\s+\S+(?:\s+\S+)*)",
            output,
            re.I,
        ):
            line = match.group(1).strip()
            if line not in seen:
                seen.add(line)
                vulns.append({"severity": "INFO", "detail": f"Porta aberta: {line}", "source": command})

        for match in re.finditer(r"CVE-\d{4}-\d+", output, re.I):
            cve = match.group(0).upper()
            if cve not in seen:
                seen.add(cve)
                vulns.append({"severity": "HIGH", "detail": cve, "source": command})

    return vulns


def generate_report(
    history: list[dict],
    tool_executions: list[dict],
    title: str = "Relatório de Pentest",
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    vulns = _extract_vulnerabilities(tool_executions)

    user_messages = [m["content"] for m in history if m.get("role") == "user"]
    assistant_messages = [m["content"] for m in history if m.get("role") == "assistant"]

    scope = user_messages[0][:200] if user_messages else "Não especificado"
    executive = assistant_messages[-1][:800] if assistant_messages else "Sessão sem conclusões registradas."

    lines = [
        f"# {title}",
        "",
        f"**Data:** {now}  ",
        f"**Ferramenta:** Chat IA Kali v2.0  ",
        f"**Execuções registradas:** {len(tool_executions)}",
        "",
        "---",
        "",
        "## 1. Resumo Executivo",
        "",
        executive,
        "",
        f"**Escopo inicial (primeira solicitação):** {scope}",
        "",
        "---",
        "",
        "## 2. Resumo Técnico",
        "",
        "| # | Comando | Status | Motivo |",
        "|---|---------|--------|--------|",
    ]

    for i, ex in enumerate(tool_executions, 1):
        status = "OK" if ex.get("success") else ("BLOQUEADO" if ex.get("blocked") else f"EXIT {ex.get('exit_code')}")
        cmd = ex.get("command", "").replace("|", "\\|")
        reason = ex.get("reason", "").replace("|", "\\|")[:80]
        lines.append(f"| {i} | `{cmd}` | {status} | {reason} |")

    lines.extend(["", "---", "", "## 3. Tabela de Vulnerabilidades / Achados", ""])

    if vulns:
        lines.extend([
            "| Severidade | Detalhe | Origem |",
            "|------------|---------|--------|",
        ])
        for v in vulns[:50]:
            detail = v["detail"].replace("|", "\\|")[:120]
            source = v["source"].replace("|", "\\|")[:60]
            lines.append(f"| {v['severity']} | {detail} | `{source}` |")
    else:
        lines.append("*Nenhuma vulnerabilidade crítica extraída automaticamente dos logs.*")

    lines.extend([
        "",
        "---",
        "",
        "## 4. Recomendações de Mitigação",
        "",
        "1. **Patch Management:** Aplicar correções para CVEs e serviços desatualizados identificados.",
        "2. **Hardening:** Fechar portas/serviços desnecessários expostos na varredura.",
        "3. **Monitoramento:** Implementar detecção para tentativas de exploração nas superfícies encontradas.",
        "4. **Reteste:** Validar mitigações com nova rodada de scans autorizados.",
        "",
        "---",
        "",
        "## 5. Anexo — Logs",
        "",
    ])

    for ex in tool_executions:
        log_id = ex.get("log_file_id", "")
        cmd = ex.get("command", "")
        if log_id:
            lines.append(f"- `{cmd}` → log `{log_id}` (GET /api/logs/{log_id})")
        else:
            lines.append(f"- `{cmd}` → sem log persistido")

    lines.extend(["", "*Relatório gerado automaticamente pelo Chat IA Kali. Revisão humana obrigatória.*", ""])
    return "\n".join(lines)


def _run_openrouter(
    history: list[dict],
    user_message: str,
    model: str | None = None,
    fallback_model: str | None = None,
) -> ChatResponse:
    if not OPENROUTER_API_KEY:
        return ChatResponse(
            message=(
                "Configure OPENROUTER_API_KEY no arquivo .env.\n\n"
                "Obtenha uma chave em: https://openrouter.ai/keys"
            )
        )

    client = OpenAI(
        base_url=OPENROUTER_BASE_URL,
        api_key=OPENROUTER_API_KEY,
    )

    messages: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages.extend(_convert_history(history))
    messages.append({"role": "user", "content": user_message})

    executions: list[ToolExecution] = []
    model_to_use, fallback_to_use = resolve_model(model, fallback_model)
    nudged = False
    final_text = ""

    for _ in range(MAX_TOOL_ITERATIONS):
        try:
            response = client.chat.completions.create(
                model=model_to_use,
                messages=messages,
                tools=[KALI_TOOL_DEFINITION],
                tool_choice="auto",
                extra_headers=OPENROUTER_HEADERS,
            )
        except Exception as e:
            err = str(e)
            if model_to_use != fallback_to_use and _is_retryable_error(err):
                time.sleep(1)
                model_to_use = fallback_to_use
                continue
            return ChatResponse(message=_openrouter_error_message(err))

        assistant_message = response.choices[0].message

        if not assistant_message.tool_calls:
            if not nudged and not executions:
                nudged = True
                messages.append({
                    "role": "user",
                    "content": (
                        "Execute o comando AGORA com run_kali_tool. "
                        "Não sugira — rode a ferramenta e interprete a saída."
                    ),
                })
                continue

            final_text = assistant_message.content or "Sem resposta da IA."
            return ChatResponse(message=final_text, tool_executions=executions)

        messages.append(_assistant_message_dict(assistant_message))

        for tool_call in assistant_message.tool_calls:
            if tool_call.function.name != "run_kali_tool":
                continue

            try:
                arguments = json.loads(tool_call.function.arguments)
                command = arguments.get("command", "")
                reason = arguments.get("reason", "")
            except Exception:
                command = ""
                reason = "Falha ao decodificar os argumentos fornecidos pela IA."

            result_text = _record_execution(command, reason, executions)
            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": result_text,
            })

    messages.append({
        "role": "user",
        "content": (
            "Por favor, conclua agora e gere a sua resposta/análise final "
            "com base nas execuções realizadas acima."
        ),
    })

    try:
        final_response = client.chat.completions.create(
            model=model_to_use,
            messages=messages,
            extra_headers=OPENROUTER_HEADERS,
        )
        final_text = (
            final_response.choices[0].message.content
            or "Limite de iterações de ferramentas atingido."
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
) -> ChatResponse:
    user_message = _apply_preferred_tool(user_message, preferred_tool)
    return _run_openrouter(history, user_message, model=model, fallback_model=fallback_model)


