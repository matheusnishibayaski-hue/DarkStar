import time

from dataclasses import dataclass, field

from google import genai
from google.genai import types

from backend.config import (
    GEMINI_API_KEY,
    GEMINI_FALLBACK_MODEL,
    GEMINI_MODEL,
    MAX_TOOL_ITERATIONS,
    SYSTEM_PROMPT,
)
from backend.executor.kali import execute_in_kali
from backend.executor.result import format_result_for_llm


@dataclass
class ToolExecution:
    command: str
    reason: str
    stdout: str
    stderr: str
    exit_code: int
    success: bool
    blocked: bool = False


@dataclass
class ChatResponse:
    message: str
    tool_executions: list[ToolExecution] = field(default_factory=list)


def _build_contents(history: list[dict], user_message: str) -> list[types.Content]:
    contents = []
    for msg in history:
        role = "user" if msg["role"] == "user" else "model"
        contents.append(types.Content(role=role, parts=[types.Part(text=msg["content"])]))
    contents.append(types.Content(role="user", parts=[types.Part(text=user_message)]))
    return contents


def _apply_preferred_tool(user_message: str, preferred_tool: str | None) -> str:
    if not preferred_tool or preferred_tool == "auto":
        return user_message
    return (
        f"[Ferramenta obrigatória: '{preferred_tool}'. "
        f"Execute o comando com esta ferramenta via run_kali_tool e mostre o resultado.]\n\n"
        f"{user_message}"
    )


def _record_execution(command: str, reason: str, executions: list[ToolExecution]) -> str:
    result = execute_in_kali(command, reason)
    executions.append(ToolExecution(
        command=result.command,
        reason=result.reason,
        stdout=result.stdout,
        stderr=result.stderr,
        exit_code=result.exit_code,
        success=result.success,
        blocked=result.blocked,
    ))
    return format_result_for_llm(result)


def _parse_function_args(fc) -> dict:
    if getattr(fc, "args", None):
        return dict(fc.args)
    inner = getattr(fc, "function_call", None)
    if inner and getattr(inner, "args", None):
        return dict(inner.args)
    return {}


def _is_quota_error(error: str) -> bool:
    return "429" in error or "RESOURCE_EXHAUSTED" in error


def _gemini_error_message(error: str) -> str:
    if "API_KEY_INVALID" in error or "API key not valid" in error.lower():
        return "Chave Gemini inválida. Gere uma nova em https://aistudio.google.com/apikey"
    if _is_quota_error(error):
        return (
            "Cota do Gemini esgotada para este modelo/chave.\n\n"
            "O que fazer:\n"
            "• No .env, use GEMINI_MODEL=gemini-2.5-flash-lite (mais cota no plano gratuito)\n"
            "• Gere sua própria chave em https://aistudio.google.com/apikey (não compartilhe)\n"
            "• Aguarde alguns minutos se enviou muitas mensagens seguidas\n"
            "• Cada comando no chat gera 2–6 chamadas à API (ferramentas + resposta)"
        )
    return f"Erro ao chamar Gemini: {error}"


def _generate_content(client, model: str, contents, config):
    models = [model]
    if GEMINI_FALLBACK_MODEL not in models:
        models.append(GEMINI_FALLBACK_MODEL)

    last_error = None
    for attempt, current_model in enumerate(models):
        try:
            return client.models.generate_content(
                model=current_model,
                contents=contents,
                config=config,
            )
        except Exception as e:
            last_error = e
            if not _is_quota_error(str(e)) or attempt >= len(models) - 1:
                raise
            time.sleep(2)

    raise last_error  # type: ignore[misc]


def _run_gemini(history: list[dict], user_message: str) -> ChatResponse:
    if not GEMINI_API_KEY:
        return ChatResponse(
            message=(
                "Configure GEMINI_API_KEY no arquivo .env.\n\n"
                "Chave gratuita em: https://aistudio.google.com/apikey"
            )
        )

    executions: list[ToolExecution] = []

    def run_kali_tool(command: str, reason: str) -> str:
        """Executa uma ferramenta de segurança no ambiente Kali Linux isolado via Docker.

        Args:
            command: Comando completo (ex: nmap -sV scanme.nmap.org, dig example.com).
            reason: Breve explicação do porquê este comando é necessário.

        Returns:
            Saída do comando (stdout/stderr) para interpretação.
        """
        return _record_execution(command, reason, executions)

    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
        contents = _build_contents(history, user_message)
        config = types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            tools=[run_kali_tool],
            tool_config=types.ToolConfig(
                function_calling_config=types.FunctionCallingConfig(
                    mode=types.FunctionCallingConfigMode.VALIDATED,
                ),
            ),
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        )
        nudged = False

        for _ in range(MAX_TOOL_ITERATIONS):
            response = _generate_content(client, GEMINI_MODEL, contents, config)

            function_calls = response.function_calls or []

            if not function_calls:
                if not nudged and not executions:
                    nudged = True
                    contents.append(types.Content(
                        role="user",
                        parts=[types.Part(text=(
                            "Execute o comando AGORA com run_kali_tool. "
                            "Não sugira — rode a ferramenta e interprete a saída."
                        ))],
                    ))
                    continue

                text = response.text or "Sem resposta da IA."
                return ChatResponse(message=text, tool_executions=executions)

            if response.candidates and response.candidates[0].content:
                contents.append(response.candidates[0].content)

            response_parts = []
            for fc in function_calls:
                args = _parse_function_args(fc)
                command = args.get("command", "")
                reason = args.get("reason", "")
                name = fc.name or "run_kali_tool"

                try:
                    result_text = _record_execution(command, reason, executions)
                    response_parts.append(types.Part.from_function_response(
                        name=name,
                        response={"result": result_text},
                    ))
                except Exception as e:
                    response_parts.append(types.Part.from_function_response(
                        name=name,
                        response={"error": str(e)},
                    ))

            contents.append(types.Content(role="user", parts=response_parts))

        final = _generate_content(client, GEMINI_MODEL, contents, config)
        text = final.text or "Limite de iterações de ferramentas atingido."
        return ChatResponse(message=text, tool_executions=executions)

    except Exception as e:
        return ChatResponse(message=_gemini_error_message(str(e)))


def chat(history: list[dict], user_message: str, preferred_tool: str | None = None) -> ChatResponse:
    user_message = _apply_preferred_tool(user_message, preferred_tool)
    return _run_gemini(history, user_message)
