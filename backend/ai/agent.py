import json
from dataclasses import dataclass, field

import httpx
from google import genai
from google.genai import types

from backend.config import (
    AI_PROVIDER,
    GEMINI_API_KEY,
    GEMINI_MODEL,
    MAX_TOOL_ITERATIONS,
    OLLAMA_BASE_URL,
    OLLAMA_MODEL,
    SYSTEM_PROMPT,
)
from backend.executor.kali import execute_in_kali
from backend.executor.result import format_result_for_llm
from backend.tools.definitions import KALI_TOOL_DEFINITION


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
            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=contents,
                config=config,
            )

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

        final = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=contents,
            config=config,
        )
        text = final.text or "Limite de iterações de ferramentas atingido."
        return ChatResponse(message=text, tool_executions=executions)

    except Exception as e:
        error = str(e)
        if "API_KEY_INVALID" in error or "API key not valid" in error.lower():
            return ChatResponse(
                message="Chave Gemini inválida. Gere uma nova em https://aistudio.google.com/apikey"
            )
        if "429" in error or "RESOURCE_EXHAUSTED" in error:
            return ChatResponse(
                message="Limite de requisições do Gemini atingido. Aguarde alguns minutos e tente novamente."
            )
        return ChatResponse(message=f"Erro ao chamar Gemini: {error}")


def _run_ollama(history: list[dict], user_message: str) -> ChatResponse:
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    for msg in history:
        messages.append({"role": msg["role"], "content": msg["content"]})
    messages.append({"role": "user", "content": user_message})
    executions: list[ToolExecution] = []

    for _ in range(MAX_TOOL_ITERATIONS):
        payload = {
            "model": OLLAMA_MODEL,
            "messages": messages,
            "tools": [KALI_TOOL_DEFINITION],
            "stream": False,
        }

        try:
            resp = httpx.post(
                f"{OLLAMA_BASE_URL}/api/chat",
                json=payload,
                timeout=120.0,
            )
            resp.raise_for_status()
            data = resp.json()
        except httpx.ConnectError:
            return ChatResponse(
                message=(
                    f"Não foi possível conectar ao Ollama em {OLLAMA_BASE_URL}. "
                    "Inicie o Ollama ou use AI_PROVIDER=gemini com GEMINI_API_KEY."
                )
            )
        except Exception as e:
            return ChatResponse(message=f"Erro ao chamar Ollama: {e}")

        msg = data.get("message", {})
        tool_calls = msg.get("tool_calls", [])

        if tool_calls:
            messages.append(msg)

            for tool_call in tool_calls:
                fn = tool_call.get("function", {})
                args = fn.get("arguments", {})
                if isinstance(args, str):
                    args = json.loads(args)

                result = execute_in_kali(args["command"], args.get("reason", ""))
                executions.append(ToolExecution(
                    command=result.command,
                    reason=result.reason,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    exit_code=result.exit_code,
                    success=result.success,
                    blocked=result.blocked,
                ))

                messages.append({
                    "role": "tool",
                    "content": format_result_for_llm(result),
                })
            continue

        return ChatResponse(
            message=msg.get("content", "Sem resposta da IA."),
            tool_executions=executions,
        )

    return ChatResponse(
        message="Limite de iterações de ferramentas atingido.",
        tool_executions=executions,
    )


def chat(history: list[dict], user_message: str, preferred_tool: str | None = None) -> ChatResponse:
    user_message = _apply_preferred_tool(user_message, preferred_tool)
    if AI_PROVIDER == "ollama":
        return _run_ollama(history, user_message)
    return _run_gemini(history, user_message)
