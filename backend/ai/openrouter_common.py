"""Constantes e helpers compartilhados entre chat e Auto-Pilot (OpenRouter)."""

from __future__ import annotations

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

OPENROUTER_HEADERS = {
    "HTTP-Referer": "https://github.com/matheusnishibayaski-hue/Chat-IA-Kali",
    "X-Title": "Chat IA Kali",
}


def assistant_message_dict(message) -> dict:
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


def is_retryable_error(error: str) -> bool:
    lowered = error.lower()
    return "429" in error or "rate" in lowered or "quota" in lowered or "overloaded" in lowered


def openrouter_error_message(error: str) -> str:
    lowered = error.lower()
    if "401" in error or ("invalid" in lowered and "key" in lowered):
        return (
            "Chave OpenRouter inválida. Configure OPENROUTER_API_KEY no arquivo .env.\n\n"
            "Obtenha uma chave em: https://openrouter.ai/keys"
        )
    if is_retryable_error(error):
        return (
            "Cota ou limite de requisições atingido no OpenRouter.\n\n"
            "O que fazer:\n"
            "• Aguarde alguns minutos se enviou muitas mensagens seguidas\n"
            "• Verifique saldo/cota em https://openrouter.ai/\n"
            "• O fallback tentará deepseek/deepseek-chat-v3.2 automaticamente\n"
            "• Cada comando no chat gera 2–6 chamadas à API (ferramentas + resposta)"
        )
    return f"Erro ao chamar OpenRouter: {error}"
