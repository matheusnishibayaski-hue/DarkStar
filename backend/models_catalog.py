"""Catálogo de modelos OpenRouter — foco em custo-benefício e variedade."""

from backend.config import GEMINI_FALLBACK_MODEL, GEMINI_MODEL

# IDs antigos / descontinuados → substituto atual
RETIRED_MODEL_ALIASES: dict[str, str] = {
    "deepseek/deepseek-chat-v3.2": "deepseek/deepseek-v3.2",
    "deepseek/deepseek-chat": "deepseek/deepseek-v3.2",
    "openai/gpt-4o-mini-2024-07-18": "openai/gpt-4o-mini",
    "google/gemini-2.0-flash": "google/gemini-2.5-flash",
    "anthropic/claude-3.5-haiku": "anthropic/claude-haiku-4.5",
    "anthropic/claude-3.5-sonnet": "anthropic/claude-sonnet-4.5",
}

# Âncoras baratas e estáveis (tool calling bom o suficiente para Argus)
DEEPSEEK = "deepseek/deepseek-v3.2"
GEMINI_LITE = "google/gemini-2.5-flash-lite"
GEMINI_FLASH = "google/gemini-2.5-flash"
GPT_MINI = "openai/gpt-4o-mini"
CLAUDE_HAIKU = "anthropic/claude-haiku-4.5"

MODEL_TIERS = [
    {
        "id": "economy",
        "label": "Economia",
        "description": "Melhor custo · scans do dia a dia",
        "models": [
            {
                "id": GEMINI_LITE,
                "name": "Gemini Flash-Lite",
                "description": "Google · ultrarrápido e barato",
                "provider": "gemini",
                "fallback": DEEPSEEK,
            },
            {
                "id": DEEPSEEK,
                "name": "DeepSeek V3.2",
                "description": "DeepSeek · forte em código e comandos",
                "provider": "deepseek",
                "fallback": GEMINI_LITE,
            },
            {
                "id": GPT_MINI,
                "name": "ChatGPT 4o mini",
                "description": "OpenAI · barato e estável com tools",
                "provider": "openai",
                "fallback": DEEPSEEK,
            },
            {
                "id": "meta-llama/llama-4-scout",
                "name": "Llama 4 Scout",
                "description": "Meta · ótimo custo-benefício",
                "provider": "llama",
                "fallback": DEEPSEEK,
            },
            {
                "id": "mistralai/mistral-small-3.2-24b-instruct",
                "name": "Mistral Small",
                "description": "Mistral · leve e econômico",
                "provider": "mistral",
                "fallback": GEMINI_LITE,
            },
            {
                "id": "qwen/qwen3.6-flash",
                "name": "Qwen 3.6 Flash",
                "description": "Alibaba · rápido e acessível",
                "provider": "qwen",
                "fallback": DEEPSEEK,
            },
        ],
    },
    {
        "id": "balanced",
        "label": "Equilibrado",
        "description": "Qualidade × preço · uso geral",
        "models": [
            {
                "id": GEMINI_FLASH,
                "name": "Gemini Flash",
                "description": "Google · equilíbrio diário",
                "provider": "gemini",
                "fallback": DEEPSEEK,
            },
            {
                "id": "openai/gpt-4.1-mini",
                "name": "ChatGPT 4.1 mini",
                "description": "OpenAI · melhor que 4o mini",
                "provider": "openai",
                "fallback": GPT_MINI,
            },
            {
                "id": "openai/gpt-5-mini",
                "name": "ChatGPT 5 mini",
                "description": "OpenAI · geração nova, custo contido",
                "provider": "openai",
                "fallback": GPT_MINI,
            },
            {
                "id": CLAUDE_HAIKU,
                "name": "Claude Haiku 4.5",
                "description": "Anthropic · rápido e preciso",
                "provider": "claude",
                "fallback": GEMINI_FLASH,
            },
            {
                "id": "meta-llama/llama-4-maverick",
                "name": "Llama 4 Maverick",
                "description": "Meta · mais capacidade que Scout",
                "provider": "llama",
                "fallback": "meta-llama/llama-4-scout",
            },
            {
                "id": "x-ai/grok-4.20",
                "name": "Grok 4.20",
                "description": "xAI · bom para agentes e tools",
                "provider": "grok",
                "fallback": GEMINI_FLASH,
            },
            {
                "id": DEEPSEEK,
                "name": "DeepSeek Chat",
                "description": "DeepSeek · versátil e barato",
                "provider": "deepseek",
                "fallback": GEMINI_FLASH,
            },
        ],
    },
    {
        "id": "advanced",
        "label": "Avançado",
        "description": "Mais qualidade · missões difíceis",
        "models": [
            {
                "id": "anthropic/claude-sonnet-4.5",
                "name": "Claude Sonnet 4.5",
                "description": "Anthropic · excelente em análise",
                "provider": "claude",
                "fallback": CLAUDE_HAIKU,
            },
            {
                "id": "google/gemini-2.5-pro",
                "name": "Gemini Pro",
                "description": "Google · relatórios e raciocínio",
                "provider": "gemini",
                "fallback": GEMINI_FLASH,
            },
            {
                "id": "openai/o4-mini",
                "name": "ChatGPT o4 mini",
                "description": "OpenAI · raciocínio compacto",
                "provider": "openai",
                "fallback": "openai/gpt-5-mini",
            },
            {
                "id": "deepseek/deepseek-r1",
                "name": "DeepSeek R1",
                "description": "DeepSeek · cadeias longas de raciocínio",
                "provider": "deepseek",
                "fallback": DEEPSEEK,
            },
            {
                "id": "x-ai/grok-4.3",
                "name": "Grok 4.3",
                "description": "xAI · mais capacidade que 4.20",
                "provider": "grok",
                "fallback": "x-ai/grok-4.20",
            },
            {
                "id": "x-ai/grok-4.5",
                "name": "Grok 4.5",
                "description": "xAI · topo da linha (mais caro)",
                "provider": "grok",
                "fallback": "x-ai/grok-4.3",
            },
        ],
    },
]


def normalize_model_id(model_id: str | None) -> str:
    mid = (model_id or "").strip()
    return RETIRED_MODEL_ALIASES.get(mid, mid)


def get_models_catalog() -> dict:
    return {
        "default_model": GEMINI_MODEL,
        "default_fallback": GEMINI_FALLBACK_MODEL,
        "tiers": MODEL_TIERS,
    }


def resolve_model(model: str | None, fallback: str | None) -> tuple[str, str]:
    primary = normalize_model_id((model or "").strip() or GEMINI_MODEL)
    fb = normalize_model_id((fallback or "").strip() or GEMINI_FALLBACK_MODEL)
    if primary == fb:
        for tier in MODEL_TIERS:
            for m in tier["models"]:
                if m["id"] == primary:
                    fb = normalize_model_id(m.get("fallback", GEMINI_FALLBACK_MODEL))
                    break
    return primary, fb


def find_model_display(model_id: str) -> dict | None:
    model_id = normalize_model_id(model_id)
    for tier in MODEL_TIERS:
        for m in tier["models"]:
            if m["id"] == model_id:
                return {**m, "tier": tier["id"], "tier_label": tier["label"]}
    return None
