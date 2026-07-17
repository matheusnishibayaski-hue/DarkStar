"""Catálogo de modelos OpenRouter para seleção na UI."""

from backend.config import GEMINI_FALLBACK_MODEL, GEMINI_MODEL

# IDs descontinuados no OpenRouter → substituto atual (jul/2026)
RETIRED_MODEL_ALIASES: dict[str, str] = {
    "deepseek/deepseek-chat-v3.2": "deepseek/deepseek-v3.2",
}

DEEPSEEK_V32 = "deepseek/deepseek-v3.2"

MODEL_TIERS = [
    {
        "id": "economy",
        "label": "Economia",
        "description": "Menor custo · respostas rápidas",
        "models": [
            {
                "id": "google/gemini-2.5-flash-lite",
                "name": "Gemini Flash-Lite",
                "description": "Respostas mais rápidas · ideal para scans simples",
                "provider": "gemini",
                "fallback": DEEPSEEK_V32,
            },
            {
                "id": DEEPSEEK_V32,
                "name": "DeepSeek V3.2",
                "description": "Baixo custo · forte em código e comandos",
                "provider": "deepseek",
                "fallback": "google/gemini-2.5-flash-lite",
            },
        ],
    },
    {
        "id": "balanced",
        "label": "Equilibrado",
        "description": "Custo moderado · uso geral",
        "models": [
            {
                "id": "google/gemini-2.5-flash",
                "name": "Gemini Flash",
                "description": "Ajuda para tudo · bom equilíbrio",
                "provider": "gemini",
                "fallback": DEEPSEEK_V32,
            },
            {
                "id": DEEPSEEK_V32,
                "name": "DeepSeek Chat",
                "description": "Versátil · análise técnica eficiente",
                "provider": "deepseek",
                "fallback": "google/gemini-2.5-flash",
            },
        ],
    },
    {
        "id": "advanced",
        "label": "Raciocínio",
        "description": "Mais tokens · problemas complexos",
        "models": [
            {
                "id": "google/gemini-2.5-pro",
                "name": "Gemini Pro",
                "description": "Análise profunda · relatórios detalhados",
                "provider": "gemini",
                "fallback": "deepseek/deepseek-r1",
            },
            {
                "id": "deepseek/deepseek-r1",
                "name": "DeepSeek R1",
                "description": "Raciocínio complexo · cadeias longas",
                "provider": "deepseek",
                "fallback": "google/gemini-2.5-pro",
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
                    fb = m.get("fallback", GEMINI_FALLBACK_MODEL)
                    break
    return primary, fb


def find_model_display(model_id: str) -> dict | None:
    model_id = normalize_model_id(model_id)
    for tier in MODEL_TIERS:
        for m in tier["models"]:
            if m["id"] == model_id:
                return {**m, "tier": tier["id"], "tier_label": tier["label"]}
    return None
