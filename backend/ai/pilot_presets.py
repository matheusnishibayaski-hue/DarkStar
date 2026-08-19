"""Presets do Piloto por modo de engajamento × perfil de scan."""

from __future__ import annotations

from dataclasses import dataclass

from backend.config import MAX_TOOL_ITERATIONS, MAX_TOOL_ITERATIONS_OFFENSIVE

ENGAGEMENT_MODES = frozenset({"safe", "offensive", "offline"})

DEFAULT_OBJECTIVES: dict[str, dict[str, str]] = {
    "safe": {
        "basic": (
            "Mapear a superfície do alvo autorizado (DNS/portas/HTTP), identificar "
            "candidatos relevantes e verificar o que for confirmável com evidência."
        ),
        "intermediate": (
            "Recon e enumeração ampliada no alvo autorizado; priorizar achados "
            "confirmáveis e cobrir a fila da fase atual (não o catálogo inteiro)."
        ),
        "full": (
            "Engajamento amplo finding-driven: cobrir superfícies quentes, verificar "
            "high/critical e documentar gaps — sem checklist cosmética."
        ),
        "custom": (
            "Usar as ferramentas selecionadas de forma finding-driven no alvo "
            "autorizado; evidência antes de finish."
        ),
    },
    "offensive": {
        "basic": (
            "Kill chain curta no alvo autorizado: enum → hipótese de abuso → PoC "
            "mínimo (auth/IDOR/injection/misconfig)."
        ),
        "intermediate": (
            "Comprometer evidência: encadear enum→vetores de abuso; priorizar "
            "auth bypass, IDOR, API e high/critical."
        ),
        "full": (
            "Engajamento ofensivo autorizado: maximizar superfície de abuso "
            "verificável; não parar no primeiro 200 OK."
        ),
        "custom": (
            "Ferramentas escolhidas com mentalidade adversária no alvo autorizado; "
            "hipótese → PoC → próximo vetor."
        ),
    },
    "offline": {
        "basic": (
            "Recon low-noise no alvo autorizado: passive-first, pegada mínima, "
            "evidência limpa; só escalar ruído se necessário."
        ),
        "intermediate": (
            "Mapear e verificar com OPSEC: rate baixo, artefatos em /tools/output/, "
            "próximo passo o mais silencioso de maior valor."
        ),
        "full": (
            "Cobertura fantasma: superfícies quentes com mínimo rastro; PoC "
            "cirúrgico; documentar o que foi tocado."
        ),
        "custom": (
            "Ferramentas selecionadas em modo fantasma — quieto, preciso, só no alvo autorizado."
        ),
    },
}


@dataclass(frozen=True)
class PilotPreset:
    engagement_mode: str  # safe | offensive | offline
    offensive: bool
    offline: bool
    risk_profile: str  # safe-active | full
    objective_default: str
    per_round_iters: int


def normalize_engagement_mode(value: str | None) -> str:
    m = (value or "safe").strip().lower()
    if m in ENGAGEMENT_MODES:
        return m
    return "safe"


def resolve_engagement_mode(
    *,
    engagement_mode: str | None = None,
    offline_flag: bool = False,
    provider_is_ollama: bool = False,
    elevated: bool = False,
    risk_profile: str | None = None,
) -> str:
    """Prioridade: offline > offensive > safe."""
    requested = normalize_engagement_mode(engagement_mode)
    if offline_flag or provider_is_ollama or requested == "offline":
        return "offline"
    risk = (risk_profile or "").strip().lower()
    if requested == "offensive" and elevated:
        return "offensive"
    if risk == "full" and elevated:
        return "offensive"
    return "safe"


def resolve_pilot_preset(
    *,
    engagement_mode: str,
    scan_profile: str = "basic",
) -> PilotPreset:
    mode = normalize_engagement_mode(engagement_mode)
    scan = (scan_profile or "basic").strip().lower()
    if scan not in {"basic", "intermediate", "full", "custom"}:
        scan = "basic"
    obj_map = DEFAULT_OBJECTIVES.get(mode, DEFAULT_OBJECTIVES["safe"])
    objective = obj_map.get(scan) or obj_map["basic"]
    offline = mode == "offline"
    offensive = mode == "offensive"
    risk = "full" if offensive else "safe-active"
    iters = (
        MAX_TOOL_ITERATIONS_OFFENSIVE
        if offensive
        else (
            max(MAX_TOOL_ITERATIONS, 8) if scan in {"intermediate", "full"} else MAX_TOOL_ITERATIONS
        )
    )
    return PilotPreset(
        engagement_mode=mode,
        offensive=offensive,
        offline=offline,
        risk_profile=risk,
        objective_default=objective,
        per_round_iters=iters,
    )


def default_objective(engagement_mode: str, scan_profile: str) -> str:
    return resolve_pilot_preset(
        engagement_mode=engagement_mode, scan_profile=scan_profile
    ).objective_default
