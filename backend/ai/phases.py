"""Motor de fases metodológicas + perfis de risco para Auto-Pilot."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Ordem fixa da metodologia
PHASES = ("recon", "enumerate", "vuln_scan", "verify", "report")

PHASE_LABELS = {
    "recon": "Reconhecimento",
    "enumerate": "Enumeração",
    "vuln_scan": "Varredura de vulnerabilidades",
    "verify": "Verificação de achados",
    "report": "Relatório / encerramento",
}

PHASE_GOALS = {
    "recon": (
        "Mapear hosts, subdomínios e presença na internet. "
        "Ferramentas típicas: subfinder, amass, whois, dig, httpx (probe leve)."
    ),
    "enumerate": (
        "Descobrir portas, serviços, URLs e tecnologias. "
        "Ferramentas típicas: nmap, httpx, whatweb, gobuster/feroxbuster/ffuf."
    ),
    "vuln_scan": (
        "Identificar vulnerabilidades candidatas (não explorar de forma destrutiva). "
        "Ferramentas típicas: nuclei, nikto, sslscan, wpscan."
    ),
    "verify": (
        "Confirmar ou descartar achados candidatos com PoC mínimo e não destrutivo. "
        "Priorize findings high/critical. Marque mentalmente confirmed vs falso positivo."
    ),
    "report": ("Resuma achados confirmados, evidências e gaps. Chame finish_mission."),
}

# Ferramentas típicas por fase (sugestão + allowlist soft)
PHASE_PREFERRED_TOOLS: dict[str, frozenset[str]] = {
    "recon": frozenset(
        {
            "subfinder",
            "amass",
            "assetfinder",
            "findomain",
            "whois",
            "dig",
            "host",
            "dnsx",
            "httpx",
            "theHarvester",
            "theharvester",
            "gau",
            "waybackurls",
            "crt",
        }
    ),
    "enumerate": frozenset(
        {
            "nmap",
            "naabu",
            "masscan",
            "rustscan",
            "httpx",
            "whatweb",
            "wafw00f",
            "gobuster",
            "feroxbuster",
            "ffuf",
            "dirsearch",
            "katana",
            "hakrawler",
        }
    ),
    "vuln_scan": frozenset(
        {
            "nuclei",
            "nikto",
            "sslscan",
            "sslyze",
            "testssl.sh",
            "wpscan",
            "cmsmap",
            "jaeles",
        }
    ),
    "verify": frozenset(
        {
            "curl",
            "httpx",
            "nmap",
            "nuclei",
            "openssl",
            "nikto",
        }
    ),
    "report": frozenset(),
}

# Perfis de risco — tools bloqueadas (além do scope)
PROFILE_BLOCKED: dict[str, frozenset[str]] = {
    "passive": frozenset(
        {
            "nmap",
            "masscan",
            "zmap",
            "rustscan",
            "naabu",
            "nuclei",
            "nikto",
            "sqlmap",
            "hydra",
            "medusa",
            "ncrack",
            "john",
            "hashcat",
            "gobuster",
            "feroxbuster",
            "ffuf",
            "wfuzz",
            "dirb",
            "dirsearch",
            "wpscan",
            "metasploit",
            "msfconsole",
            "searchsploit",
            "aircrack-ng",
            "airodump-ng",
            "wifite",
            "mdk4",
            "hping3",
        }
    ),
    "safe-active": frozenset(
        {
            "sqlmap",
            "hydra",
            "medusa",
            "ncrack",
            "john",
            "hashcat",
            "metasploit",
            "msfconsole",
            "msfvenom",
            "aircrack-ng",
            "airodump-ng",
            "aireplay-ng",
            "wifite",
            "mdk4",
            "hping3",
            "yersinia",
        }
    ),
    "full": frozenset(),
}

VALID_PROFILES = frozenset(PROFILE_BLOCKED.keys())


@dataclass
class PhaseDecision:
    phase: str
    advanced: bool
    reason: str
    can_finish: bool


def normalize_risk_profile(value: str | None) -> str:
    profile = (value or "safe-active").strip().lower()
    if profile not in VALID_PROFILES:
        return "safe-active"
    return profile


def tool_binary(command_or_tool: str) -> str:
    parts = (command_or_tool or "").strip().split()
    if not parts:
        return ""
    return parts[0].split("/")[-1].lower()


def is_tool_allowed(
    tool_or_command: str,
    *,
    phase: str,
    risk_profile: str,
) -> tuple[bool, str]:
    binary = tool_binary(tool_or_command)
    if not binary:
        return False, "Comando vazio."

    profile = normalize_risk_profile(risk_profile)
    blocked = PROFILE_BLOCKED.get(profile, frozenset())
    if binary in blocked:
        return (
            False,
            f"Ferramenta '{binary}' bloqueada no perfil de risco '{profile}'. "
            f"Use ferramentas adequadas à fase '{phase}' ou eleve o perfil (com autorização).",
        )

    # Na fase report, só finish_mission (tratado fora); tools Kali desencorajadas
    if phase == "report":
        return (
            False,
            "Fase 'report': não execute mais ferramentas. Chame finish_mission com o resumo.",
        )

    return True, ""


def phase_prompt_block(
    phase: str,
    surface_summary: dict[str, Any] | None = None,
    *,
    pending_tools: list[str] | None = None,
) -> str:
    label = PHASE_LABELS.get(phase, phase)
    goal = PHASE_GOALS.get(phase, "")
    preferred = sorted(PHASE_PREFERRED_TOOLS.get(phase, frozenset()))
    preferred_txt = ", ".join(preferred[:12]) if preferred else "(nenhuma — finalize)"
    summary_txt = ""
    if surface_summary:
        summary_txt = (
            f"\nEstado do Attack Surface: hosts={surface_summary.get('hosts_count', 0)}, "
            f"ports={surface_summary.get('ports_count', 0)}, "
            f"urls={surface_summary.get('urls_count', 0)}, "
            f"findings_candidatos={surface_summary.get('findings_candidates', 0)}, "
            f"findings_confirmados={surface_summary.get('findings_confirmed', 0)}."
        )
    pending_txt = ""
    if pending_tools:
        sample = ", ".join(pending_tools[:10])
        pending_txt = (
            f"\nPendentes do perfil nesta missão (priorize uma não usada): {sample}"
            f"{'…' if len(pending_tools) > 10 else ''}."
        )
    return (
        f"[FASE ATUAL: {phase} — {label}]\n"
        f"Objetivo da fase: {goal}\n"
        f"Ferramentas preferidas da fase: {preferred_txt}."
        f"{pending_txt}"
        f"{summary_txt}\n"
        "Varie as ferramentas — não repita sempre as mesmas. "
        "Siga a metodologia: não pule para exploração destrutiva. "
        "Só chame finish_mission na fase report (ou se o objetivo já estiver claramente cumprido)."
    )


def evaluate_phase_advance(surface: dict[str, Any]) -> PhaseDecision:
    """Decide se a fase atual pode avançar com base no Attack Surface.

    Critérios por artefato (hosts/DNS, ports/URLs, findings) — não por contagem
    solta de comandos.
    """
    phase = surface.get("phase") or "recon"
    if phase not in PHASES:
        phase = "recon"

    hosts = surface.get("hosts") or []
    ports = surface.get("ports") or []
    urls = surface.get("urls") or []
    findings = surface.get("findings") or []
    tools = set(surface.get("tools_run") or [])
    candidates = [f for f in findings if f.get("status") == "candidate"]
    confirmed = [f for f in findings if f.get("status") == "confirmed"]
    open_items = [f for f in findings if f.get("status") in {"candidate", "inconclusive"}]

    def _sev(f: dict) -> str:
        return str(f.get("severity") or "").strip().lower()

    high_open = [f for f in open_items if _sev(f) in {"high", "critical"}]
    verified_attempted = any(f.get("verified_at") for f in findings) or any(
        f.get("status") in {"confirmed", "false_positive"} for f in findings
    )
    high_verified = any(
        _sev(f) in {"high", "critical"}
        and (f.get("verified_at") or f.get("status") in {"confirmed", "false_positive"})
        for f in findings
    )

    if phase == "recon":
        # Seed host sozinho não basta — precisa tool de recon ou hosts extras
        recon_tool = bool(tools & PHASE_PREFERRED_TOOLS["recon"])
        extra_hosts = len(hosts) > 1
        if recon_tool or extra_hosts:
            return PhaseDecision("enumerate", True, "Recon com evidência (DNS/hosts).", False)
        return PhaseDecision(phase, False, "Execute recon (subfinder/dig/whois/httpx).", False)

    if phase == "enumerate":
        if ports or urls:
            return PhaseDecision("vuln_scan", True, "Superfície enumerada (ports/URLs).", False)
        enum_tool = bool(tools & PHASE_PREFERRED_TOOLS["enumerate"])
        if enum_tool and (ports or urls or hosts):
            # Tool rodou mas ainda sem ports/urls — continue enum
            return PhaseDecision(phase, False, "Enumere portas/URLs/serviços.", False)
        return PhaseDecision(phase, False, "Enumere portas/URLs/serviços.", False)

    if phase == "vuln_scan":
        vuln_tool = bool(tools & PHASE_PREFERRED_TOOLS["vuln_scan"])
        has_surface = bool(ports or urls)
        if candidates or confirmed:
            return PhaseDecision("verify", True, "Candidatos encontrados — verificar.", False)
        if vuln_tool and has_surface:
            return PhaseDecision(
                "report",
                True,
                "Varredura sem candidatos — ir ao relatório.",
                True,
            )
        return PhaseDecision(phase, False, "Execute varredura de vulnerabilidades.", False)

    if phase == "verify":
        if high_open and not (verified_attempted or high_verified):
            return PhaseDecision(
                phase,
                False,
                f"Verifique {len(high_open)} achado(s) high/critical antes de report.",
                False,
            )
        if verified_attempted or not open_items:
            return PhaseDecision(
                "report",
                True,
                "Verificação suficiente — pipeline PoC fechará o relatório.",
                True,
            )
        return PhaseDecision(
            phase,
            False,
            f"Verifique {len(open_items)} achado(s) candidato(s)/inconclusivo(s).",
            False,
        )

    # report
    return PhaseDecision("report", False, "Finalize com finish_mission.", True)


def advance_surface_phase(surface: dict[str, Any]) -> tuple[dict[str, Any], PhaseDecision]:
    decision = evaluate_phase_advance(surface)
    if not decision.advanced:
        return surface, decision

    completed = list(surface.get("phases_completed") or [])
    current = surface.get("phase") or "recon"
    if current not in completed:
        completed.append(current)
    surface["phases_completed"] = completed
    surface["phase"] = decision.phase
    return surface, decision


def kickoff_for_phase(
    *,
    phase: str,
    target: str,
    objective: str,
    round_idx: int,
    max_rounds: int,
    tools_executed: int,
    surface_summary_data: dict[str, Any] | None,
    surface: dict[str, Any] | None = None,
    offensive: bool = False,
    offline: bool = False,
) -> str:
    block = phase_prompt_block(phase, surface_summary_data)
    from backend.ai.tool_playbook import compact_playbook_block, next_actions_from_surface

    surf = surface or surface_summary_data or {}
    actions = next_actions_from_surface(
        surf, phase=phase, offensive=offensive, offline=offline, limit=5
    )
    next_txt = ""
    if actions:
        next_txt = "\n[NEXT BEST ACTIONS]\n" + "\n".join(f"- {a}" for a in actions)
    playbook = ""
    if round_idx == 0:
        playbook = "\n\n" + compact_playbook_block(
            surf, phase=phase, offensive=offensive, offline=offline
        )

    if round_idx == 0:
        return (
            f"Missão autônoma iniciada (metodologia finding-driven).\n"
            f"Alvo: {target}\n"
            f"Objetivo: {objective}\n\n"
            f"{block}{next_txt}{playbook}\n\n"
            "Execute o primeiro comando via run_kali_tool agora, adequado à fase atual."
        )
    return (
        f"Rodada {round_idx + 1}/{max_rounds}. Comandos até agora: {tools_executed}.\n"
        f"{block}{next_txt}\n"
        "Analise o Attack Surface, execute a próxima melhor ação da fase "
        "ou chame finish_mission se estiver na fase report / objetivo cumprido."
    )
