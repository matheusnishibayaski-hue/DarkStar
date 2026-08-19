"""Perfis de scan do Piloto automático (conjuntos de ferramentas)."""

from __future__ import annotations

from backend.tool_catalog import TOOL_CATALOG, get_tool_info

# Ferramentas essenciais — recon rápido
BASIC_TOOLS: list[str] = [
    "nmap",
    "ping",
    "whois",
    "dig",
    "subfinder",
    "httpx",
    "nuclei",
    "nikto",
    "gobuster",
    "whatweb",
    "sslscan",
    "curl",
]

# Variedade maior — recon + enumeração web + alguns checks
INTERMEDIATE_TOOLS: list[str] = [
    *BASIC_TOOLS,
    "masscan",
    "naabu",
    "rustscan",
    "amass",
    "dnsenum",
    "dnsrecon",
    "theHarvester",
    "sublist3r",
    "gau",
    "waybackurls",
    "ffuf",
    "feroxbuster",
    "dirsearch",
    "wafw00f",
    "wpscan",
    "katana",
    "dalfox",
    "arjun",
    "testssl.sh",
    "tlsx",
    "enum4linux",
    "smbmap",
    "searchsploit",
    "autorecon",
    "wget",
    "traceroute",
    "uncover",
    "shuffledns",
]

# Todas as ferramentas catalogadas no projeto (UI padrão)
FULL_TOOLS: list[str] = list(TOOL_CATALOG.keys())


def all_allowed_tool_ids() -> list[str]:
    from backend.config_tools import ALLOWED_TOOLS

    return sorted(ALLOWED_TOOLS)


PROFILE_LABELS = {
    "basic": "Básico",
    "intermediate": "Intermediário",
    "full": "Completo",
    "custom": "Personalizado",
}


def normalize_profile(profile: str) -> str:
    p = (profile or "basic").strip().lower()
    if p in PROFILE_LABELS:
        return p
    return "basic"


def resolve_scan_tools(
    profile: str,
    custom_tools: list[str] | None = None,
    *,
    include_all_allowed: bool = False,
    available_only: bool = False,
) -> list[str]:
    p = normalize_profile(profile)
    if p == "basic":
        base = BASIC_TOOLS
    elif p == "intermediate":
        base = INTERMEDIATE_TOOLS
    elif p == "full":
        if include_all_allowed:
            ordered = all_allowed_tool_ids()
            if available_only:
                from backend.executor.tool_presence import filter_available

                ok, _ = filter_available(ordered)
                return ok
            return ordered
        base = FULL_TOOLS
    else:
        base = [t.strip().lower() for t in (custom_tools or []) if t and t.strip()]
        seen: set[str] = set()
        out: list[str] = []
        for t in base:
            if t in seen:
                continue
            seen.add(t)
            out.append(t)
        if available_only:
            from backend.executor.tool_presence import filter_available

            ok, _ = filter_available(out)
            return ok
        return out

    seen: set[str] = set()
    ordered: list[str] = []
    for t in base:
        if t not in seen and t in TOOL_CATALOG:
            seen.add(t)
            ordered.append(t)
    if available_only:
        from backend.executor.tool_presence import filter_available

        ok, _ = filter_available(ordered)
        return ok
    return ordered


def pending_scan_tools(scan_tools: list[str], tools_run: list[str] | None) -> list[str]:
    """Ferramentas do perfil ainda não executadas (ordem do perfil)."""
    used = {str(t).strip().lower() for t in (tools_run or []) if t}
    out: list[str] = []
    seen: set[str] = set()
    for t in scan_tools or []:
        key = str(t).strip().lower()
        if not key or key in used or key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def pending_phase_tools(
    scan_tools: list[str],
    tools_run: list[str] | None,
    phase: str,
) -> list[str]:
    """Pendentes do perfil ∩ preferidos da fase."""
    from backend.ai.phases import PHASE_PREFERRED_TOOLS

    pend = pending_scan_tools(scan_tools, tools_run)
    pref = PHASE_PREFERRED_TOOLS.get((phase or "recon").strip().lower(), frozenset())
    if not pref:
        return pend[:8]
    phase_pend = [t for t in pend if t in pref]
    return phase_pend or pend[:8]


def max_tool_budget(profile: str, tool_count: int) -> int:
    """Limite de execuções de comando na missão."""
    p = normalize_profile(profile)
    if p == "basic":
        return max(20, tool_count * 3)
    if p == "intermediate":
        return max(60, tool_count * 3)
    if p == "full":
        return max(250, tool_count * 2)
    return max(30, tool_count * 3)


def scan_profile_prompt_block(
    profile: str,
    tools: list[str],
    *,
    target: str,
    phase: str | None = None,
) -> str:
    """Fila de prioridade finding-driven — não exige rodar o catálogo inteiro."""
    if not tools:
        return ""
    from backend.ai.phases import PHASE_PREFERRED_TOOLS

    label = PROFILE_LABELS.get(normalize_profile(profile), profile)
    ph = (phase or "recon").strip().lower()
    pref = PHASE_PREFERRED_TOOLS.get(ph, frozenset())
    phase_first = [t for t in tools if t in pref]
    rest = [t for t in tools if t not in pref]
    ordered = (phase_first or tools[:12]) + rest
    # Limitar exemplos no prompt para não estourar contexto
    show = ordered[:24]
    lines = [
        f"[PERFIL DE SCAN: {label}]",
        f"Alvo autorizado: {target}",
        f"Fase atual: {ph}",
        "Regras (finding-driven):",
        "1. A lista é FILA DE PRIORIDADE da fase — não checklist obrigatória de todas as tools.",
        "2. Escolha a próxima melhor ação (superfície + achados); varie ferramentas.",
        "3. finish_mission quando a fase tiver evidência mínima + verify de high/critical,",
        "   ou com coverage_waived=true justificado (host morto / sem superfície / WAF).",
        "4. Ordem lógica: DNS/recon → portas → HTTP → vulns → verify.",
        "",
        f"Fila ({len(tools)} no perfil; mostrando {len(show)}):",
    ]
    for tid in show:
        meta = get_tool_info(tid)
        ex = meta.get("example", "").replace("alvo.com", target).replace("scanme.nmap.org", target)
        mark = "★" if tid in pref else "·"
        lines.append(f"{mark} {tid}: {meta.get('summary', '')} Ex.: {ex}")
    if len(ordered) > len(show):
        lines.append(f"… +{len(ordered) - len(show)} outras no perfil (use se a superfície pedir).")
    return "\n".join(lines)


def profile_catalog(*, offensive: bool = False) -> dict:
    full_count = len(all_allowed_tool_ids()) if offensive else len(FULL_TOOLS)
    return {
        "profiles": [
            {
                "id": "basic",
                "label": PROFILE_LABELS["basic"],
                "description": "Recon essencial (portas, DNS, HTTP, nuclei, nikto).",
                "tool_count": len(resolve_scan_tools("basic")),
            },
            {
                "id": "intermediate",
                "label": PROFILE_LABELS["intermediate"],
                "description": "Recon ampliado + enumeração web e checks extras.",
                "tool_count": len(resolve_scan_tools("intermediate")),
            },
            {
                "id": "full",
                "label": PROFILE_LABELS["full"],
                "description": (
                    f"Todas as ferramentas permitidas no servidor ({full_count}). Pode demorar."
                    if offensive
                    else f"Ferramentas do catálogo da UI ({full_count}). Pode demorar."
                ),
                "tool_count": full_count,
            },
            {
                "id": "custom",
                "label": PROFILE_LABELS["custom"],
                "description": "Escolha manualmente uma ou mais ferramentas.",
                "tool_count": 0,
            },
        ],
        "catalog_size": len(TOOL_CATALOG),
        "allowed_size": len(all_allowed_tool_ids()),
        "offensive": offensive,
    }
