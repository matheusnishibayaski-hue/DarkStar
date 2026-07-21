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
) -> list[str]:
    p = normalize_profile(profile)
    if p == "basic":
        base = BASIC_TOOLS
    elif p == "intermediate":
        base = INTERMEDIATE_TOOLS
    elif p == "full":
        if include_all_allowed:
            return all_allowed_tool_ids()
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
        return out

    seen: set[str] = set()
    ordered: list[str] = []
    for t in base:
        if t not in seen and t in TOOL_CATALOG:
            seen.add(t)
            ordered.append(t)
    return ordered


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
) -> str:
    if not tools:
        return ""
    label = PROFILE_LABELS.get(normalize_profile(profile), profile)
    lines = [
        f"[PERFIL DE SCAN: {label}]",
        f"Alvo autorizado: {target}",
        "Regras obrigatórias:",
        "1. Execute CADA ferramenta da lista abaixo pelo menos UMA vez no alvo (comando real via execute_kali_command).",
        "2. Use exemplos do catálogo Kali adaptados ao alvo; não invente ferramentas fora da lista.",
        "3. Só chame finish_mission depois de ter tentado todas as ferramentas pendentes ou documentado bloqueio/WAF.",
        "4. Priorize ordem lógica: DNS/recon → portas → HTTP → vulns.",
        "",
        f"Ferramentas ({len(tools)}):",
    ]
    for tid in tools:
        meta = get_tool_info(tid)
        ex = meta.get("example", "").replace("alvo.com", target).replace("scanme.nmap.org", target)
        lines.append(f"- {tid}: {meta.get('summary', '')} Ex.: {ex}")
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
