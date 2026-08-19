"""Playbook compacto de ferramentas + próximas ações a partir do Attack Surface."""

from __future__ import annotations

from typing import Any

# Exemplos curtos por categoria (flags válidas, SecLists, /tools/output/)
_CATEGORY_BLOCKS: list[tuple[str, str]] = [
    (
        "DNS / OSINT",
        "subfinder -d ALVO -silent | tee /tools/output/subs.txt\n"
        "dig ALVO ANY +noall +answer\n"
        "amass enum -passive -d ALVO -o /tools/output/amass.txt",
    ),
    (
        "Portas / serviços",
        "nmap -sV -sC -oA /tools/output/nmap ALVO\n"
        "naabu -host ALVO -silent\n"
        "rustscan -a ALVO -- -sV",
    ),
    (
        "HTTP enum",
        "httpx -u https://ALVO -title -tech-detect -status-code -silent\n"
        "katana -u https://ALVO -d 2 -o /tools/output/katana.txt\n"
        "ffuf -u https://ALVO/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403",
    ),
    (
        "Vuln / templates",
        "nuclei -u https://ALVO -severity critical,high,medium -silent -jsonl -o /tools/output/nuclei.jsonl\n"
        "nikto -h https://ALVO\n"
        "sslscan ALVO",
    ),
    (
        "Auth / API",
        "arjun -u https://ALVO/api/endpoint\n"
        "curl -sk https://ALVO/swagger.json\n"
        "httpx -u https://ALVO/api/v1 -path /openapi.json,/swagger.json -mc 200",
    ),
    (
        "SMB / AD (se porta 445/389)",
        "enum4linux -a ALVO\n"
        "smbmap -H ALVO\n"
        "nmap -p 445 --script smb-enum-shares,smb-os-discovery ALVO",
    ),
]

_OFFENSIVE_ATTACK_PATHS = """ATTACK PATHS (priorize — alvo autorizado):
- Auth/session: default creds, bypass de login, cookie/JWT fraco, reset flow
- IDOR / BOLA: IDs sequenciais em /api/.../user/{id}, troca de owner
- Injection: params refletidos → XSS/SQLi leve (nuclei + curl PoC)
- Upload / path traversal: endpoints de file, LFI clássico (?file=../../)
- Admin / debug: /admin, /actuator, /.env, /graphql introspection
- API abuse: mass assignment, verb tampering, rate-limit ausente
Regra: cada achado fraco vira hipótese → PoC mínimo → próximo vetor de maior ROI."""

_OFFLINE_OPSEC = """OPSEC / LOW-NOISE (modo fantasma — alvo autorizado):
- Passiveive-first: dig/whois/subfinder/amass -passive/CT antes de syn-scan largo
- Rate baixo; evite -T5, masscan full e wordlists enormes sem necessidade
- Preferir -silent / saída mínima; artefatos só em /tools/output/
- Não redispare a mesma superfície ruidosa; aprofunde o fio mais quieto
- PoC mínimo: um request cirúrgico > dump completo"""


def _port_nums(ports: list[Any]) -> set[int]:
    out: set[int] = set()
    for p in ports or []:
        if isinstance(p, dict):
            raw = p.get("port") or p.get("number")
        else:
            raw = p
        try:
            out.add(int(str(raw).split("/")[0]))
        except (TypeError, ValueError):
            continue
    return out


def _sev(f: dict) -> str:
    return str(f.get("severity") or f.get("severity_label") or "").strip().lower()


def next_actions_from_surface(
    surface: dict[str, Any] | None,
    *,
    phase: str | None = None,
    offensive: bool = False,
    offline: bool = False,
    limit: int = 5,
) -> list[str]:
    """Sugestões acionáveis a partir do surface (ou summary-like dict)."""
    if not surface:
        return []
    actions: list[str] = []
    ph = (phase or surface.get("phase") or "").strip().lower()
    ports = surface.get("ports") or []
    urls = surface.get("urls") or []
    hosts = surface.get("hosts") or []
    findings = surface.get("findings") or []
    techs = surface.get("services") or surface.get("technologies") or []
    port_nums = _port_nums(ports if isinstance(ports, list) else [])

    # Summary-only shapes (hosts_count etc.)
    if not ports and not urls and "ports_count" in surface:
        if int(surface.get("ports_count") or 0) == 0 and ph in {"", "recon", "enumerate"}:
            if offline:
                actions.append("Passive DNS/OSINT primeiro (dig/subfinder) — só depois ports leves")
            else:
                actions.append("Enumere portas (nmap -sV) no alvo autorizado")
        if int(surface.get("urls_count") or 0) == 0:
            actions.append("Probe HTTP (httpx) e descubra URLs (katana/gau)")
        if int(surface.get("findings_candidates") or 0) > 0:
            actions.append("Verifique candidatos high/critical com PoC mínimo (curl/nuclei)")
        return actions[:limit]

    if 80 in port_nums or 443 in port_nums or 8080 in port_nums or 8443 in port_nums:
        scheme = "https" if (443 in port_nums or 8443 in port_nums) else "http"
        actions.append(f"HTTP ativo — {scheme} probe (httpx -title -tech-detect) + crawl (katana)")
        actions.append("Varredura templates: nuclei -severity critical,high,medium -jsonl")

    if 445 in port_nums or 139 in port_nums:
        actions.append("SMB aberto — enum4linux/smbmap (shares, usuários)")
    if 22 in port_nums:
        actions.append("SSH — banner/versão (nmap -sV -p 22); checar defaults só se autorizado")
    if 389 in port_nums or 636 in port_nums:
        actions.append("LDAP — enumeração leve alinhada ao perfil de risco")

    url_blob = " ".join(str(u) for u in (urls or [])[:40]).lower()
    if any(x in url_blob for x in ("swagger", "openapi", "/api/", "graphql")):
        actions.append("Superfície API — mapear OpenAPI/GraphQL e testar IDOR/authz")
    if any(x in url_blob for x in ("login", "signin", "auth", "oauth")):
        actions.append("Fluxo de auth exposto — hipóteses de bypass/session/default creds")
    if any(x in url_blob for x in ("upload", "file", "import")):
        actions.append("Upload/file — testar path traversal e tipos perigosos (não destrutivo)")

    tech_blob = " ".join(str(t) for t in (techs or [])[:40]).lower()
    if any(x in tech_blob for x in ("wordpress", "wp")):
        actions.append("WordPress — wpscan (plugins/users) no alvo autorizado")
    if any(x in tech_blob for x in ("node", "express", "nestjs")):
        actions.append("Stack Node — foco auth/JWT, mass assignment e IDOR em APIs")

    candidates = [f for f in findings if isinstance(f, dict) and f.get("status") == "candidate"]
    high = [f for f in candidates if _sev(f) in {"high", "critical"}]
    if high:
        actions.insert(
            0,
            f"Prioridade: verificar {len(high)} candidato(s) high/critical com evidência",
        )
    elif candidates:
        actions.append(f"Confirmar/descartar {len(candidates)} candidato(s) restantes")

    if not hosts and ph == "recon":
        actions.append("Recon DNS/OSINT (subfinder/dig/whois) antes de enum profunda")

    if offline:
        quiet = [
            a
            for a in actions
            if any(
                k in a.lower()
                for k in ("passive", "dns", "httpx", "verificar", "poc", "api", "auth")
            )
        ]
        actions = quiet + [a for a in actions if a not in quiet]
        if ph in {"", "recon"} and not any("passive" in a.lower() for a in actions):
            actions.insert(0, "Passive-first no alvo — dig/subfinder antes de barulho")

    if offensive and not offline:
        offensive_boost = [
            a
            for a in actions
            if any(
                k in a.lower()
                for k in ("idor", "auth", "api", "verificar", "smb", "upload", "nuclei")
            )
        ]
        merged = offensive_boost + [a for a in actions if a not in offensive_boost]
        actions = merged

    # dedupe preserve order
    seen: set[str] = set()
    out: list[str] = []
    for a in actions:
        if a not in seen:
            seen.add(a)
            out.append(a)
        if len(out) >= limit:
            break
    return out


_PHASE_CATEGORIES: dict[str, frozenset[str]] = {
    "recon": frozenset({"DNS / OSINT"}),
    "enumerate": frozenset({"Portas / serviços", "HTTP enum", "SMB / AD (se porta 445/389)"}),
    "vuln_scan": frozenset({"Vuln / templates", "Auth / API", "HTTP enum"}),
    "verify": frozenset({"Auth / API", "Vuln / templates", "HTTP enum"}),
    "report": frozenset(),
}


def classify_target_kind(target: str) -> str:
    """url | ip | domain."""
    t = (target or "").strip().lower()
    if t.startswith("http://") or t.startswith("https://"):
        return "url"
    host = t.split("/")[0].split(":")[0]
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts if p.isdigit()):
        try:
            if all(0 <= int(p) <= 255 for p in parts):
                return "ip"
        except ValueError:
            pass
    return "domain"


def adaptive_first_actions(target: str, *, offline: bool = False) -> list[str]:
    kind = classify_target_kind(target)
    if kind == "url":
        return [
            "Alvo é URL — httpx -title -tech-detect no URL autorizado",
            "Em seguida crawl leve (katana) se HTTP responder",
        ]
    if kind == "ip":
        if offline:
            return ["Alvo é IP — nmap -sV focado (portas top) com rate moderado"]
        return ["Alvo é IP — nmap -sV -sC no IP autorizado"]
    # domain
    if offline:
        return [
            "Alvo é domínio — passive DNS primeiro (dig/subfinder)",
            "Só depois probe HTTP quieto (httpx)",
        ]
    return [
        "Alvo é domínio — dig/subfinder/whois antes de port scan largo",
        "Em seguida httpx no host se DNS resolver",
    ]


def rank_pending_tools(
    pending: list[str],
    *,
    offline: bool = False,
    offensive: bool = False,
) -> list[str]:
    quiet = {
        "dig",
        "whois",
        "host",
        "subfinder",
        "amass",
        "httpx",
        "curl",
        "dnsx",
        "gau",
        "waybackurls",
    }
    loud = {"masscan", "rustscan", "nmap", "nikto", "ffuf", "gobuster", "feroxbuster"}
    attack = {"nuclei", "dalfox", "sqlmap", "wpscan", "nikto", "ffuf"}

    def score(t: str) -> int:
        if offline:
            if t in quiet:
                return 0
            if t in loud:
                return 5
            return 2
        if offensive:
            if t in attack:
                return 0
            if t in quiet:
                return 1
            return 2
        # safe: prefer phase-natural order already in pending
        return 1

    return sorted(pending, key=score)


def compact_playbook_block(
    surface: dict[str, Any] | None = None,
    *,
    phase: str | None = None,
    offensive: bool = False,
    offline: bool = False,
    max_chars: int = 3500,
    target_hint: str | None = None,
) -> str:
    """Texto curto para injetar no system prompt do chat/piloto."""
    lines: list[str] = [
        "[TOOL PLAYBOOK — use run_kali_tool com comandos da whitelist; ALVO = host autorizado]",
        "Wordlists: /usr/share/seclists · Artefatos: /tools/output/",
        "Sem ; | & ou redirecionamentos de shell. Varie ferramentas; não pare no primeiro 200 OK.",
        "",
    ]
    ph = (phase or "").strip().lower()
    allowed_cats = _PHASE_CATEGORIES.get(ph)
    for title, body in _CATEGORY_BLOCKS:
        if allowed_cats is not None and allowed_cats and title not in allowed_cats:
            continue
        if allowed_cats is not None and not allowed_cats and ph == "report":
            continue
        lines.append(f"## {title}")
        lines.append(body)
        lines.append("")

    if offline:
        lines.append(_OFFLINE_OPSEC)
        lines.append("")
    elif offensive:
        lines.append(_OFFENSIVE_ATTACK_PATHS)
        lines.append("")

    if target_hint:
        for a in adaptive_first_actions(target_hint, offline=offline)[:2]:
            lines.append(f"[KICKOFF] {a}")
        lines.append("")

    actions = next_actions_from_surface(
        surface, phase=phase, offensive=offensive, offline=offline
    )
    if actions:
        lines.append("[NEXT BEST ACTIONS]")
        for i, a in enumerate(actions, 1):
            lines.append(f"{i}. {a}")
        lines.append("")

    text = "\n".join(lines).strip()
    if len(text) > max_chars:
        text = text[: max_chars - 20].rstrip() + "\n… [playbook truncado]"
    return text
