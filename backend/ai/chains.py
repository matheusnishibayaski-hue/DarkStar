"""Hipóteses de cadeias de ataque (kill-chain leve) a partir do surface."""

from __future__ import annotations

from typing import Any


def infer_attack_chains(surface: dict[str, Any]) -> list[dict[str, str]]:
    """
    Gera hipóteses A+B → risco composto. Não confirma exploração —
    apenas sinaliza combinação no relatório.
    """
    findings = [
        f
        for f in (surface.get("findings") or [])
        if f.get("status") == "confirmed"
    ]
    ports = surface.get("ports") or []
    urls = surface.get("urls") or []
    chains: list[dict[str, str]] = []

    titles = " ".join(str(f.get("title") or "").lower() for f in findings)
    tids = " ".join(str(f.get("template_id") or "").lower() for f in findings)
    blob = titles + " " + tids

    open_ports = {str(p.get("port")) for p in ports}
    has_http = bool(urls) or "80" in open_ports or "443" in open_ports
    missing_hsts = "hsts" in blob or "strict-transport" in blob
    exposed = any(k in blob for k in ("exposed", "admin", "panel", "debug", "swagger"))
    cve_high = any(
        f.get("cve") and str(f.get("severity")).lower() in {"critical", "high"}
        for f in findings
    )
    xss = "xss" in blob
    sqli = "sql" in blob

    if missing_hsts and has_http and exposed:
        chains.append(
            {
                "title": "Exposição web + ausência de HSTS",
                "detail": (
                    "Painel/recurso exposto em HTTP(S) sem HSTS aumenta risco de "
                    "interceptação e abuso de sessão em redes hostis."
                ),
                "severity": "high",
            }
        )
    if cve_high and exposed:
        chains.append(
            {
                "title": "CVE alto + superfície exposta",
                "detail": (
                    "Componente com CVE crítico/alto combinado a recurso acessível "
                    "eleva probabilidade de exploração remota."
                ),
                "severity": "critical",
            }
        )
    if xss and missing_hsts:
        chains.append(
            {
                "title": "XSS + headers fracos",
                "detail": (
                    "XSS com headers de segurança ausentes amplia impacto "
                    "(exfiltração de sessão / phishing in-app)."
                ),
                "severity": "high",
            }
        )
    if sqli and has_http:
        chains.append(
            {
                "title": "Injeção SQL em superfície web",
                "detail": (
                    "SQLi em endpoint web pode levar a leitura/alteração de dados "
                    "e pivô interno — priorizar remediação e reteste."
                ),
                "severity": "critical",
            }
        )
    if "22" in open_ports and any(
        str(f.get("severity")).lower() in {"critical", "high"} for f in findings
    ):
        chains.append(
            {
                "title": "SSH exposto + achados altos",
                "detail": (
                    "SSH público junto a vulnerabilidades altas amplia impacto "
                    "se credenciais ou bugs de serviço forem obtidos."
                ),
                "severity": "medium",
            }
        )

    return chains[:8]
