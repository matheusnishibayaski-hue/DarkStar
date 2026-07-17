"""Remediação acionável por tipo de finding (mapa estático + fallback)."""

from __future__ import annotations

import re
from typing import Any


def classify_remediation_key(finding: dict[str, Any]) -> str:
    title = str(finding.get("title") or "").lower()
    ftype = str(finding.get("finding_type") or "").lower()
    if finding.get("cve") or title.startswith("cve-") or "cve-" in title:
        return "cve"
    if ftype == "header" or any(
        k in title
        for k in (
            "hsts",
            "x-frame",
            "csp",
            "strict-transport",
            "x-content-type",
            "missing header",
            "security header",
        )
    ):
        if "hsts" in title or "strict-transport" in title:
            return "header_hsts"
        if "x-frame" in title:
            return "header_xfo"
        if "csp" in title or "content-security" in title:
            return "header_csp"
        if "x-content-type" in title:
            return "header_xcto"
        return "header_generic"
    if ftype == "ssl" or any(k in title for k in ("ssl", "tls", "certificate", "cipher")):
        return "ssl"
    if ftype == "xss" or "xss" in title or "cross-site scripting" in title:
        return "xss"
    if ftype == "sqli" or "sql" in title:
        return "sqli"
    if ftype == "port_info" or re.search(r"\d+/tcp", title):
        return "port_exposure"
    if "wordpress" in title or "wp-" in title:
        return "wordpress"
    if "admin" in title or "exposed" in title or "panel" in title:
        return "exposure"
    return "generic"


_REMEDIATIONS: dict[str, dict[str, str]] = {
    "cve": {
        "title": "Atualizar componente vulnerável",
        "action": (
            "Aplicar patch/upgrade para a versão corrigida do CVE. "
            "Validar com reteste do mesmo template/CVE após o deploy."
        ),
    },
    "header_hsts": {
        "title": "Habilitar HSTS",
        "action": (
            "Configurar Strict-Transport-Security (ex.: max-age=31536000; includeSubDomains) "
            "no edge/reverse-proxy e forçar HTTPS."
        ),
    },
    "header_xfo": {
        "title": "Proteger contra clickjacking",
        "action": "Definir X-Frame-Options: DENY (ou SAMEORIGIN) e/ou CSP frame-ancestors.",
    },
    "header_csp": {
        "title": "Content-Security-Policy",
        "action": (
            "Implantar CSP restritiva (default-src 'self'; script-src …) "
            "e evoluir com report-only antes do enforce."
        ),
    },
    "header_xcto": {
        "title": "X-Content-Type-Options",
        "action": "Adicionar X-Content-Type-Options: nosniff em todas as respostas.",
    },
    "header_generic": {
        "title": "Headers de segurança",
        "action": "Revisar e padronizar headers de segurança no proxy/aplicação (OWASP Secure Headers).",
    },
    "ssl": {
        "title": "Fortalecer TLS",
        "action": (
            "Desabilitar protocolos/cifras obsoletas, renovar certificado válido, "
            "habilitar TLS 1.2+ e Perfect Forward Secrecy."
        ),
    },
    "xss": {
        "title": "Mitigar XSS",
        "action": (
            "Sanitizar/escapar saída, CSP restritiva, validar entrada e "
            "usar encoding contextual no framework."
        ),
    },
    "sqli": {
        "title": "Mitigar SQL Injection",
        "action": (
            "Usar queries parametrizadas/ORM, validar entrada e "
            "reduzir privilégios da conta do banco da aplicação."
        ),
    },
    "port_exposure": {
        "title": "Reduzir superfície de rede",
        "action": (
            "Fechar porta/serviço desnecessário no firewall/SG; "
            "expor apenas via VPN ou allowlist de IPs autorizados."
        ),
    },
    "wordpress": {
        "title": "Hardening WordPress",
        "action": (
            "Atualizar core/plugins/temas, remover componentes órfãos, "
            "reforçar autenticação e limitar enumeração de usuários."
        ),
    },
    "exposure": {
        "title": "Restringir painel/recurso exposto",
        "action": (
            "Autenticar o recurso, restringir por IP/VPN, "
            "remover paths de administração da internet pública."
        ),
    },
    "generic": {
        "title": "Corrigir conforme evidência",
        "action": (
            "Aplicar correção alinhada à evidência/PoC do achado, "
            "documentar mudança e retestar o mesmo vetor."
        ),
    },
}


def remediation_for(finding: dict[str, Any]) -> dict[str, str]:
    key = classify_remediation_key(finding)
    base = dict(_REMEDIATIONS.get(key) or _REMEDIATIONS["generic"])
    cve = str(finding.get("cve") or "")
    if not cve:
        m = re.search(r"CVE-\d{4}-\d+", str(finding.get("title") or ""), re.I)
        if m:
            cve = m.group(0).upper()
    if cve and key == "cve":
        base["action"] = f"{cve}: {base['action']}"
    base["key"] = key
    return base


def remediations_for_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for f in findings:
        rem = remediation_for(f)
        title = str(f.get("title") or "")[:120]
        row_key = f"{rem['key']}|{title}"
        if row_key in seen:
            continue
        seen.add(row_key)
        rows.append(
            {
                "finding_id": f.get("id"),
                "finding_title": title,
                "severity": f.get("severity"),
                "remediation_title": rem["title"],
                "action": rem["action"],
                "key": rem["key"],
            }
        )
    return rows
