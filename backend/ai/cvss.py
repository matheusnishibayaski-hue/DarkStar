"""CVSS estimado, impacto de negócio e correlação CVE × versão."""

from __future__ import annotations

import re
from typing import Any

SEVERITY_CVSS = {
    "critical": (9.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "high": (7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
    "medium": (5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "low": (3.1, "AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"),
    "info": (0.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    "unknown": (5.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
}

_IMPACT = {
    "cve": "Possível exploração remota do componente afetado (confidencialidade/integridade).",
    "header_hsts": "Tráfego HTTP pode ser interceptado (downgrade / MITM em redes hostis).",
    "header_xfo": "Página pode ser embutida em iframe malicioso (clickjacking).",
    "header_csp": "Maior superfície para XSS e injeção de conteúdo de terceiros.",
    "header_xcto": "Browser pode interpretar MIME incorretamente (MIME sniffing).",
    "header_generic": "Ausência de controles HTTP recomendados reduz defesa em profundidade.",
    "ssl": "Comunicação ou autenticidade do canal pode ser comprometida.",
    "xss": "Execução de script no browser da vítima (sessão/dados).",
    "sqli": "Acesso ou manipulação indevida do banco de dados.",
    "port_exposure": "Serviço exposto aumenta superfície de ataque na rede.",
    "wordpress": "CMS/plugins desatualizados são alvo frequente de exploração.",
    "exposure": "Recurso administrativo ou sensível acessível sem controle adequado.",
    "generic": "Impacto depende do contexto; validar com evidência do PoC.",
}

_VERSION_RE = re.compile(
    r"(?P<name>[\w.\-]+)/(?P<ver>\d+(?:\.\d+){0,3}[a-z0-9\-]*)",
    re.I,
)
_NMAP_VER_RE = re.compile(
    r"(?P<port>\d+)/tcp[ \t]+open[ \t]+(?P<service>[\w\-]+)"
    r"(?:[ \t]+(?P<product>[A-Za-z][\w.\-]*))?(?:[ \t]+(?P<ver>\d[\w.\-]*))?",
    re.I,
)


def estimate_cvss(finding: dict[str, Any]) -> dict[str, Any]:
    """Retorna score/vector/severity — usa cvss_score do Nuclei se existir."""
    if finding.get("cvss_score") is not None:
        try:
            score = float(finding["cvss_score"])
        except (TypeError, ValueError):
            score = None
        if score is not None:
            return {
                "score": round(score, 1),
                "vector": finding.get("cvss_vector") or _vector_for_score(score),
                "source": "nuclei",
            }
    sev = str(finding.get("severity") or "unknown").lower()
    score, vector = SEVERITY_CVSS.get(sev, SEVERITY_CVSS["unknown"])
    # Eleva se multi-fonte + high confidence
    if int(finding.get("sources") or 1) >= 2 and sev in {"medium", "low"}:
        score = min(10.0, score + 0.5)
    return {"score": score, "vector": vector, "source": "estimated"}


def _vector_for_score(score: float) -> str:
    if score >= 9.0:
        return SEVERITY_CVSS["critical"][1]
    if score >= 7.0:
        return SEVERITY_CVSS["high"][1]
    if score >= 4.0:
        return SEVERITY_CVSS["medium"][1]
    if score > 0:
        return SEVERITY_CVSS["low"][1]
    return SEVERITY_CVSS["info"][1]


def impact_for(finding: dict[str, Any]) -> str:
    from backend.ai.remediation import classify_remediation_key

    key = classify_remediation_key(finding)
    base = _IMPACT.get(key) or _IMPACT["generic"]
    cve = str(finding.get("cve") or "")
    if cve:
        return f"{cve}: {base}"
    return base


def effort_for(finding: dict[str, Any]) -> str:
    """Esforço de remediação estimado."""
    key_blob = (
        str(finding.get("title") or "")
        + " "
        + str(finding.get("template_id") or "")
        + " "
        + str(finding.get("finding_type") or "")
    ).lower()
    if any(k in key_blob for k in ("header", "hsts", "csp", "x-frame")):
        return "baixo"
    if any(k in key_blob for k in ("ssl", "tls", "certificate")):
        return "médio"
    if finding.get("cve") or "cve-" in key_blob:
        return "médio"
    if any(k in key_blob for k in ("sql", "xss", "rce", "auth")):
        return "alto"
    return "médio"


def enrich_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Aplica CVSS, impacto e esforço no finding (in-place + return)."""
    cvss = estimate_cvss(finding)
    finding["cvss_score"] = cvss["score"]
    finding["cvss_vector"] = cvss["vector"]
    finding["cvss_source"] = cvss["source"]
    finding["impact"] = impact_for(finding)
    finding["effort"] = effort_for(finding)
    return finding


def parse_versions_from_nmap(output: str) -> list[dict[str, str]]:
    """Extrai port/service/version de saída nmap -sV."""
    rows = []
    for m in _NMAP_VER_RE.finditer(output or ""):
        rows.append(
            {
                "port": m.group("port"),
                "service": (m.group("service") or "").lower(),
                "product": (m.group("product") or "").lower(),
                "version": (m.group("ver") or "").lower(),
            }
        )
    # Também produto/versão estilo Apache/2.4.49
    for m in _VERSION_RE.finditer(output or ""):
        rows.append(
            {
                "port": "",
                "service": m.group("name").lower(),
                "product": m.group("name").lower(),
                "version": m.group("ver").lower(),
            }
        )
    return rows


def correlate_cve_version(
    finding: dict[str, Any],
    ports: list[dict[str, Any]] | None = None,
    nmap_output: str = "",
) -> dict[str, Any]:
    """
    Heurística local (sem NVD online): se há versão no surface/nmap e o
    finding é CVE, marca version_correlated.
    Retorna: {matched, reason, versions_seen}
    """
    cve = str(finding.get("cve") or "")
    versions: list[str] = []
    for p in ports or []:
        v = p.get("version") or ""
        prod = p.get("product") or p.get("service") or ""
        if v:
            versions.append(f"{prod}/{v}".strip("/"))
        elif prod:
            versions.append(str(prod))
    for row in parse_versions_from_nmap(nmap_output):
        if row.get("version"):
            versions.append(f"{row.get('product') or row.get('service')}/{row['version']}")

    versions = list(dict.fromkeys(versions))[:20]
    if not cve:
        return {"matched": False, "reason": "sem CVE", "versions_seen": versions}

    if not versions:
        return {
            "matched": False,
            "reason": "CVE sem versão de serviço no surface — confirmação só via PoC.",
            "versions_seen": [],
        }

    # Se nmap/vulners cita o CVE junto com versão → matched
    out_l = (nmap_output or "").lower()
    if cve.lower() in out_l and any(v.split("/")[-1] in out_l for v in versions if "/" in v):
        return {
            "matched": True,
            "reason": f"{cve} citado com versão de serviço no scan.",
            "versions_seen": versions,
        }
    # Serviço web presente + PoC nuclei já é correlação fraca
    webby = any(
        "http" in v or "nginx" in v or "apache" in v or "ssl" in v for v in versions
    ) or any(
        str(p.get("service") or "").lower() in {"http", "https", "ssl", "http-proxy"}
        for p in (ports or [])
    )
    if webby:
        return {
            "matched": True,
            "reason": f"Serviço correlacionado no surface ({', '.join(versions[:3])}); validar versão afetada.",
            "versions_seen": versions,
            "weak": True,
        }
    return {
        "matched": False,
        "reason": "Versões presentes mas sem vínculo claro com o CVE.",
        "versions_seen": versions,
    }


def apply_enrichment_to_surface(target: str) -> int:
    """Enriquece todos os findings do surface com CVSS/impacto."""
    from backend.executor.surface import load_surface, save_surface

    data = load_surface(target)
    if not data:
        return 0
    n = 0
    for f in data.get("findings") or []:
        enrich_finding(f)
        n += 1
    save_surface(target, data)
    return n
