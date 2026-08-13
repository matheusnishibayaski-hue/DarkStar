"""Threat Intelligence — CISA KEV (Known Exploited Vulnerabilities) + FIRST EPSS.

Enriquece os CVEs mapeados no Attack Surface Graph (`backend/executor/surface.py`)
e nos relatórios de triagem com dois sinais externos de priorização:

- **CISA KEV**: catálogo público de vulnerabilidades com exploração ativa
  confirmada (https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
  Um CVE presente no catálogo é tratado como risco imediato — a severidade do
  achado é elevada automaticamente para, no mínimo, ``high``.
- **FIRST EPSS**: score de probabilidade (0–1) de que o CVE seja explorado em
  campo nos próximos 30 dias (https://www.first.org/epss/).

Sem dependências externas: usa apenas ``urllib`` da stdlib e mantém cache em
memória por processo com TTL configurável (``THREAT_INTEL_CACHE_TTL``), para
não bater nas APIs públicas a cada finding. As funções de rede são isoladas
(`_http_get_json`) para facilitar mock nos testes.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from typing import Any

from backend.config import THREAT_INTEL_CACHE_TTL, THREAT_INTEL_ENABLED
from backend.security.http_client import http_urlopen

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_HTTP_TIMEOUT_SEC = 8

# Cache em memória (por processo) — evita golpear as APIs a cada finding.
_kev_cache: dict[str, Any] = {"data": None, "fetched_at": 0.0}
_epss_cache: dict[str, tuple[float, dict[str, float]]] = {}


def normalize_cve(cve: str) -> str:
    """Normaliza e valida um identificador CVE. Retorna '' se inválido."""
    value = (cve or "").strip().upper()
    return value if _CVE_RE.match(value) else ""


def _http_get_json(url: str) -> Any:
    """GET simples com timeout curto. Isolado para facilitar mocks em testes."""
    req = urllib.request.Request(url, headers={"User-Agent": "chat-ia-kali-threat-intel/1.1"})
    with http_urlopen(req, timeout=_HTTP_TIMEOUT_SEC) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_cisa_kev_catalog(*, force_refresh: bool = False) -> dict[str, dict[str, Any]]:
    """Baixa (ou reaproveita do cache) o catálogo CISA KEV como ``{CVE: metadata}``.

    Em caso de falha de rede, retorna o último catálogo em cache (ou dict
    vazio na primeira falha) — nunca propaga a exceção para o chamador.
    """
    now = time.monotonic()
    if (
        not force_refresh
        and _kev_cache["data"] is not None
        and (now - _kev_cache["fetched_at"]) < THREAT_INTEL_CACHE_TTL
    ):
        return _kev_cache["data"]

    try:
        payload = _http_get_json(CISA_KEV_URL)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return _kev_cache["data"] or {}

    catalog: dict[str, dict[str, Any]] = {}
    for vuln in payload.get("vulnerabilities") or []:
        cve = normalize_cve(str(vuln.get("cveID") or ""))
        if not cve:
            continue
        catalog[cve] = {
            "vendor_project": vuln.get("vendorProject", ""),
            "product": vuln.get("product", ""),
            "vulnerability_name": vuln.get("vulnerabilityName", ""),
            "date_added": vuln.get("dateAdded", ""),
            "due_date": vuln.get("dueDate", ""),
            "ransomware_use": str(vuln.get("knownRansomwareCampaignUse", "")).lower() == "known",
        }
    _kev_cache["data"] = catalog
    _kev_cache["fetched_at"] = now
    return catalog


def is_in_kev(cve: str) -> dict[str, Any] | None:
    """Retorna os metadados KEV do CVE, ou None se não estiver no catálogo."""
    normalized = normalize_cve(cve)
    if not normalized:
        return None
    return fetch_cisa_kev_catalog().get(normalized)


def fetch_epss_score(cve: str) -> dict[str, float] | None:
    """Consulta score/percentile EPSS (FIRST.org) para um único CVE, com cache TTL."""
    normalized = normalize_cve(cve)
    if not normalized:
        return None

    now = time.monotonic()
    cached = _epss_cache.get(normalized)
    if cached and (now - cached[0]) < THREAT_INTEL_CACHE_TTL:
        return cached[1]

    try:
        payload = _http_get_json(f"{FIRST_EPSS_URL}?cve={normalized}")
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return cached[1] if cached else None

    rows = payload.get("data") or []
    if not rows:
        result = {"score": 0.0, "percentile": 0.0}
    else:
        row = rows[0]
        try:
            result = {
                "score": float(row.get("epss", 0) or 0),
                "percentile": float(row.get("percentile", 0) or 0),
            }
        except (TypeError, ValueError):
            result = {"score": 0.0, "percentile": 0.0}

    _epss_cache[normalized] = (now, result)
    return result


def lookup_cve_intel(cve: str) -> dict[str, Any]:
    """Agrega KEV + EPSS para um único CVE em um dict pronto para o surface."""
    normalized = normalize_cve(cve)
    if not normalized:
        return {}
    kev = is_in_kev(normalized)
    epss = fetch_epss_score(normalized) or {"score": 0.0, "percentile": 0.0}
    return {
        "cve": normalized,
        "cisa_kev_flag": kev is not None,
        "kev_date_added": (kev or {}).get("date_added", ""),
        "kev_ransomware_use": bool((kev or {}).get("ransomware_use", False)),
        "epss_score": round(float(epss.get("score", 0.0)), 5),
        "epss_percentile": round(float(epss.get("percentile", 0.0)), 5),
    }


_SEVERITY_ORDER = ["info", "unknown", "low", "medium", "high", "critical"]


def enrich_finding_with_threat_intel(finding: dict[str, Any]) -> dict[str, Any]:
    """Aplica cisa_kev_flag/epss_score/epss_percentile no finding (in-place).

    Se o CVE estiver no catálogo CISA KEV, eleva a severidade para no mínimo
    ``high`` (exploração ativa em campo já confirmada) e anota o motivo.
    """
    if not THREAT_INTEL_ENABLED:
        return finding
    cve = normalize_cve(str(finding.get("cve") or ""))
    if not cve:
        return finding

    intel = lookup_cve_intel(cve)
    if not intel:
        return finding

    finding["cisa_kev_flag"] = intel["cisa_kev_flag"]
    finding["kev_date_added"] = intel["kev_date_added"]
    finding["kev_ransomware_use"] = intel["kev_ransomware_use"]
    finding["epss_score"] = intel["epss_score"]
    finding["epss_percentile"] = intel["epss_percentile"]

    if intel["cisa_kev_flag"]:
        current = str(finding.get("severity") or "unknown").lower()
        idx = _SEVERITY_ORDER.index(current) if current in _SEVERITY_ORDER else 1
        if idx < _SEVERITY_ORDER.index("high"):
            finding["severity"] = "high"
        finding["threat_intel_note"] = (
            f"{cve} está no catálogo CISA KEV (exploração ativa confirmada) "
            "— severidade elevada automaticamente."
        )
    return finding


def enrich_surface_with_threat_intel(target: str) -> int:
    """Enriquece com threat intel todos os findings com CVE do surface de `target`.

    Retorna a quantidade de findings processados (com CVE). Persiste o surface
    no disco somente se houve pelo menos um finding processado.
    """
    from backend.executor.surface import load_surface, save_surface

    data = load_surface(target)
    if not data:
        return 0

    processed = 0
    for finding in data.get("findings") or []:
        if finding.get("cve"):
            enrich_finding_with_threat_intel(finding)
            processed += 1

    if processed:
        save_surface(target, data)
    return processed
