"""Catálogo estático de assets por indústria (heurístico)."""

from __future__ import annotations

from typing import Any

ASSET_CATALOG: dict[str, list[dict[str, Any]]] = {
    "financial": [
        {"name": "Payment / core banking API", "criticality": 10, "focus": "auth, injection, IDOR"},
        {
            "name": "Admin / backoffice panel",
            "criticality": 9,
            "focus": "exposure, MFA, default creds",
        },
        {"name": "Customer PII database path", "criticality": 9, "focus": "SQLi, access control"},
        {"name": "API gateway / BFF", "criticality": 8, "focus": "rate limit, JWT, SSRF"},
    ],
    "healthcare": [
        {
            "name": "Patient / EHR data store",
            "criticality": 10,
            "focus": "access control, encryption",
        },
        {"name": "Clinician admin portal", "criticality": 9, "focus": "authZ, session"},
        {"name": "Compliance / audit logs", "criticality": 7, "focus": "integrity, exposure"},
        {"name": "Appointment / patient API", "criticality": 8, "focus": "IDOR, PHI leak"},
    ],
    "ecommerce": [
        {
            "name": "Payment processor integration",
            "criticality": 10,
            "focus": "PCI paths, XSS on checkout",
        },
        {"name": "Customer account / PII", "criticality": 8, "focus": "auth, IDOR"},
        {"name": "Inventory / admin CMS", "criticality": 7, "focus": "exposure, RCE templates"},
        {"name": "Search / catalog API", "criticality": 6, "focus": "injection, abuse"},
    ],
    "generic": [
        {"name": "Public web application", "criticality": 7, "focus": "OWASP Top 10"},
        {"name": "Exposed admin or debug", "criticality": 9, "focus": "auth, default creds"},
        {"name": "External APIs", "criticality": 7, "focus": "authN/Z, injection"},
        {"name": "Mail / VPN / remote access", "criticality": 8, "focus": "exposure, weak crypto"},
    ],
}


def assets_for_industry(industry: str) -> list[dict[str, Any]]:
    key = (industry or "generic").strip().lower() or "generic"
    base = ASSET_CATALOG.get(key) or ASSET_CATALOG["generic"]
    out: list[dict[str, Any]] = []
    for item in base:
        out.append(
            {
                "name": item["name"],
                "criticality": int(item["criticality"]),
                "rationale": f"Asset típico de industry={key}; foco: {item['focus']}.",
                "focus": item["focus"],
            }
        )
    return out
