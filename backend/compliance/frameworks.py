"""Frameworks de compliance — mapeamentos indicativos (não certificação)."""

from __future__ import annotations

from typing import Any

FRAMEWORKS: dict[str, dict[str, Any]] = {
    "LGPD": {
        "name": "LGPD",
        "region": "BR",
        "controls": [
            {
                "id": "Art.46",
                "name": "Segurança do tratamento",
                "keywords": ["sql", "xss", "rce", "injection", "exposure", "default"],
                "critical": True,
            },
            {
                "id": "Art.49",
                "name": "Responsabilidade do controlador",
                "keywords": ["admin", "auth", "access", "idor", "permission"],
                "critical": True,
            },
            {
                "id": "Art.6-II",
                "name": "Segurança / prevenção",
                "keywords": ["ssl", "tls", "hsts", "weak", "crypto", "certificate"],
                "critical": False,
            },
        ],
    },
    "GDPR": {
        "name": "GDPR",
        "region": "EU",
        "controls": [
            {
                "id": "Art.32",
                "name": "Security of processing",
                "keywords": ["sql", "xss", "rce", "encryption", "ssl", "tls", "hsts"],
                "critical": True,
            },
            {
                "id": "Art.25",
                "name": "Data protection by design",
                "keywords": ["exposure", "debug", "swagger", "admin", "default"],
                "critical": True,
            },
            {
                "id": "Art.5",
                "name": "Integrity and confidentiality",
                "keywords": ["idor", "auth", "access", "leak", "disclosure"],
                "critical": False,
            },
        ],
    },
    "PCI-DSS": {
        "name": "PCI-DSS",
        "region": "global",
        "controls": [
            {
                "id": "6.5",
                "name": "Secure development — common vulns",
                "keywords": ["sql", "xss", "csrf", "injection", "rce"],
                "critical": True,
            },
            {
                "id": "4.1",
                "name": "Strong cryptography in transit",
                "keywords": ["ssl", "tls", "hsts", "weak", "certificate"],
                "critical": True,
            },
            {
                "id": "8.2",
                "name": "Authentication management",
                "keywords": ["auth", "password", "default", "mfa", "credential"],
                "critical": True,
            },
        ],
    },
    "SOC2": {
        "name": "SOC 2 (indicative CC)",
        "region": "global",
        "controls": [
            {
                "id": "CC6.1",
                "name": "Logical access",
                "keywords": ["auth", "admin", "access", "idor", "permission"],
                "critical": True,
            },
            {
                "id": "CC7.1",
                "name": "System vulnerabilities",
                "keywords": ["cve", "rce", "exposure", "outdated"],
                "critical": True,
            },
            {
                "id": "CC6.7",
                "name": "Transmission confidentiality",
                "keywords": ["ssl", "tls", "hsts", "cleartext"],
                "critical": False,
            },
        ],
    },
    "HIPAA": {
        "name": "HIPAA (indicative)",
        "region": "US",
        "controls": [
            {
                "id": "164.312(a)",
                "name": "Access control",
                "keywords": ["auth", "access", "idor", "admin", "permission"],
                "critical": True,
            },
            {
                "id": "164.312(e)",
                "name": "Transmission security",
                "keywords": ["ssl", "tls", "hsts", "cleartext"],
                "critical": True,
            },
            {
                "id": "164.308(a)(1)",
                "name": "Security management — risk",
                "keywords": ["cve", "rce", "sql", "exposure", "leak"],
                "critical": True,
            },
        ],
    },
}


def list_frameworks() -> list[dict[str, Any]]:
    return [
        {
            "id": k,
            "name": v["name"],
            "region": v["region"],
            "controls": len(v["controls"]),
        }
        for k, v in FRAMEWORKS.items()
    ]


def get_framework(framework_id: str) -> dict[str, Any] | None:
    raw = (framework_id or "").strip()
    key = raw.upper().replace("_", "-")
    if key in {"SOC-2", "SOC2"}:
        return FRAMEWORKS.get("SOC2")
    if key in {"PCI", "PCIDSS", "PCI-DSS"}:
        return FRAMEWORKS.get("PCI-DSS")
    if key in FRAMEWORKS:
        return FRAMEWORKS[key]
    # case-sensitive id match for mixed keys
    for k, v in FRAMEWORKS.items():
        if k.upper() == key:
            return v
    return None
