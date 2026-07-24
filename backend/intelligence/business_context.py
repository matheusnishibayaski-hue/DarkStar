"""Contexto de negócio opcional para threat modeling."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class BusinessContext:
    industry: str = "generic"
    company_size: str = ""
    business_model: str = ""
    regulations: list[str] = field(default_factory=list)
    notes: str = ""

    def normalized_industry(self) -> str:
        raw = (self.industry or "generic").strip().lower()
        aliases = {
            "finance": "financial",
            "fintech": "financial",
            "bank": "financial",
            "health": "healthcare",
            "hospital": "healthcare",
            "e-commerce": "ecommerce",
            "ecommerce": "ecommerce",
            "retail": "ecommerce",
        }
        return aliases.get(raw, raw if raw else "generic")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_business_context(payload: dict[str, Any] | None) -> BusinessContext:
    payload = payload or {}
    regs = payload.get("regulations") or []
    if isinstance(regs, str):
        regs = [r.strip() for r in regs.split(",") if r.strip()]
    return BusinessContext(
        industry=str(payload.get("industry") or "generic"),
        company_size=str(payload.get("company_size") or ""),
        business_model=str(payload.get("business_model") or ""),
        regulations=[str(r) for r in regs][:12],
        notes=str(payload.get("notes") or "")[:500],
    )
