"""Rotas do Intelligence Hub e Threat Modeling — `/api/intelligence/*`."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from backend.config import INTELLIGENCE_ENABLED
from backend.intelligence.exceptions import IntelligenceError, SurfaceNotFound
from backend.intelligence import hub
from backend.intelligence.threat_modeling import generate_threat_model, get_threat_model

router = APIRouter(prefix="/api/intelligence", tags=["intelligence"])


class RecordRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=256)
    industry: str = Field(default="", max_length=64)


class ThreatModelRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=256)
    industry: str = Field(default="generic", max_length=64)
    company_size: str = Field(default="", max_length=32)
    business_model: str = Field(default="", max_length=128)
    regulations: list[str] = Field(default_factory=list)
    notes: str = Field(default="", max_length=500)


def _ensure_enabled() -> None:
    if not INTELLIGENCE_ENABLED:
        raise HTTPException(
            status_code=404,
            detail="Intelligence Hub desabilitado (INTELLIGENCE_ENABLED=false).",
        )


@router.post("/record")
def api_record(body: RecordRequest):
    _ensure_enabled()
    try:
        return hub.record_from_surface(body.target.strip(), industry=body.industry.strip())
    except SurfaceNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except IntelligenceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Falha ao gravar: {exc}") from exc


@router.get("/suggest/{target}")
def api_suggest(target: str, industry: str | None = None, limit: int = 10):
    _ensure_enabled()
    return hub.suggest(target, industry=industry, limit=limit)


@router.get("/stats")
def api_stats():
    _ensure_enabled()
    return hub.stats()


@router.get("/similar/{target}")
def api_similar(target: str, limit: int = 10):
    _ensure_enabled()
    return hub.similar_targets(target, limit=limit)


@router.post("/threat-model")
def api_threat_model_create(body: ThreatModelRequest):
    _ensure_enabled()
    payload: dict[str, Any] = body.model_dump()
    target = payload.pop("target")
    return generate_threat_model(target, payload)


@router.get("/threat-model/{target}")
def api_threat_model_get(target: str):
    _ensure_enabled()
    data = get_threat_model(target)
    if not data:
        raise HTTPException(status_code=404, detail="Threat model não encontrado.")
    return data


@router.get("/fp-suppress")
def api_fp_suppress_list(limit: int = 100):
    """Padrões aprendidos como falso positivo (supressão em imports)."""
    from backend.ai.fp_learn import list_suppressed

    return {"patterns": list_suppressed(limit=limit)}


@router.delete("/fp-suppress")
def api_fp_suppress_clear(pattern_key: str | None = Query(default=None)):
    from backend.ai.fp_learn import clear_suppressed

    n = clear_suppressed(pattern_key)
    return {"cleared": n, "pattern_key": pattern_key}
