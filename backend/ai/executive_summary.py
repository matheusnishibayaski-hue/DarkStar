"""Sumário executivo para PDF — LLM com cache, timeout e fallback determinístico."""

from __future__ import annotations

import hashlib
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from typing import Any

from backend.ai.report import _structured_executive
from backend.config import EXECUTIVE_SUMMARY_TIMEOUT
from backend.executor.surface import load_surface, save_surface

logger = logging.getLogger(__name__)


def _fingerprint(
    executive: list,
    risk: dict,
    delta: dict,
    client: str,
    target: str,
) -> str:
    payload = {
        "executive": [
            {
                "id": f.get("id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "cve": f.get("cve"),
                "status": f.get("status"),
            }
            for f in (executive or [])[:20]
        ],
        "risk": {"score": risk.get("score"), "label": risk.get("label")},
        "delta": {
            "fixed": len(delta.get("fixed") or []),
            "new": len(delta.get("new") or []),
            "still_open": len(delta.get("still_open") or []),
            "ports_opened": len((delta.get("surface") or {}).get("ports_opened") or []),
            "ports_closed": len((delta.get("surface") or {}).get("ports_closed") or []),
            "hosts_added": len((delta.get("surface") or {}).get("hosts_added") or []),
        },
        "client": client,
        "target": target,
    }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def fallback_executive_text(
    executive: list,
    risk: dict,
    client: str,
    target: str,
    scope_notes: str,
    delta: dict | None = None,
) -> str:
    """Texto determinístico (mesmo conteúdo do relatório MD)."""
    lines = _structured_executive(executive, risk, client, target, scope_notes)
    parts = ["\n".join(lines)]
    if delta and delta.get("has_baseline"):
        surf = delta.get("surface") or {}
        parts.append(
            "\n### Evolução desde o último scan\n\n"
            f"Corrigidos: {len(delta.get('fixed') or [])}; "
            f"novos: {len(delta.get('new') or [])}; "
            f"ainda abertos: {len(delta.get('still_open') or [])}. "
            f"Portas novas: {len(surf.get('ports_opened') or [])}; "
            f"portas fechadas: {len(surf.get('ports_closed') or [])}; "
            f"ativos novos: {len(surf.get('hosts_added') or [])}."
        )
        narrative = business_delta_narrative(delta)
        if narrative:
            parts.append(f"\n{narrative}")
    parts.append(
        "\n### Ações prioritárias (30 dias)\n\n"
        "1. Corrigir primeiro os itens critical/high com evidência.\n"
        "2. Validar remediações com reteste (mesmo template-id/CVE).\n"
        "3. Revisar a fila humana antes da entrega final.\n"
    )
    return "\n".join(parts).strip()


def business_delta_narrative(delta: dict[str, Any]) -> str:
    """Uma frase de negócio para o PDF executivo."""
    if not delta.get("has_baseline"):
        return (
            "Este é o primeiro ciclo documentado — o estado atual será a referência "
            "para o próximo reteste mensal."
        )
    fixed = len(delta.get("fixed") or [])
    new = len(delta.get("new") or [])
    still = len(delta.get("still_open") or [])
    surf = delta.get("surface") or {}
    ports_new = len(surf.get("ports_opened") or [])
    hosts_new = len(surf.get("hosts_added") or [])
    bits = []
    if fixed:
        bits.append(f"{fixed} risco(s) corrigido(s)")
    if new:
        bits.append(f"{new} novo(s) achado(s)")
    if still:
        bits.append(f"{still} ainda aberto(s)")
    if ports_new:
        bits.append(f"{ports_new} porta(s) nova(s) aberta(s)")
    if hosts_new:
        bits.append(f"{hosts_new} ativo(s) descoberto(s)")
    if not bits:
        return "Desde o último scan, a superfície e os achados confirmados permaneceram estáveis."
    return "Desde o último scan: " + "; ".join(bits) + "."


def _llm_generate(prompt: str) -> str:
    from backend.ai.providers.factory import get_llm_provider

    provider = get_llm_provider()
    if not provider.is_configured():
        raise RuntimeError(provider.configuration_error())
    model, _ = provider.resolve_models(None, None)
    result = provider.complete(
        model=model,
        messages=[
            {
                "role": "system",
                "content": (
                    "Você é analista sênior escrevendo sumário executivo de pentest "
                    "para CEOs e diretores. Linguagem de negócios, sem jargão excessivo. "
                    "Nunca invente CVEs, severidades ou achados — use só os dados fornecidos. "
                    "Responda em português (Brasil), em markdown simples: 3–6 parágrafos "
                    "e uma seção 'Ações prioritárias (30 dias)' com 3–5 bullets."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        tools=None,
        tool_choice=None,
    )
    text = (result.message.content or "").strip()
    if not text:
        raise RuntimeError("LLM retornou sumário vazio.")
    return text


def generate_executive_summary(
    target: str,
    *,
    regenerate: bool = False,
    use_llm: bool = True,
) -> dict[str, Any]:
    """
    Retorna {text, source, fingerprint}.
    Cache em surface.executive_summary / executive_summary_at / executive_summary_fp.
    """
    from backend.ai.delta import compute_delta
    from backend.ai.risk_score import risk_score_for_target
    from backend.ai.verify import confidence_gate_buckets
    from backend.executor.recon_db import normalize_target

    norm = normalize_target(target)
    surface = load_surface(norm)
    if not surface:
        return {
            "text": "Sem Attack Surface para este alvo.",
            "source": "empty",
            "fingerprint": "",
        }

    gate = confidence_gate_buckets(norm)
    executive = list(gate.get("executive") or [])
    risk = risk_score_for_target(norm)
    delta = compute_delta(norm)
    client = str(surface.get("client") or surface.get("client_id") or "")
    scope = str(surface.get("scope_notes") or "")
    fp = _fingerprint(executive, risk, delta, client, norm)

    cached = str(surface.get("executive_summary") or "").strip()
    cached_fp = str(surface.get("executive_summary_fp") or "")
    if cached and cached_fp == fp and not regenerate:
        return {"text": cached, "source": "cache", "fingerprint": fp}

    fallback = fallback_executive_text(executive, risk, client, norm, scope, delta=delta)

    if not use_llm:
        surface["executive_summary"] = fallback
        surface["executive_summary_at"] = surface.get("updated_at")
        surface["executive_summary_fp"] = fp
        surface["executive_summary_source"] = "fallback"
        save_surface(norm, surface)
        return {"text": fallback, "source": "fallback", "fingerprint": fp}

    compact = {
        "target": norm,
        "client": client,
        "objective": surface.get("objective"),
        "scope_notes": scope[:400],
        "risk": risk,
        "executive_findings": [
            {
                "title": f.get("title"),
                "severity": f.get("severity"),
                "cve": f.get("cve"),
                "cvss_score": f.get("cvss_score"),
                "impact": str(f.get("impact") or "")[:200],
            }
            for f in executive[:12]
        ],
        "delta_narrative": business_delta_narrative(delta),
        "delta_counts": {
            "fixed": len(delta.get("fixed") or []),
            "new": len(delta.get("new") or []),
            "still_open": len(delta.get("still_open") or []),
            "ports_opened": len((delta.get("surface") or {}).get("ports_opened") or []),
            "ports_closed": len((delta.get("surface") or {}).get("ports_closed") or []),
            "hosts_added": len((delta.get("surface") or {}).get("hosts_added") or []),
        },
    }
    prompt = (
        "Gere o sumário executivo com base nestes dados JSON "
        "(não invente nada além do fornecido):\n\n"
        + json.dumps(compact, ensure_ascii=False, indent=2)
    )

    text = fallback
    source = "fallback"
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(_llm_generate, prompt)
            text = fut.result(timeout=EXECUTIVE_SUMMARY_TIMEOUT)
            source = "llm"
    except FuturesTimeout:
        logger.warning("executive_summary_timeout target=%s", norm)
        text = fallback
        source = "fallback_timeout"
    except Exception as exc:  # noqa: BLE001
        logger.warning("executive_summary_llm_failed: %s", exc)
        text = fallback
        source = "fallback_error"

    surface["executive_summary"] = text
    surface["executive_summary_at"] = surface.get("updated_at")
    surface["executive_summary_fp"] = fp
    surface["executive_summary_source"] = source
    save_surface(norm, surface)
    return {"text": text, "source": source, "fingerprint": fp}
