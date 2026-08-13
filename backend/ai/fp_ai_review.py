"""Segunda opinião de falso positivo via LLM (não marca o achado sozinha)."""

from __future__ import annotations

import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from typing import Any

from backend.ai.exec_digest import strip_ansi
from backend.ai.fp_explain import explain_false_positive
from backend.config import PRIMARY_MODEL

logger = logging.getLogger(__name__)

_REVIEW_TIMEOUT_SEC = 8
_VERDICTS = {"confirmed", "false_positive", "unsure"}


def _extract_json(text: str) -> dict[str, Any] | None:
    if not text:
        return None
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        pass
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S | re.I)
    chunk = m.group(1) if m else None
    if not chunk:
        start, end = text.find("{"), text.rfind("}")
        if start >= 0 and end > start:
            chunk = text[start : end + 1]
    if not chunk:
        return None
    try:
        data = json.loads(chunk)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        return None


def parse_ai_review(raw: str) -> dict[str, Any] | None:
    data = _extract_json(raw)
    if not data:
        return None
    verdict = str(data.get("verdict") or "unsure").strip().lower()
    if verdict in {"real", "vulnerability", "vuln", "problema"}:
        verdict = "confirmed"
    if verdict in {"fp", "false", "alarme", "falso"}:
        verdict = "false_positive"
    if verdict not in _VERDICTS:
        verdict = "unsure"
    try:
        confidence = int(data.get("confidence") or 0)
    except (TypeError, ValueError):
        confidence = 0
    confidence = max(0, min(100, confidence))
    reasons = data.get("reasons") or []
    if isinstance(reasons, str):
        reasons = [reasons]
    reasons = [str(r).strip()[:280] for r in reasons if str(r).strip()][:4]
    summary = str(data.get("summary") or data.get("reason") or "").strip()[:400]
    if summary and not reasons:
        reasons = [summary]
    return {
        "verdict": verdict,
        "confidence": confidence,
        "reasons": reasons,
        "summary": summary,
        "source": "llm",
    }


def _prompt(finding: dict[str, Any], heuristic: dict[str, Any]) -> str:
    evidence = strip_ansi(str(finding.get("evidence") or ""))[:1200]
    title = str(finding.get("title") or finding.get("plain_title") or "Achado")[:200]
    cmd = str(finding.get("command") or "")[:400]
    tool = str(finding.get("tool") or "")[:80]
    heur_v = heuristic.get("suggestion") or "unsure"
    heur_fp = int(heuristic.get("likely_fp") or 0)
    why_v = "; ".join(heuristic.get("why_vulnerability") or [])[:400]
    why_f = "; ".join(heuristic.get("why_false_positive") or [])[:400]
    return (
        "Você é a Argus, assistente de pentest. Leia o achado e diga se parece "
        "vulnerabilidade real, alarme falso, ou incerto. Não invente evidência.\n"
        "Responda SÓ um JSON: "
        '{"verdict":"confirmed"|"false_positive"|"unsure","confidence":0-100,'
        '"summary":"frase em português","reasons":["motivo 1","motivo 2"]}\n\n'
        f"Título: {title}\nFerramenta: {tool}\nComando: {cmd}\n"
        f"Heurística local: {heur_v} (chance de FP {heur_fp}%).\n"
        f"A favor de ser real: {why_v or '—'}\n"
        f"A favor de alarme falso: {why_f or '—'}\n"
        f"Evidência:\n{evidence or '(vazia)'}\n"
    )


def _call_llm(finding: dict[str, Any], heuristic: dict[str, Any]) -> dict[str, Any]:
    from backend.ai.providers import get_llm_provider

    provider = get_llm_provider()
    if not provider.is_configured():
        return {
            "verdict": "unsure",
            "confidence": 0,
            "reasons": [],
            "summary": "",
            "source": "unavailable",
            "error": "IA não configurada (offline sem Ollama ou sem chave).",
        }
    model, _ = provider.resolve_models(PRIMARY_MODEL, None)
    completion = provider.complete(
        model=model,
        messages=[
            {"role": "system", "content": "Responda apenas JSON válido, em português."},
            {"role": "user", "content": _prompt(finding, heuristic)},
        ],
        tools=None,
        tool_choice=None,
    )
    text = (completion.message.content or "") if completion and completion.message else ""
    parsed = parse_ai_review(text)
    if not parsed:
        return {
            "verdict": "unsure",
            "confidence": 0,
            "reasons": [],
            "summary": "",
            "source": "unavailable",
            "error": "A IA não devolveu um JSON utilizável.",
        }
    return parsed


def review_finding(finding: dict[str, Any]) -> dict[str, Any]:
    cached = finding.get("ai_review")
    if isinstance(cached, dict) and cached.get("source") == "llm" and cached.get("verdict"):
        return cached
    heuristic = explain_false_positive(finding)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(_call_llm, finding, heuristic)
            return fut.result(timeout=_REVIEW_TIMEOUT_SEC)
    except FuturesTimeout:
        logger.info("ai_review_timeout")
        return {
            "verdict": "unsure",
            "confidence": 0,
            "reasons": [],
            "summary": "",
            "source": "unavailable",
            "error": "A segunda leitura demorou demais. Use a opinião automática.",
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("ai_review_failed: %s", exc)
        return {
            "verdict": "unsure",
            "confidence": 0,
            "reasons": [],
            "summary": "",
            "source": "unavailable",
            "error": "Não foi possível pedir a segunda opinião agora.",
        }
