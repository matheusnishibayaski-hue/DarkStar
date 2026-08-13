"""Segunda opinião de falso positivo via LLM (não marca o achado sozinha)."""

from __future__ import annotations

import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from typing import Any

from backend.ai.exec_digest import strip_ansi
from backend.ai.fp_explain import apply_fp_hard_rules, detect_finding_kind
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


def _likely_from_legacy(verdict: str, confidence: int) -> int:
    """Converte a antiga 'confiança no veredito' para chance de alarme falso."""
    if verdict == "false_positive":
        return confidence
    if verdict == "confirmed":
        return max(0, 100 - confidence) if confidence else 20
    return confidence if confidence else 50


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
    likely: int | None = None
    for key in ("likely_fp", "false_positive_chance"):
        if data.get(key) is None:
            continue
        try:
            likely = int(data[key])
        except (TypeError, ValueError):
            likely = None
        break
    if likely is None:
        likely = _likely_from_legacy(verdict, confidence)
    likely = max(0, min(100, likely))
    reasons = data.get("reasons") or []
    if isinstance(reasons, str):
        reasons = [reasons]
    reasons = [str(r).strip()[:280] for r in reasons if str(r).strip()][:4]
    summary = str(data.get("summary") or data.get("reason") or "").strip()[:400]
    if summary and not reasons:
        reasons = [summary]
    return {
        "verdict": verdict,
        "likely_fp": likely,
        "confidence": likely,
        "reasons": reasons,
        "summary": summary,
        "source": "llm",
        "adjusted": False,
        "adjust_reason": "",
    }


def calibrate_review(finding: dict[str, Any], review: dict[str, Any]) -> dict[str, Any]:
    """Regras duras na mesma escala da heurística (chance de alarme falso)."""
    out = dict(review or {})
    kind = detect_finding_kind(finding)
    blob = " ".join(
        str(finding.get(k) or "")
        for k in ("title", "evidence", "template_id", "cve", "tool", "command", "severity")
    ).lower()
    verdict = str(out.get("verdict") or "unsure")
    try:
        if out.get("likely_fp") is not None:
            likely = int(out["likely_fp"])
        else:
            conf = int(out.get("confidence") or 0)
            likely = _likely_from_legacy(verdict, conf)
    except (TypeError, ValueError):
        likely = 50
    likely, verdict, adjusted, reason = apply_fp_hard_rules(
        kind=kind, blob=blob, likely_fp=likely, verdict=verdict
    )
    out["verdict"] = verdict
    out["likely_fp"] = likely
    out["confidence"] = likely
    out["adjusted"] = bool(adjusted or out.get("adjusted"))
    if reason:
        out["adjust_reason"] = reason
    else:
        out.setdefault("adjust_reason", "")
    return out


def _prompt(finding: dict[str, Any]) -> str:
    evidence = strip_ansi(str(finding.get("evidence") or ""))[:1200]
    title = str(finding.get("title") or finding.get("plain_title") or "Achado")[:200]
    cmd = str(finding.get("command") or "")[:400]
    tool = str(finding.get("tool") or "")[:80]
    ftype = detect_finding_kind(finding)
    return (
        "Você é a Argus, assistente de pentest. Leia só os fatos abaixo e diga se parece "
        "vulnerabilidade real, alarme falso, ou incerto. Não invente evidência. "
        "Não copie nenhum veredito prévio — julgue só tipo, comando e evidência.\n"
        "likely_fp é a chance de alarme falso (0–100), NÃO a confiança no veredito.\n"
        "Responda SÓ um JSON: "
        '{"verdict":"confirmed"|"false_positive"|"unsure","likely_fp":0-100,'
        '"summary":"frase em português","reasons":["motivo 1","motivo 2"]}\n\n'
        f"Tipo: {ftype}\nTítulo: {title}\n"
        f"Ferramenta: {tool}\nComando: {cmd}\n"
        f"Evidência:\n{evidence or '(vazia)'}\n"
    )


def _unavailable(error: str) -> dict[str, Any]:
    return {
        "verdict": "unsure",
        "likely_fp": 50,
        "confidence": 50,
        "reasons": [],
        "summary": "",
        "source": "unavailable",
        "error": error,
        "adjusted": False,
        "adjust_reason": "",
    }


def _call_llm(finding: dict[str, Any]) -> dict[str, Any]:
    from backend.ai.providers import get_llm_provider

    provider = get_llm_provider()
    if not provider.is_configured():
        return _unavailable("IA não configurada (offline sem Ollama ou sem chave).")
    model, _ = provider.resolve_models(PRIMARY_MODEL, None)
    completion = provider.complete(
        model=model,
        messages=[
            {"role": "system", "content": "Responda apenas JSON válido, em português."},
            {"role": "user", "content": _prompt(finding)},
        ],
        tools=None,
        tool_choice=None,
    )
    text = (completion.message.content or "") if completion and completion.message else ""
    parsed = parse_ai_review(text)
    if not parsed:
        return _unavailable("A IA não devolveu um JSON utilizável.")
    return parsed


def review_finding(finding: dict[str, Any]) -> dict[str, Any]:
    cached = finding.get("ai_review")
    if isinstance(cached, dict) and cached.get("source") == "llm" and cached.get("verdict"):
        return calibrate_review(finding, cached)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(_call_llm, finding)
            parsed = fut.result(timeout=_REVIEW_TIMEOUT_SEC)
    except FuturesTimeout:
        logger.info("ai_review_timeout")
        return _unavailable("A segunda leitura demorou demais. Use a opinião automática.")
    except Exception as exc:  # noqa: BLE001
        logger.warning("ai_review_failed: %s", exc)
        return _unavailable("Não foi possível pedir a segunda opinião agora.")
    if parsed.get("source") != "llm":
        return parsed
    return calibrate_review(finding, parsed)
