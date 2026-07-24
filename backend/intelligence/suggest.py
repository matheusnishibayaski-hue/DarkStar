"""Sugestões de próximos checks a partir de surface + padrões."""

from __future__ import annotations

from typing import Any

from backend.intelligence.patterns import pattern_key_for_finding, top_patterns


def build_suggestions(
    surface: dict[str, Any],
    patterns: dict[str, Any],
    *,
    industry: str | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Gera sugestões heurísticas rankeadas (sem claim de acurácia)."""
    findings = surface.get("findings") or []
    ports = surface.get("ports") or []
    urls = surface.get("urls") or []
    tools = {str(t).lower() for t in (surface.get("tools_run") or [])}

    present_keys = {pattern_key_for_finding(f)[0] for f in findings}
    suggestions: list[dict[str, Any]] = []

    open_ports = {str(p.get("port")) for p in ports if isinstance(p, dict)}
    has_http = bool(urls) or "80" in open_ports or "443" in open_ports or "8080" in open_ports

    if has_http and "nuclei" not in tools:
        suggestions.append(
            {
                "suggestion": "Rodar nuclei -jsonl nas URLs/hosts HTTP descobertos",
                "priority": 1,
                "confidence": "high",
                "rationale": "Há superfície web e nuclei ainda não aparece em tools_run.",
                "related_keys": ["tool:nuclei"],
            }
        )

    if open_ports and "nmap" not in tools and not any("nmap" in t for t in tools):
        # tools_run pode já ter nmap; se ports existem provavelmente rodou — só sugere se vazio
        pass
    if not open_ports and "nmap" not in tools:
        suggestions.append(
            {
                "suggestion": "Mapear portas com nmap -sV -Pn no alvo",
                "priority": 1,
                "confidence": "high",
                "rationale": "Nenhuma porta registrada no Attack Surface.",
                "related_keys": ["tool:nmap"],
            }
        )

    candidates = [f for f in findings if str(f.get("status") or "") in {"", "candidate", "inconclusive"}]
    if candidates:
        suggestions.append(
            {
                "suggestion": f"Verificar/PoC em {min(len(candidates), 5)} finding(s) candidatos/inconclusivos",
                "priority": 2,
                "confidence": "medium",
                "rationale": "Há achados sem status confirmed — pipeline verify reduz falso positivo.",
                "related_keys": [pattern_key_for_finding(f)[0] for f in candidates[:5]],
            }
        )

    kev_like = [f for f in findings if f.get("cisa_kev_flag") or f.get("cve")]
    if kev_like and not any(str(f.get("status")) == "confirmed" for f in kev_like):
        suggestions.append(
            {
                "suggestion": "Priorizar CVEs (e KEV se marcado) no verify/PoC",
                "priority": 1,
                "confidence": "high",
                "rationale": "Achados com CVE merecem confirmação antes do executivo.",
                "related_keys": [pattern_key_for_finding(f)[0] for f in kev_like[:5]],
            }
        )

    for pat in top_patterns(patterns, industry=industry, limit=15):
        key = str(pat.get("pattern_key") or "")
        if not key or key in present_keys:
            continue
        freq = int(pat.get("frequency") or 0)
        if freq < 2:
            continue
        suggestions.append(
            {
                "suggestion": f"Checar padrão recorrente: {pat.get('title_sample') or key}",
                "priority": 3 if freq < 5 else 2,
                "confidence": "medium" if freq < 5 else "high",
                "rationale": (
                    f"Padrão {key} visto {freq}x no histórico"
                    + (f" (industry={pat.get('industry')})" if pat.get("industry") else "")
                    + "; ausente no surface atual."
                ),
                "related_keys": [key],
            }
        )

    # Dedup por suggestion text
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for s in sorted(suggestions, key=lambda x: (int(x.get("priority") or 9), x.get("suggestion", ""))):
        text = str(s.get("suggestion") or "")
        if text in seen:
            continue
        seen.add(text)
        unique.append(s)
        if len(unique) >= limit:
            break

    if not unique:
        unique.append(
            {
                "suggestion": "Executar recon básico (subfinder/httpx) ou nmap -sV e gravar surface",
                "priority": 2,
                "confidence": "low",
                "rationale": "Histórico/padrões insuficientes para sugestões específicas.",
                "related_keys": [],
            }
        )
    return unique
