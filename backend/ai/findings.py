"""Heurísticas de verificação de findings do Attack Surface."""

from __future__ import annotations

from typing import Any

from backend.executor.surface import load_surface, mark_finding_status, save_surface


def auto_verify_from_execution(
    target: str,
    *,
    command: str,
    tool: str,
    stdout: str,
    stderr: str,
    success: bool,
) -> list[dict[str, Any]]:
    """
    Quando um comando de verificação (curl/httpx/nuclei/nmap) sucede e
    menciona um finding candidato, promove para confirmed.
    Se re-scan limpo (sucesso sem menção), marca inconclusive (pipeline decide depois).
    """
    data = load_surface(target)
    if not data:
        return []

    output = f"{stdout or ''}\n{stderr or ''}\n{command or ''}".lower()
    tool_l = (tool or "").lower()
    verify_tools = {"curl", "httpx", "nuclei", "nmap", "openssl", "nikto", "wpscan", "sslscan"}

    updated: list[dict[str, Any]] = []
    for finding in list(data.get("findings") or []):
        if finding.get("status") not in {"candidate", "inconclusive"}:
            continue
        title = str(finding.get("title") or "")
        fid = str(finding.get("id") or "")
        needle = title.lower()[:80]
        mentioned = bool(needle) and needle[:40] in output
        cve_like = "cve-" in needle
        if cve_like and not mentioned:
            import re

            m = re.search(r"cve-\d{4}-\d+", needle)
            if m:
                mentioned = m.group(0) in output

        same_tool_rescan = (
            success
            and tool_l
            and tool_l == str(finding.get("tool") or "").lower()
            and tool_l in verify_tools
            and (needle[:40] in output if needle else False)
        )

        if success and (mentioned or same_tool_rescan):
            result = mark_finding_status(
                target,
                fid,
                "confirmed",
                evidence=(stdout or stderr or title)[:500],
            )
            if result:
                updated.append(result)
            continue

        # Re-scan da mesma família sem menção → não confirma; deixa para pipeline
        if (
            success
            and tool_l in verify_tools
            and not mentioned
            and finding.get("status") == "candidate"
        ):
            # Não marca FP aqui — o pipeline assertivo fará PoC dedicado
            pass

    return updated


def confirmed_findings(target: str) -> list[dict[str, Any]]:
    data = load_surface(target)
    if not data:
        return []
    return [f for f in (data.get("findings") or []) if f.get("status") == "confirmed"]


def findings_for_report(target: str) -> dict[str, list[dict[str, Any]]]:
    """Buckets finais para relatório assertivo (sem candidatos soltos)."""
    data = load_surface(target)
    findings = list((data or {}).get("findings") or [])
    return {
        "confirmed": [f for f in findings if f.get("status") == "confirmed"],
        "false_positive": [f for f in findings if f.get("status") == "false_positive"],
        "discarded": [f for f in findings if f.get("status") == "discarded"],
        "inconclusive": [f for f in findings if f.get("status") == "inconclusive"],
        "candidates": [f for f in findings if f.get("status") == "candidate"],
    }


def executive_findings(target: str) -> list[dict[str, Any]]:
    """Confirmados com confiança medium/high — prontos para o cliente."""
    from backend.ai.verify import confidence_gate_buckets

    return confidence_gate_buckets(target)["executive"]


def set_phase(target: str, phase: str) -> dict[str, Any] | None:
    data = load_surface(target)
    if not data:
        return None
    data["phase"] = phase
    return save_surface(target, data)
