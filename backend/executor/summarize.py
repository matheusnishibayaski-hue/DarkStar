import re

from backend.config import OUTPUT_TOKEN_LIMIT, SUMMARY_HEAD_LINES, SUMMARY_TAIL_LINES

CRITICAL_LINE_PATTERNS = [
    re.compile(r"\[CRITICAL\]", re.I),
    re.compile(r"\[HIGH\]", re.I),
    re.compile(r"\[MEDIUM\]", re.I),
    re.compile(r"\[VULNERABLE\]", re.I),
    re.compile(r"\[CVE-", re.I),
    re.compile(r"CVE-\d{4}-\d+", re.I),
    re.compile(r"\bopen/tcp\b", re.I),
    re.compile(r"\bopen/udp\b", re.I),
    re.compile(r"\bVULNERABILITY\b", re.I),
    re.compile(r"\bSQL injection\b", re.I),
    re.compile(r"\bfound\b.*\bvuln", re.I),
    re.compile(r"^\d+/tcp\s+open", re.I),
    re.compile(r"^\d+/udp\s+open", re.I),
]

TRUNCATION_NOTE = "[Output truncado para economia. Resumo técnico abaixo:]"


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def _extract_critical_lines(lines: list[str]) -> list[str]:
    critical: list[str] = []
    seen: set[str] = set()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped in seen:
            continue
        if any(p.search(line) for p in CRITICAL_LINE_PATTERNS):
            seen.add(stripped)
            critical.append(line)
    return critical


def summarize_output(stdout: str, stderr: str = "") -> tuple[str, bool]:
    """Retorna (texto_resumido, foi_truncado)."""
    combined = "\n".join(part for part in (stdout, stderr) if part).strip()
    if not combined:
        return "", False

    if estimate_tokens(combined) <= OUTPUT_TOKEN_LIMIT:
        return combined, False

    lines = combined.splitlines()
    head = lines[:SUMMARY_HEAD_LINES]
    tail = (
        lines[-SUMMARY_TAIL_LINES:] if len(lines) > SUMMARY_HEAD_LINES + SUMMARY_TAIL_LINES else []
    )
    critical = _extract_critical_lines(lines)

    sections = [TRUNCATION_NOTE, "", f"=== Início ({SUMMARY_HEAD_LINES} linhas) ==="]
    sections.extend(head)

    if critical:
        sections.extend(["", "=== Linhas críticas ==="])
        sections.extend(critical)

    if tail:
        sections.extend(["", f"=== Final ({SUMMARY_TAIL_LINES} linhas) ==="])
        sections.extend(tail)

    sections.append("")
    sections.append(
        f"[Total original: {len(lines)} linhas, ~{estimate_tokens(combined)} tokens estimados]"
    )

    return "\n".join(sections), True
