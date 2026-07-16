"""Geração de relatórios Markdown a partir do histórico e execuções."""

import re
from datetime import datetime, timezone

from backend.deps import APP_VERSION
from backend.executor.files_store import list_output_files
from backend.executor.recon_db import list_recon_summaries


def _extract_vulnerabilities(tool_executions: list[dict]) -> list[dict]:
    vulns: list[dict] = []
    seen: set[str] = set()

    for ex in tool_executions:
        output = "\n".join(filter(None, [ex.get("stdout", ""), ex.get("stderr", "")]))
        command = ex.get("command", "")

        for match in re.finditer(
            r"\[(critical|high|medium|low|info)\][^\n]*",
            output,
            re.I,
        ):
            line = match.group(0).strip()
            if line not in seen:
                seen.add(line)
                vulns.append(
                    {"severity": match.group(1).upper(), "detail": line, "source": command}
                )

        for match in re.finditer(
            r"(\d+/tcp\s+open\s+\S+(?:\s+\S+)*)",
            output,
            re.I,
        ):
            line = match.group(1).strip()
            if line not in seen:
                seen.add(line)
                vulns.append(
                    {"severity": "INFO", "detail": f"Porta aberta: {line}", "source": command}
                )

        for match in re.finditer(r"CVE-\d{4}-\d+", output, re.I):
            cve = match.group(0).upper()
            if cve not in seen:
                seen.add(cve)
                vulns.append({"severity": "HIGH", "detail": cve, "source": command})

    return vulns


def generate_report(
    history: list[dict],
    tool_executions: list[dict],
    title: str = "Relatório de Pentest",
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    vulns = _extract_vulnerabilities(tool_executions)

    user_messages = [m["content"] for m in history if m.get("role") == "user"]
    assistant_messages = [m["content"] for m in history if m.get("role") == "assistant"]

    scope = user_messages[0][:200] if user_messages else "Não especificado"
    executive = (
        assistant_messages[-1][:800] if assistant_messages else "Sessão sem conclusões registradas."
    )

    lines = [
        f"# {title}",
        "",
        f"**Data:** {now}  ",
        f"**Ferramenta:** Chat IA Kali v{APP_VERSION}  ",
        f"**Execuções registradas:** {len(tool_executions)}",
        "",
        "---",
        "",
        "## 1. Resumo Executivo",
        "",
        executive,
        "",
        f"**Escopo inicial (primeira solicitação):** {scope}",
        "",
        "---",
        "",
        "## 2. Resumo Técnico",
        "",
        "| # | Comando | Status | Motivo |",
        "|---|---------|--------|--------|",
    ]

    for i, ex in enumerate(tool_executions, 1):
        status = (
            "OK"
            if ex.get("success")
            else ("BLOQUEADO" if ex.get("blocked") else f"EXIT {ex.get('exit_code')}")
        )
        cmd = ex.get("command", "").replace("|", "\\|")
        reason = ex.get("reason", "").replace("|", "\\|")[:80]
        lines.append(f"| {i} | `{cmd}` | {status} | {reason} |")

    lines.extend(["", "---", "", "## 3. Tabela de Vulnerabilidades / Achados", ""])

    if vulns:
        lines.extend(
            [
                "| Severidade | Detalhe | Origem |",
                "|------------|---------|--------|",
            ]
        )
        for v in vulns[:50]:
            detail = v["detail"].replace("|", "\\|")[:120]
            source = v["source"].replace("|", "\\|")[:60]
            lines.append(f"| {v['severity']} | {detail} | `{source}` |")
    else:
        lines.append("*Nenhuma vulnerabilidade crítica extraída automaticamente dos logs.*")

    lines.extend(["", "---", "", "## 4. Recon cacheado (/var/recon)", ""])
    recon_summaries = list_recon_summaries()
    if recon_summaries:
        lines.extend(
            [
                "| Alvo | Portas | CVEs | Achados | Atualizado |",
                "|------|--------|------|---------|------------|",
            ]
        )
        for r in recon_summaries[:20]:
            lines.append(
                f"| {r.get('target', '')} | {r.get('open_ports_count', 0)} | "
                f"{r.get('cves_count', 0)} | {r.get('vulnerabilities_count', 0)} | "
                f"{r.get('updated_at', '')[:16]} |"
            )
    else:
        lines.append("*Nenhum dado de recon persistido.*")

    lines.extend(["", "---", "", "## 5. Artefatos (/tools/output)", ""])
    artifacts = list_output_files()
    if artifacts:
        lines.append("| Arquivo | Tamanho | Modificado |")
        lines.append("|---------|---------|------------|")
        for f in artifacts[:30]:
            size_kb = f.get("size", 0) // 1024
            lines.append(
                f"| `{f.get('name', '')}` | {size_kb} KB | {f.get('modified_at', '')[:16]} |"
            )
    else:
        lines.append("*Nenhum artefato em /tools/output.*")

    lines.extend(
        [
            "",
            "---",
            "",
            "## 6. Recomendações de Mitigação",
            "",
            "1. **Patch Management:** Aplicar correções para CVEs e serviços desatualizados identificados.",
            "2. **Hardening:** Fechar portas/serviços desnecessários expostos na varredura.",
            "3. **Monitoramento:** Implementar detecção para tentativas de exploração nas superfícies encontradas.",
            "4. **Reteste:** Validar mitigações com nova rodada de scans autorizados.",
            "",
            "---",
            "",
            "## 7. Anexo — Logs",
            "",
        ]
    )

    for ex in tool_executions:
        log_id = ex.get("log_file_id", "")
        cmd = ex.get("command", "")
        if log_id:
            lines.append(f"- `{cmd}` → log `{log_id}` (GET /api/logs/{log_id})")
        else:
            lines.append(f"- `{cmd}` → sem log persistido")

    lines.extend(
        [
            "",
            "*Relatório gerado automaticamente pelo Chat IA Kali. Revisão humana obrigatória.*",
            "",
        ]
    )
    return "\n".join(lines)
