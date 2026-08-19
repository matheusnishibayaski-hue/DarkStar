"""Preflight e utilitários do Piloto (alvo vivo, anti-repeat)."""

from __future__ import annotations

import re
from typing import Any

from backend.ai.tool_playbook import adaptive_first_actions, classify_target_kind


def preflight_commands(target: str, *, offline: bool = False) -> list[str]:
    """1–2 comandos leves para checar se o alvo responde."""
    kind = classify_target_kind(target)
    host = re.sub(r"^https?://", "", (target or "").strip(), flags=re.I).split("/")[0].split(":")[0]
    if kind == "url":
        url = target if target.lower().startswith("http") else f"https://{host}"
        return [f"httpx -u {url} -silent -status-code -timeout 8"]
    if offline:
        return [f"dig {host} A +time=3 +tries=1"]
    if kind == "ip":
        return [f"ping -c 2 -W 2 {host}"]
    return [f"ping -c 2 -W 2 {host}", f"dig {host} A +time=3 +tries=1"]


def interpret_preflight_output(
    *,
    commands: list[str],
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    """Decide alive/dead a partir de exit codes / stdout rasos."""
    if not results:
        return {"alive": True, "reason": "preflight vazio — assumindo vivo", "waive": False}
    any_ok = False
    infra_fail = False
    snippets: list[str] = []
    for r in results:
        code = int(r.get("exit_code") if r.get("exit_code") is not None else 1)
        out = f"{r.get('stdout') or ''}\n{r.get('stderr') or ''}".lower()
        snippets.append((r.get("command") or "")[:80])
        if any(
            x in out
            for x in (
                "docker",
                "no such container",
                "cannot connect",
                "blocked",
                "permission denied",
                "not found",
            )
        ):
            infra_fail = True
        if code == 0:
            any_ok = True
        if "status-code" in (r.get("command") or "") or "httpx" in (r.get("command") or ""):
            if re.search(r"\b[1-5]\d{2}\b", out):
                any_ok = True
        if "answer:" in out or "inx\t" in out or " has address" in out:
            any_ok = True
        if "1 received" in out or "bytes from" in out:
            any_ok = True
    if any_ok:
        return {"alive": True, "reason": "alvo respondeu no preflight", "waive": False}
    if infra_fail:
        return {
            "alive": True,
            "reason": "preflight inconclusivo (infra/kali) — seguindo",
            "waive": False,
        }
    return {
        "alive": False,
        "reason": "sem resposta no preflight (timeout/falha) — coverage_waived",
        "waive": True,
        "tried": snippets,
    }


def command_looks_repeated(command: str, tools_run: list[str] | None, recent_commands: list[str]) -> bool:
    """True se o binário já rodou e o comando é quase idêntico a um recente."""
    cmd = (command or "").strip().lower()
    if not cmd:
        return False
    binary = cmd.split()[0].split("/")[-1]
    used = {str(t).strip().lower() for t in (tools_run or [])}
    if binary not in used:
        return False
    # normalizar espaços
    norm = re.sub(r"\s+", " ", cmd)
    for prev in recent_commands[-12:]:
        p = re.sub(r"\s+", " ", (prev or "").strip().lower())
        if not p:
            continue
        if p == norm:
            return True
        # mesmo binário + mesmos 3 primeiros args
        if p.split()[:3] == norm.split()[:3] and binary == p.split()[0].split("/")[-1]:
            return True
    return False


def kickoff_target_hint(target: str, *, offline: bool = False) -> str:
    actions = adaptive_first_actions(target, offline=offline)
    return "\n".join(f"- {a}" for a in actions)
