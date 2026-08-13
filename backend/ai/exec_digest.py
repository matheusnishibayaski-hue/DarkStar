"""Limpa stdout de tools e resume execuções para o relatório."""

from __future__ import annotations

import re
from typing import Any

_CSI = re.compile(r"\x1b\[[0-9;:?]*[A-Za-z]")
_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_OTHER_ESC = re.compile(r"\x1b[@-Z\\-_]")
_LEFTOVER_SGR = re.compile(r"\[[\d;]{1,12}m")
_CR = re.compile(r"\r+")
_HOST = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
    re.I,
)
_NMAP_PORT = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)", re.I | re.M)
_HTTP_STATUS = re.compile(r"https?://\S+", re.I)
_STATUS_CODE = re.compile(r"\[(\d{3})\]")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_NIKTO_PLUS = re.compile(r"^\+\s+(.+)$", re.M)
_NUCLEI_FIND = re.compile(r"\[(?:critical|high|medium|low|info)\][^\n]*", re.I)
_UNRESPONSIVE = re.compile(r"skipped\s+\S+\s+from target list as found unresponsive", re.I)
_NO_INPUT = re.compile(r"no input provided|no files found", re.I)
_WORDLIST = re.compile(
    r"(?:wordlist|file).*(?:does not exist|not found|no such file)|cannot find file",
    re.I,
)
_WHATWEB_TITLE = re.compile(r"Title\[([^\]]+)\]", re.I)
_WHATWEB_SERVER = re.compile(r"(?:HTTPServer|Microsoft-IIS|nginx|Apache)[^\],]*", re.I)
_BANNER_HINTS = (
    "projectdiscovery.io",
    "httpx.io",
    "nuclei - fast and customisable",
    "https://docs.projectdiscovery.io",
)


def strip_ansi(text: str) -> str:
    raw = str(text or "")
    raw = _OSC.sub("", raw)
    raw = _CSI.sub("", raw)
    raw = _OTHER_ESC.sub("", raw)
    raw = _CR.sub("\n", raw)
    raw = _LEFTOVER_SGR.sub("", raw)
    return raw.replace("\x00", "")


def _is_banner_line(line: str) -> bool:
    s = line.strip()
    if not s:
        return False
    low = s.lower()
    if any(h in low for h in _BANNER_HINTS):
        return True
    if re.fullmatch(r"[\W_]+", s) and len(s) >= 8:
        return True
    art = sum(1 for c in s if c in r"|/_\\`'.,-=+*#░▒▓█▀▄")
    letters = sum(1 for c in s if c.isalpha())
    if len(s) > 14 and art / len(s) > 0.42 and letters < 8:
        return True
    return False


def clean_tool_output(text: str, *, max_chars: int = 1200) -> str:
    cleaned = strip_ansi(text)
    kept: list[str] = []
    blank = 0
    for line in cleaned.splitlines():
        if _is_banner_line(line):
            continue
        stripped = line.rstrip()
        if not stripped.strip():
            blank += 1
            if blank > 1:
                continue
            kept.append("")
            continue
        blank = 0
        kept.append(stripped)
    body = "\n".join(kept).strip()
    if len(body) > max_chars:
        body = body[: max_chars - 1].rstrip() + "…"
    return body


def _tool_name(ex: dict[str, Any]) -> str:
    tool = str(ex.get("tool") or "").strip()
    if tool:
        return tool.split("/")[-1].lower()
    cmd = str(ex.get("command") or "").strip()
    if not cmd:
        return "comando"
    return cmd.split()[0].split("/")[-1].lower()


def _status(ex: dict[str, Any]) -> tuple[str, str]:
    if ex.get("blocked"):
        return "blocked", "BLOQUEADO"
    if ex.get("success"):
        return "ok", "OK"
    return "fail", "FALHA"


def _hosts_from(text: str) -> list[str]:
    seen: list[str] = []
    for m in _HOST.findall(text or ""):
        h = m.lower().rstrip(".")
        if h not in seen and "localhost" not in h:
            seen.append(h)
        if len(seen) >= 8:
            break
    return seen


def _digest_subfinder(clean: str) -> tuple[str, list[str]]:
    hosts = [ln.strip() for ln in clean.splitlines() if ln.strip() and " " not in ln.strip()]
    if not hosts:
        hosts = _hosts_from(clean)
    n = len(hosts)
    if n == 0:
        return "Nenhum subdomínio listado.", []
    phrase = f"Encontrou {n} subdomínio{'s' if n != 1 else ''}."
    return phrase, hosts[:6]


def _digest_nmap(clean: str) -> tuple[str, list[str]]:
    ports = _NMAP_PORT.findall(clean)
    bullets = [f"Porta {num}/{proto} aberta — {svc}" for num, proto, svc in ports[:8]]
    up = "Host is up" in clean or "host is up" in clean.lower()
    if ports:
        phrase = f"{'Alvo no ar. ' if up else ''}{len(ports)} porta(s) aberta(s)."
        return phrase, bullets
    if "0 hosts up" in clean.lower() or "host seems down" in clean.lower():
        return "O nmap não viu o host no ar.", ["Nenhuma porta aberta reportada."]
    return "Varredura de portas concluída, sem 'open' na saída.", []


def _digest_httpx(clean: str, ok: bool) -> tuple[str, list[str], str]:
    fail = ""
    if _NO_INPUT.search(clean):
        fail = (
            "O httpx esperava um arquivo com `-l` (lista de URLs), "
            "não nomes separados por vírgula."
        )
        return "Não rodou: faltou arquivo de entrada.", [], fail
    urls = _HTTP_STATUS.findall(clean)
    bullets: list[str] = []
    for u in urls[:6]:
        codes = _STATUS_CODE.findall(u)
        extra = f" [{codes[-1]}]" if codes else ""
        bullets.append(u.split()[0][:120] + extra)
    if urls:
        return f"Respondeu em {len(urls)} URL(s).", bullets, ""
    if ok:
        return "httpx terminou sem listar URLs na saída.", [], ""
    return "httpx falhou.", [], fail or (clean.splitlines()[-1][:200] if clean else "")


def _digest_whatweb(clean: str) -> tuple[str, list[str]]:
    bullets: list[str] = []
    title = _WHATWEB_TITLE.search(clean)
    if title:
        bullets.append(f"Título: {title.group(1).strip()[:80]}")
    server = _WHATWEB_SERVER.search(clean)
    if server:
        bullets.append(server.group(0).strip()[:100])
    ip = _IP.search(clean)
    if ip:
        bullets.append(f"IP: {ip.group(0)}")
    if bullets:
        return "Identificou o site (título/servidor).", bullets
    return "whatweb rodou; pouco texto útil após limpar as cores.", []


def _digest_gobuster(clean: str, ok: bool) -> tuple[str, list[str], str]:
    if _WORDLIST.search(clean) or "no such file" in clean.lower():
        fail = "A wordlist apontada não existe neste Kali (caminho seclists ausente)."
        return "Não rodou: wordlist não encontrada.", [], fail
    hits = [ln.strip() for ln in clean.splitlines() if "Status:" in ln or ln.strip().startswith("/")]
    if hits:
        return f"Encontrou {len(hits)} caminho(s).", hits[:6], ""
    if ok:
        return "gobuster terminou sem caminhos listados.", [], ""
    return "gobuster falhou.", [], clean.splitlines()[-1][:200] if clean else ""


def _digest_nuclei(clean: str, ok: bool) -> tuple[str, list[str], str]:
    fail = ""
    if _UNRESPONSIVE.search(clean):
        fail = "O alvo foi pulado: nuclei considerou a porta 443 sem resposta (30 vezes)."
        return "Não varreu de verdade — alvo sem resposta.", [], fail
    finds = _NUCLEI_FIND.findall(clean)
    if finds:
        return f"Nuclei apontou {len(finds)} alerta(s).", finds[:6], ""
    if ok:
        return "Nuclei terminou sem alertas na saída.", [], ""
    return "Nuclei falhou ou não completou.", [], clean.splitlines()[-1][:200] if clean else ""


def _digest_nikto(clean: str) -> tuple[str, list[str]]:
    plus = [m.group(1).strip() for m in _NIKTO_PLUS.finditer(clean)]
    useful = [
        p
        for p in plus
        if not p.lower().startswith(("start time", "end time", "target ip", "target hostname"))
    ]
    if useful:
        return f"Nikto registrou {len(useful)} observação(ões).", useful[:6]
    return "Nikto rodou; sem linhas '+' relevantes.", []


def digest_execution(ex: dict[str, Any]) -> dict[str, Any]:
    tool = _tool_name(ex)
    code, label = _status(ex)
    cmd = str(ex.get("command") or "").strip()
    raw = "\n".join(filter(None, [str(ex.get("stdout") or ""), str(ex.get("stderr") or "")]))
    clean = clean_tool_output(raw, max_chars=4000)
    reason = str(ex.get("reason") or "").strip()
    phrase = ""
    bullets: list[str] = []
    failure = ""

    if tool == "subfinder":
        phrase, bullets = _digest_subfinder(clean)
    elif tool == "nmap":
        phrase, bullets = _digest_nmap(clean)
    elif tool == "httpx":
        phrase, bullets, failure = _digest_httpx(clean, code == "ok")
    elif tool == "whatweb":
        phrase, bullets = _digest_whatweb(clean)
    elif tool == "gobuster":
        phrase, bullets, failure = _digest_gobuster(clean, code == "ok")
    elif tool == "nuclei":
        phrase, bullets, failure = _digest_nuclei(clean, code == "ok")
    elif tool == "nikto":
        phrase, bullets = _digest_nikto(clean)
    else:
        lines = [ln.strip() for ln in clean.splitlines() if ln.strip()]
        if code != "ok":
            phrase = "O comando não completou com sucesso."
            failure = lines[-1][:220] if lines else ""
        elif lines:
            phrase = "Comando concluído."
            bullets = lines[:4]
        else:
            phrase = "Sem saída útil após limpar o log."

    if code == "blocked" and not failure:
        failure = reason or "Comando bloqueado pelo perfil ou pelo escopo."

    log = clean_tool_output(raw, max_chars=800)
    return {
        "tool": tool,
        "status": code,
        "status_label": label,
        "command": cmd[:500],
        "headline": phrase,
        "bullets": bullets[:6],
        "failure": failure[:400],
        "reason": reason[:400],
        "log": log,
    }
