"""Extrai intel compacto de anexos de projeto (mapa + arquivos) para pentest white-box."""

from __future__ import annotations

import json
import re
from typing import Any

_URL_RE = re.compile(
    r"https?://[^\s\"'<>\]\)]+|wss?://[^\s\"'<>\]\)]+",
    re.I,
)
_HOST_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,}|localhost)\b",
    re.I,
)
_PORT_RE = re.compile(
    r"(?:(?:ports?|PORT|listen|expose|published)\s*[:=]\s*|:)(\d{2,5})\b|"
    r"[\"'](\d{2,5}):(\d{2,5})[\"']|"
    r"-\s*[\"']?(\d{2,5}):(\d{2,5})[\"']?",
)
_PATH_RE = re.compile(r"[\"'`](/[a-zA-Z0-9_\-./{}:]+)[\"'`]")
_OPENAPI_PATH_RE = re.compile(r'["\'](/[a-zA-Z0-9_\-./{}]+)["\']\s*:\s*\{')

_NOISE_HOSTS = frozenset(
    {
        "github.com",
        "githubusercontent.com",
        "npmjs.com",
        "registry.npmjs.org",
        "pypi.org",
        "python.org",
        "example.com",
        "example.org",
        "localhost",
        "schema.org",
        "w3.org",
        "googleapis.com",
        "openrouter.ai",
    }
)


def _norm_items(attachments: list | None) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for item in attachments or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")[:256]
        content = str(item.get("content") or "")[:200000]
        if name and content:
            out.append({"name": name, "content": content})
    return out


def _detect_stack(names: list[str], blobs: str) -> list[str]:
    stack: list[str] = []
    lower_names = " ".join(n.lower() for n in names)
    low = blobs.lower()
    if "package.json" in lower_names or '"dependencies"' in low:
        stack.append("Node/JS")
    if any(x in lower_names for x in ("requirements.txt", "pyproject.toml", "poetry.lock")):
        stack.append("Python")
    if "go.mod" in lower_names:
        stack.append("Go")
    if "cargo.toml" in lower_names:
        stack.append("Rust")
    if "pom.xml" in lower_names or "build.gradle" in lower_names:
        stack.append("Java")
    if "composer.json" in lower_names:
        stack.append("PHP")
    if "gemfile" in lower_names:
        stack.append("Ruby")
    if any(x in lower_names for x in ("dockerfile", "docker-compose")):
        stack.append("Docker")
    if "next.config" in lower_names or "next" in low and "react" in low:
        stack.append("Next.js")
    if "fastapi" in low or "from fastapi" in low:
        stack.append("FastAPI")
    if "django" in low:
        stack.append("Django")
    if "flask" in low:
        stack.append("Flask")
    if "express" in low:
        stack.append("Express")
    # dedupe preserve order
    seen: set[str] = set()
    ordered: list[str] = []
    for s in stack:
        if s not in seen:
            seen.add(s)
            ordered.append(s)
    return ordered[:8]


def _collect_urls(text: str, limit: int = 12) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for m in _URL_RE.finditer(text):
        u = m.group(0).rstrip(".,);]")
        if any(n in u for n in _NOISE_HOSTS):
            continue
        if u in seen:
            continue
        seen.add(u)
        found.append(u)
        if len(found) >= limit:
            break
    return found


def _collect_hosts(text: str, limit: int = 10) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for m in _HOST_RE.finditer(text):
        h = m.group(0).lower().rstrip(".")
        if "." not in h and h != "localhost":
            continue
        if h in _NOISE_HOSTS or h.endswith(".png") or h.endswith(".jpg"):
            continue
        if any(h.endswith("." + n) or h == n for n in _NOISE_HOSTS):
            continue
        if h.count(".") == 1 and h.split(".")[1] in {
            "get",
            "post",
            "put",
            "json",
            "js",
            "ts",
            "py",
            "css",
        }:
            continue
        if h in seen:
            continue
        seen.add(h)
        found.append(h)
        if len(found) >= limit:
            break
    return found


def _collect_ports(text: str, limit: int = 12) -> list[int]:
    ports: list[int] = []
    seen: set[int] = set()
    for m in _PORT_RE.finditer(text):
        for g in m.groups():
            if not g:
                continue
            try:
                p = int(g)
            except ValueError:
                continue
            if p < 20 or p > 65535 or p in seen:
                continue
            seen.add(p)
            ports.append(p)
            if len(ports) >= limit:
                return ports
    return ports


def _collect_routes(names: list[str], text: str, limit: int = 20) -> list[str]:
    routes: list[str] = []
    seen: set[str] = set()
    for n in names:
        low = n.lower().replace("\\", "/")
        if any(seg in low for seg in ("/routes/", "/api/", "/auth/", "/middleware/")):
            if n not in seen:
                seen.add(n)
                routes.append(n)
    for m in _OPENAPI_PATH_RE.finditer(text):
        p = m.group(1)
        if len(p) < 2 or p in seen:
            continue
        seen.add(p)
        routes.append(p)
        if len(routes) >= limit:
            return routes[:limit]
    for m in _PATH_RE.finditer(text):
        p = m.group(1)
        if len(p) < 2 or p in {"/", "/static", "/favicon.ico"}:
            continue
        if p in seen:
            continue
        if not any(p.startswith(x) for x in ("/api", "/auth", "/v1", "/v2", "/admin", "/login")):
            continue
        seen.add(p)
        routes.append(p)
        if len(routes) >= limit:
            break
    return routes[:limit]


def _sensitive_files(names: list[str]) -> list[str]:
    hits: list[str] = []
    for n in names:
        low = n.lower()
        base = low.rsplit("/", 1)[-1]
        if base in {".env.example", ".env.sample", ".env.template"} or "docker-compose" in base:
            hits.append(n)
        if base.startswith("nginx") or base in {"openapi.yaml", "openapi.json", "swagger.json"}:
            hits.append(n)
    return hits[:10]


def _package_json_hints(content: str) -> list[str]:
    hints: list[str] = []
    try:
        data = json.loads(content)
    except Exception:
        return hints
    if not isinstance(data, dict):
        return hints
    deps = {}
    for key in ("dependencies", "devDependencies"):
        block = data.get(key)
        if isinstance(block, dict):
            deps.update(block)
    for pkg in ("express", "fastify", "next", "nuxt", "nestjs", "react", "vue"):
        if pkg in deps:
            hints.append(f"dep:{pkg}")
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for s in list(scripts.keys())[:6]:
            hints.append(f"script:{s}")
    return hints[:12]


def extract_project_intel(attachments: list | None) -> str:
    """Retorna bloco [PROJECT INTEL] ou string vazia."""
    items = _norm_items(attachments)
    if not items:
        return ""

    names = [i["name"] for i in items]
    # Prefer content files over giant map for regex (map still used for routes paths)
    blobs: list[str] = []
    map_text = ""
    for i in items:
        if i["name"] == "__project_map.txt":
            map_text = i["content"]
        else:
            blobs.append(i["content"][:80000])
    combined = "\n".join(blobs)
    scan_text = combined + "\n" + map_text[:50000]

    stack = _detect_stack(names, combined)
    for i in items:
        if i["name"].endswith("package.json") or i["name"] == "package.json":
            stack_extra = _package_json_hints(i["content"])
            for h in stack_extra:
                if h.startswith("dep:") and h[4:] not in " ".join(stack).lower():
                    stack.append(h[4:].title() if len(h) < 20 else h)
            break

    urls = _collect_urls(combined)
    hosts = _collect_hosts(combined)
    ports = _collect_ports(scan_text)
    routes = _collect_routes(names, combined)
    sensitive = _sensitive_files(names)

    # tool bias hint — diversificado (não só o trio web)
    bias: list[str] = []
    joined = " ".join(stack).lower() + " " + combined.lower()[:4000]
    if any(
        x in joined
        for x in ("node", "next", "express", "fastapi", "django", "flask", "php", "vue", "react")
    ):
        bias.extend(["httpx", "katana", "nuclei", "nikto", "ffuf"])
    if any(x in joined for x in ("dns", "subdomain", "domain")):
        bias.extend(["dnsx", "amass", "subfinder", "dig"])
    if any(x in joined for x in ("ssl", "tls", "https", "cert")):
        bias.extend(["sslscan", "tlsx", "testssl.sh"])
    if any(x in joined for x in ("smb", "samba", "445", "windows")):
        bias.extend(["smbmap", "enum4linux", "nmap"])
    if "docker" in joined or "container" in joined:
        bias.append("trivy")
    if ports or urls:
        bias.extend(["nmap", "httpx", "whatweb"])
    # dedupe bias
    bias_u: list[str] = []
    seen_b: set[str] = set()
    for b in bias:
        if b not in seen_b:
            seen_b.add(b)
            bias_u.append(b)

    lines = [
        "[PROJECT INTEL — derivado dos anexos; use para white-box / priorizar scans]",
        f"Arquivos anexados: {len(items)} (inclui mapa se presente)",
    ]
    if stack:
        lines.append("Stack: " + ", ".join(stack[:8]))
    if hosts:
        lines.append("Hosts candidatos: " + ", ".join(hosts[:8]))
    if urls:
        lines.append("URLs: " + ", ".join(urls[:8]))
    if ports:
        lines.append("Portas: " + ", ".join(str(p) for p in ports[:10]))
    if routes:
        lines.append("Entrypoints/rotas: " + ", ".join(routes[:12]))
    if sensitive:
        lines.append("Configs úteis: " + ", ".join(sensitive[:8]))
    if bias_u:
        lines.append("Preferência de ferramentas (quando fizer sentido): " + ", ".join(bias_u[:8]))
    lines.append(
        "Regras: priorize o alvo autorizado pelo operador; derive paths/portas do código; "
        "não invente hosts; se não houver alvo na mensagem, peça o host/URL."
    )
    return "\n".join(lines)


def apply_project_intel(user_message: str, attachments: list | None) -> str:
    block = extract_project_intel(attachments)
    if not block:
        return user_message
    return f"{block}\n\n{user_message}"


def operator_text_for_targets(user_message: str) -> str:
    """Remove blocos de anexos/intel para extract_targets não poluir com deps."""
    text = user_message or ""
    for marker in ("\n\n[Anexos]\n", "\n[Anexos]\n", "[PROJECT INTEL"):
        idx = text.find(marker if marker.startswith("\n") else f"\n{marker}")
        if idx < 0 and marker.startswith("["):
            idx = text.find(marker)
        if idx >= 0:
            text = text[:idx]
    return text.strip() or (user_message or "")[:2000]


def attachments_as_dicts(attachments: list | None) -> list[dict[str, Any]]:
    """Normaliza ChatAttachment / dict para lista de dicts."""
    out: list[dict[str, Any]] = []
    for item in attachments or []:
        if hasattr(item, "model_dump"):
            out.append(item.model_dump())
        elif isinstance(item, dict):
            out.append(item)
    return out
