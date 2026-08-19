"""Intel e relatório agrupados por conversa (chat_session_id)."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.config import BASE_DIR
from backend.executor.recon_db import normalize_target
from backend.executor.surface import load_surface, mark_finding_status, save_surface

INTEL_SESSIONS_DIR = BASE_DIR / "backend" / "intel_sessions"
_SESSION_ID_RE = re.compile(r"^[\w-]{8,128}$")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _session_path(session_id: str) -> Path | None:
    if not session_id or not _SESSION_ID_RE.match(session_id):
        return None
    INTEL_SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    return INTEL_SESSIONS_DIR / f"{session_id}.json"


def _load_session_from_file(session_id: str) -> dict[str, Any]:
    path = _session_path(session_id)
    if not path or not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def load_session(session_id: str) -> dict[str, Any]:
    """Carrega intel da conversa (DB; migra JSON legado se existir)."""
    from backend.database.db import ensure_dashboard_db, session_scope
    from backend.database.models_store import IntelSessionRow

    if not session_id or not _SESSION_ID_RE.match(session_id):
        return {}
    try:
        ensure_dashboard_db()
        with session_scope() as db:
            row = db.query(IntelSessionRow).filter(IntelSessionRow.session_id == session_id).first()
            if row:
                try:
                    data = json.loads(row.payload_json or "{}")
                except json.JSONDecodeError:
                    data = {}
                return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001
        pass

    # Fallback + migrate file → DB
    data = _load_session_from_file(session_id)
    if data:
        save_session(session_id, data)
        path = _session_path(session_id)
        if path and path.is_file():
            try:
                path.unlink()
            except OSError:
                pass
    return data


def save_session(session_id: str, data: dict[str, Any]) -> dict[str, Any]:
    """Persiste intel da conversa no banco."""
    from backend.database.db import ensure_dashboard_db, session_scope
    from backend.database.models_store import IntelSessionRow

    if not session_id or not _SESSION_ID_RE.match(session_id):
        return {}
    payload = dict(data)
    payload["session_id"] = session_id
    payload["updated_at"] = _now()
    if not payload.get("created_at"):
        payload["created_at"] = payload["updated_at"]
    raw = json.dumps(payload, ensure_ascii=False)
    try:
        ensure_dashboard_db()
        with session_scope() as db:
            row = db.query(IntelSessionRow).filter(IntelSessionRow.session_id == session_id).first()
            if row:
                row.payload_json = raw
            else:
                db.add(IntelSessionRow(session_id=session_id, payload_json=raw))
    except Exception:  # noqa: BLE001
        # último recurso: arquivo
        path = _session_path(session_id)
        if path:
            path.write_text(raw, encoding="utf-8")
    return payload


def touch_session(session_id: str, target: str) -> dict[str, Any]:
    """Registra alvo testado nesta conversa."""
    if not session_id or not target:
        return {}
    host = normalize_target(target)
    if not host:
        return {}
    data = load_session(session_id) or {
        "session_id": session_id,
        "label": "",
        "targets": [],
        "created_at": _now(),
    }
    targets = list(data.get("targets") or [])
    if host not in targets:
        targets.append(host)
    data["targets"] = targets[:50]
    return save_session(session_id, data)


def set_session_label(session_id: str, label: str) -> dict[str, Any]:
    data = load_session(session_id) or {
        "session_id": session_id,
        "label": "",
        "targets": [],
        "created_at": _now(),
    }
    data["label"] = (label or "").strip()[:120]
    return save_session(session_id, data)


def _finding_belongs_to_session(finding: dict[str, Any], session_id: str) -> bool:
    return str(finding.get("chat_session_id") or "") == session_id


def _parse_execution_log(raw: str) -> dict[str, str]:
    cmd = ""
    stdout_lines: list[str] = []
    stderr_lines: list[str] = []
    section = "head"
    for line in raw.splitlines():
        if line.startswith("Comando:"):
            cmd = line.split(":", 1)[-1].strip()
            continue
        if line.strip() == "=== STDOUT ===":
            section = "stdout"
            continue
        if line.strip() == "=== STDERR ===":
            section = "stderr"
            continue
        if section == "stdout":
            stdout_lines.append(line)
        elif section == "stderr":
            stderr_lines.append(line)
    return {
        "command": cmd,
        "stdout": "\n".join(stdout_lines).strip(),
        "stderr": "\n".join(stderr_lines).strip(),
    }


def sync_session_intel_from_logs(session_id: str) -> dict[str, Any]:
    """Reindexa alvos e achados a partir dos logs desta conversa."""
    from backend.executor.logs import list_log_ids_for_session, read_execution_log
    from backend.executor.recon_db import extract_targets, is_recon_target
    from backend.executor.surface import update_surface_from_execution

    stats = {"logs": 0, "targets_touched": 0, "surfaces_updated": 0, "session_findings": 0}
    data = load_session(session_id) or {
        "session_id": session_id,
        "label": "",
        "targets": [],
        "session_findings": [],
        "created_at": _now(),
    }
    session_findings: list[dict[str, Any]] = list(data.get("session_findings") or [])
    by_id = {str(f.get("id")): f for f in session_findings if f.get("id")}

    for log_id in list_log_ids_for_session(session_id):
        raw = read_execution_log(log_id)
        if not raw:
            continue
        stats["logs"] += 1
        parsed = _parse_execution_log(raw)
        cmd = parsed["command"]
        if not cmd:
            continue
        stdout = parsed["stdout"]
        stderr = parsed["stderr"]
        targets = [
            normalize_target(t) for t in extract_targets(cmd, stdout, stderr) if is_recon_target(t)
        ]
        for t in targets:
            touch_session(session_id, t)
            stats["targets_touched"] += 1

        tool = (cmd.split() or ["unknown"])[0].split("/")[-1].lower()
        success = not (stderr and "error" in stderr.lower()[:300])

        for target in dict.fromkeys(targets):
            try:
                update_surface_from_execution(
                    target,
                    command=cmd,
                    tool=tool,
                    stdout=stdout,
                    stderr=stderr,
                    success=success,
                    blocked=False,
                    exit_code=0 if success else 1,
                    chat_session_id=session_id,
                )
                stats["surfaces_updated"] += 1
            except Exception:
                pass

        fid = f"exec-{log_id}"
        if fid in by_id:
            continue
        host = targets[0] if targets else ""
        excerpt = (stdout or stderr or "Execução registrada (sem saída longa no log).")[:500]
        row = {
            "id": fid,
            "title": f"Resultado — {tool}",
            "severity": "info",
            "status": "candidate",
            "evidence": f"{cmd}\n\n{excerpt}"[:2000],
            "tool": tool,
            "command": cmd[:500],
            "host": host,
            "surface_target": host or "_session",
            "chat_session_id": session_id,
            "source": "execution_log",
        }
        session_findings.append(row)
        by_id[fid] = row
        stats["session_findings"] += 1

    data["session_findings"] = session_findings[-200:]
    save_session(session_id, data)
    return stats


def backfill_session_findings_from_client(
    session_id: str,
    executions: list[dict[str, Any]],
) -> dict[str, Any]:
    """Achados resumidos a partir das execuções salvas no navegador (quando logs não indexados)."""
    import hashlib

    from backend.executor.recon_db import extract_targets, is_recon_target

    data = load_session(session_id) or {
        "session_id": session_id,
        "label": "",
        "targets": [],
        "session_findings": [],
        "created_at": _now(),
    }
    session_findings: list[dict[str, Any]] = list(data.get("session_findings") or [])
    by_id = {str(f.get("id")): f for f in session_findings if f.get("id")}
    added = 0

    for idx, ex in enumerate(executions[:100]):
        if not isinstance(ex, dict):
            continue
        cmd = str(ex.get("command") or "").strip()
        if not cmd:
            continue
        stdout = str(ex.get("stdout") or "")
        stderr = str(ex.get("stderr") or "")
        targets = [
            normalize_target(t) for t in extract_targets(cmd, stdout, stderr) if is_recon_target(t)
        ]
        for t in targets:
            touch_session(session_id, t)

        digest = hashlib.sha256(
            f"{session_id}:{cmd}:{idx}".encode(), usedforsecurity=False
        ).hexdigest()[:12]
        fid = f"exec-client-{digest}"
        if fid in by_id:
            continue
        tool = str(ex.get("tool") or (cmd.split() or ["?"])[0]).split("/")[-1].lower()
        host = targets[0] if targets else ""
        excerpt = (stdout or stderr or "—")[:500]
        ok = ex.get("success", True)
        row = {
            "id": fid,
            "title": f"{'OK' if ok else 'Falha'} — {tool}",
            "severity": "info" if ok else "low",
            "status": "candidate",
            "evidence": f"{cmd}\n\n{excerpt}"[:2000],
            "tool": tool,
            "command": cmd[:500],
            "host": host,
            "surface_target": host or "_session",
            "chat_session_id": session_id,
            "source": "client_history",
        }
        session_findings.append(row)
        by_id[fid] = row
        added += 1

    data["session_findings"] = session_findings[-200:]
    save_session(session_id, data)
    return {"added": added, "total": len(session_findings)}


def aggregate_session_findings(session_id: str, *, sync: bool = True) -> list[dict[str, Any]]:
    """Achados de todos os alvos desta conversa + resumos de execução."""
    if sync:
        try:
            sync_session_intel_from_logs(session_id)
        except Exception:
            pass

    meta = load_session(session_id)
    targets = list(meta.get("targets") or [])

    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for target in targets:
        surface = load_surface(target)
        if not surface:
            continue
        for f in surface.get("findings") or []:
            if not isinstance(f, dict):
                continue
            if not _finding_belongs_to_session(f, session_id):
                continue
            fid = str(f.get("id") or "")
            key = f"surface:{target}:{fid}"
            if key in seen:
                continue
            seen.add(key)
            row = dict(f)
            row["surface_target"] = target
            out.append(row)

    for f in meta.get("session_findings") or []:
        if not isinstance(f, dict):
            continue
        fid = str(f.get("id") or "")
        if not fid or fid in seen:
            continue
        seen.add(fid)
        row = dict(f)
        if not row.get("surface_target"):
            row["surface_target"] = row.get("host") or "_session"
        out.append(row)

    return out


def ingest_extracted_findings(
    session_id: str,
    extra_executions: list[dict[str, Any]] | None = None,
    *,
    skip_disk_logs: bool = False,
) -> int:
    """Cria candidatos a partir das saídas das execuções (logs + histórico do chat)."""
    execs: list[dict[str, Any]] = []
    if not skip_disk_logs:
        execs = list(collect_session_tool_executions(session_id) or [])
    if extra_executions:
        for ex in extra_executions:
            if isinstance(ex, dict):
                execs.append(ex)
    if not execs:
        return 0
    from backend.ai.report import _extract_vulnerabilities

    vulns = _extract_vulnerabilities(execs)
    if not vulns:
        return 0
    data = load_session(session_id) or {
        "session_id": session_id,
        "label": "",
        "targets": [],
        "session_findings": [],
        "created_at": _now(),
    }
    session_findings: list[dict[str, Any]] = list(data.get("session_findings") or [])
    by_id = {str(f.get("id")): f for f in session_findings if f.get("id")}
    added = 0
    for i, v in enumerate(vulns):
        fid = f"extract-{i}-{abs(hash(str(v.get('detail') or i))) % 10_000_000}"
        if fid in by_id:
            continue
        sev = str(v.get("severity") or "info").lower()
        row = {
            "id": fid,
            "title": str(v.get("detail") or "Achado")[:200],
            "severity": sev,
            "status": "candidate",
            "evidence": str(v.get("detail") or "")[:2000],
            "tool": "",
            "command": str(v.get("source") or "")[:500],
            "host": "",
            "surface_target": "_session",
            "chat_session_id": session_id,
            "source": "execution_extract",
        }
        session_findings.append(row)
        by_id[fid] = row
        added += 1
    if not added:
        return 0
    data["session_findings"] = session_findings[-200:]
    save_session(session_id, data)
    return added


_ASSISTANT_FINDING_RULES: list[tuple[str, str, str, tuple[str, ...]]] = [
    (
        "idor",
        "IDOR / falha de autorização (acesso a dados de outros usuários)",
        "high",
        (
            "idor",
            "bola",
            "broken access",
            "broken object",
            "insecure direct object",
            "dados de outros usu",
            "outro usuário",
            "outro usuario",
            "outros usuários",
            "outros usuarios",
            "iterar sobre os id",
            "iterar sobre id",
            "não está validando corretamente a autoriza",
            "nao esta validando corretamente a autoriza",
            "falha de autoriza",
            "authorization bypass",
            "sem checar se quem pediu",
            "escalonamento de privil",
        ),
    ),
    (
        "xss",
        "XSS (script refletido ou armazenado)",
        "high",
        ("reflected xss", "stored xss", "cross-site scripting", "<script>alert"),
    ),
    (
        "sqli",
        "SQL Injection",
        "high",
        ("sql injection", "injeção de sql", "injecao de sql", "union select"),
    ),
]


def _excerpt_around(text: str, needle: str, *, radius: int = 450) -> str:
    low = text.lower()
    idx = low.find(needle.lower())
    if idx < 0:
        return text[:2000]
    start = max(0, idx - radius // 3)
    end = min(len(text), idx + len(needle) + radius)
    chunk = text[start:end].strip()
    if start > 0:
        chunk = "…" + chunk
    if end < len(text):
        chunk = chunk + "…"
    return chunk[:2000]


def ingest_assistant_findings(session_id: str) -> int:
    """Cria candidatos a partir da narrativa do assistente (IDOR, XSS, SQLi, …) sem LLM."""
    import hashlib

    try:
        from backend.database.chat_store import get_chat_session
    except Exception:  # noqa: BLE001
        return 0

    chat = get_chat_session(session_id) or {}
    messages = chat.get("messages") or []
    if not messages:
        return 0

    data = load_session(session_id) or {
        "session_id": session_id,
        "label": "",
        "targets": [],
        "session_findings": [],
        "created_at": _now(),
    }
    session_findings: list[dict[str, Any]] = list(data.get("session_findings") or [])
    by_id = {str(f.get("id")): f for f in session_findings if f.get("id")}
    added = 0

    for mi, msg in enumerate(messages):
        if not isinstance(msg, dict) or msg.get("role") != "assistant":
            continue
        content = str(msg.get("content") or "").strip()
        if len(content) < 40:
            continue
        low = content.lower()
        for kind, title, sev, needles in _ASSISTANT_FINDING_RULES:
            hit = next((n for n in needles if n in low), None)
            if not hit:
                continue
            digest = hashlib.sha256(
                f"{session_id}:{kind}:{hit}:{mi}".encode(), usedforsecurity=False
            ).hexdigest()[:12]
            fid = f"narr-{kind}-{digest}"
            if fid in by_id:
                break
            # Evita duplicar título parecido já presente
            title_key = title.lower()[:60]
            if any(
                title_key in str(f.get("title") or "").lower()
                and str(f.get("source") or "") == "assistant_narrative"
                for f in session_findings
            ):
                break
            evidence = _excerpt_around(content, hit)
            row = {
                "id": fid,
                "title": title,
                "severity": sev,
                "status": "candidate",
                "evidence": evidence,
                "tool": "assistant",
                "command": "",
                "host": "",
                "surface_target": "_session",
                "chat_session_id": session_id,
                "source": "assistant_narrative",
                "kind": kind,
            }
            session_findings.append(row)
            by_id[fid] = row
            added += 1
            break  # um achado por mensagem (o primeiro tipo que casar)

    if not added:
        return 0
    data["session_findings"] = session_findings[-200:]
    save_session(session_id, data)
    return added


def session_summary(session_id: str) -> dict[str, Any]:
    meta = load_session(session_id)
    findings = aggregate_session_findings(session_id)
    confirmed = sum(1 for f in findings if f.get("status") == "confirmed")
    return {
        "session_id": session_id,
        "label": meta.get("label") or "",
        "targets": meta.get("targets") or [],
        "findings_total": len(findings),
        "findings_confirmed": confirmed,
        "updated_at": meta.get("updated_at"),
        "created_at": meta.get("created_at"),
    }


def list_session_summaries() -> list[dict[str, Any]]:
    from backend.database.db import ensure_dashboard_db, session_scope
    from backend.database.models_store import IntelSessionRow

    ids: list[str] = []
    try:
        ensure_dashboard_db()
        with session_scope() as db:
            ids = [r.session_id for r in db.query(IntelSessionRow.session_id).all()]
    except Exception:  # noqa: BLE001
        ids = []

    # Migra arquivos restantes
    if INTEL_SESSIONS_DIR.is_dir():
        for path in INTEL_SESSIONS_DIR.glob("*.json"):
            sid = path.stem
            if _SESSION_ID_RE.match(sid) and sid not in ids:
                load_session(sid)  # migrate
                ids.append(sid)

    items = [session_summary(sid) for sid in ids if _SESSION_ID_RE.match(sid)]
    items.sort(key=lambda x: str(x.get("updated_at") or ""), reverse=True)
    return items


def patch_session_finding(
    session_id: str,
    surface_target: str,
    finding_id: str,
    status: str,
    *,
    evidence: str = "",
    preserve_evidence: bool = False,
) -> dict[str, Any] | None:
    data = load_session(session_id) or {}
    updated: dict[str, Any] | None = None
    for f in data.get("session_findings") or []:
        if str(f.get("id")) != finding_id:
            continue
        f["status"] = status
        if evidence and not preserve_evidence:
            f["evidence"] = evidence[:2000]
        _apply_normalized_severity(f)
        updated = dict(f)
        break
    if updated:
        save_session(session_id, data)
        if status == "false_positive":
            try:
                from backend.ai.fp_learn import remember_false_positive

                remember_false_positive(updated, target=surface_target or "")
            except Exception:  # noqa: BLE001
                pass
        return {
            **updated,
            "surface_target": updated.get("surface_target") or surface_target or "_session",
        }

    finding = mark_finding_status(
        surface_target,
        finding_id,
        status,
        evidence="" if preserve_evidence else evidence,
    )
    if not finding:
        return None
    _apply_normalized_severity(finding)
    if status == "false_positive":
        try:
            from backend.ai.fp_learn import remember_false_positive

            remember_false_positive(finding, target=surface_target or "")
        except Exception:  # noqa: BLE001
            pass
    touch_session(session_id, surface_target)
    return {**finding, "surface_target": surface_target}


def patch_session_findings_batch(
    session_id: str,
    rows: list[dict[str, Any]],
    *,
    preserve_evidence: bool = True,
) -> int:
    """Aplica vários status numa só gravação (triagem automática)."""
    if not rows:
        return 0
    data = load_session(session_id) or {}
    findings = list(data.get("session_findings") or [])
    by_id = {str(f.get("id")): f for f in findings if f.get("id")}
    applied = 0
    surface_patches: list[tuple[str, str, str]] = []

    for row in rows:
        fid = str(row.get("id") or "")
        status = str(row.get("status") or "")
        if not fid or not status:
            continue
        target = str(row.get("surface_target") or row.get("host") or "_session")
        f = by_id.get(fid)
        if f is not None:
            f["status"] = status
            if not preserve_evidence:
                ev = str(row.get("evidence") or "")
                if ev:
                    f["evidence"] = ev[:2000]
            _apply_normalized_severity(f)
            applied += 1
            if status == "false_positive":
                try:
                    from backend.ai.fp_learn import remember_false_positive

                    remember_false_positive(f, target=target)
                except Exception:  # noqa: BLE001
                    pass
        else:
            surface_patches.append((target, fid, status))

    if applied:
        data["session_findings"] = findings
        save_session(session_id, data)

    for target, fid, status in surface_patches:
        try:
            finding = mark_finding_status(target, fid, status, evidence="")
            if finding:
                _apply_normalized_severity(finding)
                applied += 1
                touch_session(session_id, target)
        except Exception:  # noqa: BLE001
            pass
    return applied


def _apply_normalized_severity(finding: dict[str, Any]) -> None:
    """Garante gravidade coerente com tipo/título (ex.: [high] XSS não fica como info)."""
    try:
        from backend.ai.report_model import enrich_finding

        enriched = enrich_finding(finding)
        for key in (
            "severity",
            "severity_label",
            "kind",
            "kind_label",
            "plain_title",
            "cwe",
            "owasp",
        ):
            if enriched.get(key) not in (None, ""):
                finding[key] = enriched[key]
    except Exception:  # noqa: BLE001
        pass


def merge_session_finding_fields(
    session_id: str, finding_id: str, fields: dict[str, Any]
) -> dict[str, Any] | None:
    """Atualiza campos extras do achado (ex. ai_review) sem mudar o status."""
    fid = str(finding_id or "")
    if not fid or not fields:
        return None
    data = load_session(session_id) or {}
    updated: dict[str, Any] | None = None
    for f in data.get("session_findings") or []:
        if str(f.get("id")) != fid:
            continue
        for key, value in fields.items():
            f[key] = value
        updated = dict(f)
        break
    if updated:
        save_session(session_id, data)
        return updated
    return None


def delete_session_intel(session_id: str) -> bool:
    """Remove índice da conversa e achados vinculados a ela."""
    from backend.database.db import ensure_dashboard_db, session_scope
    from backend.database.models_store import IntelSessionRow

    meta = load_session(session_id)
    path = _session_path(session_id)
    if path and path.is_file():
        try:
            path.unlink()
        except OSError:
            pass

    try:
        ensure_dashboard_db()
        with session_scope() as db:
            db.query(IntelSessionRow).filter(IntelSessionRow.session_id == session_id).delete(
                synchronize_session=False
            )
    except Exception:  # noqa: BLE001
        pass

    removed_any = bool(meta)
    for target in meta.get("targets") or []:
        surface = load_surface(target)
        if not surface:
            continue
        before = len(surface.get("findings") or [])
        kept = [
            f
            for f in (surface.get("findings") or [])
            if str(f.get("chat_session_id") or "") != session_id
        ]
        if len(kept) != before:
            surface["findings"] = kept
            save_surface(target, surface)
            removed_any = True
    return removed_any or True


def collect_session_tool_executions(session_id: str, limit: int = 80) -> list[dict[str, Any]]:
    """Logs de execução desta conversa (para anexo no PDF)."""
    from backend.executor.logs import list_log_ids_for_session, read_execution_log

    rows: list[dict[str, Any]] = []
    for log_id in list_log_ids_for_session(session_id)[:limit]:
        raw = read_execution_log(log_id)
        if not raw:
            continue
        parsed = _parse_execution_log(raw)
        cmd = parsed["command"]
        rows.append(
            {
                "log_id": log_id,
                "command": cmd,
                "stdout": parsed["stdout"][:4000],
                "stderr": parsed["stderr"][:2000],
                "success": True,
                "tool": (cmd.split() or [""])[0].split("/")[-1] if cmd else "",
            }
        )
    return rows
