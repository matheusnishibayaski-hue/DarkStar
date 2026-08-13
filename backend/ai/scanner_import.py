"""Import de scanners externos (Nuclei JSONL, Nessus CSV básico) → surface."""

from __future__ import annotations

import csv
import io
import json
import re
from typing import Any

from backend.ai.fp_learn import is_suppressed
from backend.executor.recon_db import normalize_target
from backend.executor.surface import get_or_create_surface, save_surface

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def _sev(value: str) -> str:
    s = (value or "info").strip().lower()
    if s in {"critical", "high", "medium", "low", "info"}:
        return s
    if s in {"4", "critical"}:
        return "critical"
    if s in {"3", "high"}:
        return "high"
    if s in {"2", "medium"}:
        return "medium"
    if s in {"1", "low"}:
        return "low"
    return "info"


def import_nuclei_jsonl(target: str, content: str) -> dict[str, Any]:
    from backend.ai.nuclei_json import events_to_finding_patches, parse_nuclei_json_lines

    data = get_or_create_surface(target)
    events = parse_nuclei_json_lines(content)
    patches = events_to_finding_patches(events, tool="nuclei-import", command="import")
    added = 0
    skipped_fp = 0
    for patch in patches:
        if is_suppressed(patch):
            skipped_fp += 1
            continue
        patch.setdefault("status", "candidate")
        patch.setdefault("host", normalize_target(target))
        # reuse upsert via save path — append-ish
        from backend.executor.surface import _upsert_finding

        _upsert_finding(data, patch)
        added += 1
    save_surface(target, data)
    return {
        "format": "nuclei_jsonl",
        "target": normalize_target(target),
        "imported": added,
        "skipped_fp_learned": skipped_fp,
        "events": len(events),
    }


def import_nessus_csv(target: str, content: str) -> dict[str, Any]:
    """CSV export típico Nessus: Plugin Name, Severity, CVE, Host, Port…"""
    data = get_or_create_surface(target)
    reader = csv.DictReader(io.StringIO(content))
    if not reader.fieldnames:
        raise ValueError("CSV sem cabeçalho")
    # normaliza keys
    fields = {f.lower().strip(): f for f in reader.fieldnames}

    def col(*names: str) -> str | None:
        for n in names:
            if n in fields:
                return fields[n]
        return None

    c_title = col("plugin name", "name", "title", "plugin")
    c_sev = col("severity", "risk", "risk factor")
    c_cve = col("cve", "cves")
    c_host = col("host", "ip address", "dns name")
    c_port = col("port", "port #")
    if not c_title:
        raise ValueError("CSV Nessus: coluna de título/plugin não encontrada")

    from backend.executor.surface import _upsert_finding

    added = 0
    skipped_fp = 0
    for row in reader:
        title = str(row.get(c_title) or "").strip()
        if not title:
            continue
        sev = _sev(str(row.get(c_sev) or "info") if c_sev else "info")
        cve_raw = str(row.get(c_cve) or "") if c_cve else ""
        m = _CVE_RE.search(cve_raw)
        cve = m.group(0).upper() if m else ""
        host = str(row.get(c_host) or target) if c_host else target
        port = str(row.get(c_port) or "") if c_port else ""
        finding = {
            "title": title[:240],
            "severity": sev,
            "cve": cve,
            "status": "candidate",
            "tool": "nessus-import",
            "host": normalize_target(host),
            "evidence": f"Import Nessus CSV · porta {port}" if port else "Import Nessus CSV",
            "command": "import:nessus_csv",
        }
        if is_suppressed(finding):
            skipped_fp += 1
            continue
        _upsert_finding(data, finding)
        added += 1
        if port.isdigit():
            from backend.executor.surface import _unique_append

            _unique_append(
                data.setdefault("ports", []),
                {
                    "host": normalize_target(host),
                    "port": port,
                    "proto": "tcp",
                },
                key_fn=lambda x: (x.get("host"), x.get("port"), x.get("proto")),
            )

    save_surface(target, data)
    return {
        "format": "nessus_csv",
        "target": normalize_target(target),
        "imported": added,
        "skipped_fp_learned": skipped_fp,
    }


def import_scanner_payload(
    target: str,
    content: str,
    *,
    format: str = "auto",
) -> dict[str, Any]:
    fmt = (format or "auto").strip().lower()
    text = content or ""
    if fmt == "auto":
        stripped = text.lstrip()
        if stripped.startswith("["):
            fmt = "nuclei"
        elif "Plugin Name" in text[:500] or "Risk Factor" in text[:500]:
            fmt = "nessus"
        elif "\n" in text and text.strip().startswith("{"):
            fmt = "nuclei"
        elif stripped.startswith("{"):
            fmt = "nuclei"
        else:
            # tenta nuclei linha a linha
            try:
                for line in text.splitlines()[:3]:
                    if line.strip():
                        json.loads(line)
                        fmt = "nuclei"
                        break
            except json.JSONDecodeError:
                fmt = "nessus"

    if fmt in {"nuclei", "nuclei_jsonl", "jsonl"}:
        return import_nuclei_jsonl(target, text)
    if fmt in {"nessus", "nessus_csv", "csv"}:
        return import_nessus_csv(target, text)
    raise ValueError(f"Formato não suportado: {format}")
