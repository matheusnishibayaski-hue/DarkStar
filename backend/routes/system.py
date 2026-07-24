"""Rotas de sistema: health, tools, models, logs."""

from __future__ import annotations

import subprocess
import sys

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response, StreamingResponse

from backend.config import (
    CHAT_API_TOKEN,
    KALI_CONTAINER,
    TOOL_CATEGORIES,
    UVICORN_HOST,
    UVICORN_PORT,
)
from backend.deps import APP_VERSION
from backend.executor.logs import read_execution_log
from backend.executor.recon_db import get_recon_data, list_recon_summaries
from backend.executor.stream_hub import get_stream_hub
from backend.models_catalog import get_models_catalog
from backend.security.scope import scope_lock_enabled
from backend.tool_catalog import enrich_categories

router = APIRouter(prefix="/api", tags=["system"])


@router.get("/client-config")
def client_config():
    from backend.security.privileges import master_key_configured, privilege_status

    return {
        "version": APP_VERSION,
        "brand": "DarkStar",
        "assistant": "Argus",
        "authRequired": bool(CHAT_API_TOKEN),
        "sessionAuth": bool(CHAT_API_TOKEN),
        "host": UVICORN_HOST,
        "port": UVICORN_PORT,
        "scope_lock_enabled": scope_lock_enabled(),
        "scope_warning": not scope_lock_enabled(),
        "master_key_configured": master_key_configured(),
        **privilege_status(),
    }


@router.get("/health")
def health():
    from backend.config import CHAT_API_TOKEN

    docker_ok = False
    kali_ok = False
    kali_error = ""
    wifi_ok = False
    wifi_interfaces: list[str] = []
    wifi_message = ""

    try:
        proc = subprocess.run(
            ["docker", "ps", "--filter", f"name={KALI_CONTAINER}", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        docker_ok = proc.returncode == 0
        kali_ok = KALI_CONTAINER in proc.stdout
        if docker_ok and not kali_ok:
            kali_error = (
                f"Container '{KALI_CONTAINER}' não está rodando. Execute: start.bat ou ./start.sh"
            )
        elif not docker_ok:
            kali_error = (proc.stderr or "Docker não está disponível.").strip()
    except FileNotFoundError:
        kali_error = "Docker não instalado ou não está no PATH."
    except Exception as e:
        kali_error = str(e)

    if sys.platform == "win32":
        try:
            from backend.executor.wifi_scan import windows_wifi_health

            wifi_ok, wifi_interfaces, wifi_message = windows_wifi_health()
        except Exception as e:
            wifi_message = str(e)
    elif kali_ok:
        try:
            iw = subprocess.run(
                ["docker", "exec", "--user", "root", KALI_CONTAINER, "iw", "dev"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if iw.returncode == 0 and iw.stdout.strip():
                wifi_interfaces = [
                    line.split()[1]
                    for line in iw.stdout.splitlines()
                    if line.strip().startswith("Interface ")
                ]
                wifi_ok = len(wifi_interfaces) > 0
                wifi_message = f"{len(wifi_interfaces)} interface(s): {', '.join(wifi_interfaces)}"
            else:
                wifi_message = "Nenhuma interface wireless no container."
        except Exception as e:
            wifi_message = str(e)

    return {
        "status": "ok",
        "version": APP_VERSION,
        "docker": docker_ok,
        "kali_container": kali_ok,
        "kali_error": kali_error,
        "wifi_ready": wifi_ok,
        "wifi_interfaces": wifi_interfaces,
        "wifi_message": wifi_message,
        "auth_required": bool(CHAT_API_TOKEN),
        "scope_lock_enabled": scope_lock_enabled(),
        "scope_warning": not scope_lock_enabled(),
    }


@router.get("/metrics")
def api_metrics():
    """Métricas leves em memória (protegidas por auth quando CHAT_API_TOKEN está ativo)."""
    from backend.observability import get_metrics

    return get_metrics()


@router.get("/tools")
def api_tools(offensive: bool = False):
    if offensive:
        from backend.config_tools import ALLOWED_TOOLS
        from backend.tool_catalog import get_tool_info

        tools = []
        for tid in sorted(ALLOWED_TOOLS):
            meta = get_tool_info(tid)
            tools.append(
                {
                    "id": tid,
                    "summary": meta["summary"],
                    "example": meta["example"],
                }
            )
        return {"categories": [{"id": "all", "name": "Permitidas no servidor", "tools": tools}]}
    return {"categories": enrich_categories(TOOL_CATEGORIES)}


@router.get("/scan-profiles")
def api_scan_profiles(offensive: bool = False):
    from backend.ai.scan_profiles import profile_catalog

    return profile_catalog(offensive=offensive)


@router.get("/models")
def api_models():
    return get_models_catalog()


@router.get("/recon")
def api_recon_list():
    return {"targets": list_recon_summaries()}


@router.delete("/recon/{target}")
def api_recon_delete(target: str):
    from backend.executor.data_cleanup import delete_recon

    if not delete_recon(target):
        raise HTTPException(status_code=404, detail="Nenhum recon salvo para este alvo.")
    return {"deleted": True, "target": target}


@router.get("/recon/{target}")
def api_recon_detail(target: str):
    if not target or len(target) > 128 or ".." in target:
        raise HTTPException(status_code=400, detail="Alvo inválido.")
    from backend.executor.surface import load_surface, repair_surface_from_stored_output
    from backend.executor.recon_db import sync_recon_counts_from_surface

    try:
        repair_surface_from_stored_output(target)
    except Exception:
        pass
    surface = load_surface(target) or {}
    data = get_recon_data(target)
    if surface:
        sync_recon_counts_from_surface(target, surface)
        data = get_recon_data(target) or data or {"target": target}
    if not data and not surface:
        raise HTTPException(status_code=404, detail="Nenhum recon salvo para este alvo.")
    if not data:
        data = {"target": target}

    findings = surface.get("findings") or []
    data = dict(data)
    data["findings"] = findings
    data["findings_summary"] = {
        "total": len(findings),
        "confirmed": sum(1 for f in findings if f.get("status") == "confirmed"),
        "candidates": sum(1 for f in findings if f.get("status") == "candidate"),
        "inconclusive": sum(1 for f in findings if f.get("status") == "inconclusive"),
    }
    data["surface_ports"] = surface.get("ports") or []
    data["tools_run"] = surface.get("tools_run") or []
    data["commands_run"] = surface.get("commands_run") or 0
    data["phase"] = surface.get("phase")
    data["has_surface"] = bool(surface)
    # Preferir portas limpas do surface
    if surface.get("ports"):
        data["open_ports"] = [
            f"{p.get('port')}/tcp open {p.get('service') or p.get('product') or ''}".strip()
            for p in surface["ports"]
            if p.get("port")
        ]
    if findings and not data.get("vulnerabilities"):
        data["vulnerabilities"] = [
            f"[{f.get('severity') or 'info'}] {f.get('title') or ''}" for f in findings
        ]
    return data


@router.get("/logs/stream/{execution_id}")
def api_log_stream(execution_id: str):
    if not execution_id.isalnum():
        raise HTTPException(status_code=400, detail="ID de execução inválido.")
    if not get_stream_hub().get(execution_id):
        raise HTTPException(status_code=404, detail="Execução não encontrada ou já finalizada.")

    def event_generator():
        yield from get_stream_hub().subscribe_sse(execution_id)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.delete("/logs/{log_id}")
def api_log_delete(log_id: str):
    from backend.executor.data_cleanup import delete_execution_log

    result = delete_execution_log(log_id)
    if not result.get("ok"):
        raise HTTPException(status_code=404, detail="Log não encontrado.")
    return {"deleted": True, "log_id": log_id, **result}


@router.get("/logs/{log_id}")
def api_log(log_id: str):
    content = read_execution_log(log_id)
    if content is None:
        raise HTTPException(status_code=404, detail="Log não encontrado.")
    return Response(content=content, media_type="text/plain; charset=utf-8")
