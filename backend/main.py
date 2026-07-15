import json
import subprocess
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent.parent

from backend.ai.agent import chat, chat_stream, generate_report
from backend.ai.autopilot import run_autonomous, run_autonomous_stream
from backend.config import (
    CHAT_API_TOKEN,
    CORS_ORIGINS,
    KALI_CONTAINER,
    TOOL_CATEGORIES,
    UVICORN_HOST,
    UVICORN_PORT,
)
from backend.tool_catalog import enrich_categories
from backend.models_catalog import get_models_catalog
from backend.ai.sse import format_sse
from backend.executor.logs import read_execution_log
from backend.executor.stream_hub import get_stream_hub

FRONTEND_DIR = BASE_DIR / "frontend"

app = FastAPI(title="Chat IA Kali", version="3.0.0")

_cors_allow_all = "*" in CORS_ORIGINS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if _cors_allow_all else CORS_ORIGINS,
    allow_credentials=not _cors_allow_all,
    allow_methods=["*"],
    allow_headers=["*"],
)


PUBLIC_API_PATHS = frozenset({"/api/health", "/api/client-config"})


@app.middleware("http")
async def api_token_guard(request: Request, call_next):
    if not CHAT_API_TOKEN:
        return await call_next(request)

    path = request.url.path
    if not path.startswith("/api/") or path in PUBLIC_API_PATHS:
        return await call_next(request)

    token = request.headers.get("X-Chat-Token") or request.query_params.get("token")
    if token != CHAT_API_TOKEN:
        return JSONResponse(status_code=401, content={"detail": "Token de API inválido ou ausente."})

    return await call_next(request)


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    history: list[ChatMessage] = Field(default_factory=list)
    preferred_tool: str = Field(default="auto", max_length=64)
    model: str = Field(default="", max_length=128)
    fallback_model: str = Field(default="", max_length=128)


class ToolExecutionResponse(BaseModel):
    command: str
    reason: str
    stdout: str
    stderr: str
    exit_code: int
    success: bool
    blocked: bool
    log_file_id: str = ""
    tool: str = ""


class ChatResponseModel(BaseModel):
    message: str
    tool_executions: list[ToolExecutionResponse]


class ReportRequest(BaseModel):
    history: list[ChatMessage] = Field(default_factory=list)
    tool_executions: list[ToolExecutionResponse] = Field(default_factory=list)
    title: str = Field(default="Relatório de Pentest", max_length=200)


class AutonomousRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=253)
    objective: str = Field(..., min_length=3, max_length=2000)
    model: str = Field(default="", max_length=128)
    fallback_model: str = Field(default="", max_length=128)


class AutonomousResponseModel(BaseModel):
    message: str
    tool_executions: list[ToolExecutionResponse]
    report: str
    objective_met: bool
    rounds: int
    stopped_reason: str
    tools_executed: int


def _tool_execution_response(e) -> ToolExecutionResponse:
    return ToolExecutionResponse(
        command=e.command,
        reason=e.reason,
        stdout=e.stdout,
        stderr=e.stderr,
        exit_code=e.exit_code,
        success=e.success,
        blocked=e.blocked,
        log_file_id=getattr(e, "log_file_id", "") or "",
        tool=getattr(e, "tool", "") or "",
    )


@app.get("/api/client-config")
def client_config():
    return {
        "version": "3.0.0",
        "authRequired": bool(CHAT_API_TOKEN),
        "host": UVICORN_HOST,
        "port": UVICORN_PORT,
    }


@app.get("/api/health")
def health():
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
            kali_error = f"Container '{KALI_CONTAINER}' não está rodando. Execute: start.bat"
        elif not docker_ok:
            kali_error = (proc.stderr or "Docker não está disponível. Inicie o Docker Desktop.").strip()
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
        "version": "3.0.0",
        "docker": docker_ok,
        "kali_container": kali_ok,
        "kali_error": kali_error,
        "wifi_ready": wifi_ok,
        "wifi_interfaces": wifi_interfaces,
        "wifi_message": wifi_message,
    }


@app.get("/api/tools")
def api_tools():
    return {"categories": enrich_categories(TOOL_CATEGORIES)}


@app.get("/api/models")
def api_models():
    return get_models_catalog()


@app.get("/api/logs/stream/{execution_id}")
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


@app.get("/api/logs/{log_id}")
def api_log(log_id: str):
    content = read_execution_log(log_id)
    if content is None:
        raise HTTPException(status_code=404, detail="Log não encontrado.")
    return Response(content=content, media_type="text/plain; charset=utf-8")


@app.post("/api/chat/stream")
def api_chat_stream(req: ChatRequest):
    history = [{"role": m.role, "content": m.content} for m in req.history]

    def event_generator():
        try:
            yield from chat_stream(
                history,
                req.message,
                preferred_tool=req.preferred_tool,
                model=req.model or None,
                fallback_model=req.fallback_model or None,
            )
        except Exception as e:
            yield f"event: error\ndata: {{\"detail\": {json.dumps(str(e))}}}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/chat", response_model=ChatResponseModel)
def api_chat(req: ChatRequest):
    try:
        history = [{"role": m.role, "content": m.content} for m in req.history]
        result = chat(
            history,
            req.message,
            preferred_tool=req.preferred_tool,
            model=req.model or None,
            fallback_model=req.fallback_model or None,
        )
        return ChatResponseModel(
            message=result.message,
            tool_executions=[_tool_execution_response(e) for e in result.tool_executions],
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/autonomous/stream")
def api_autonomous_stream(req: AutonomousRequest):
    def event_generator():
        try:
            yield from run_autonomous_stream(
                req.target,
                req.objective,
                model=req.model or None,
                fallback_model=req.fallback_model or None,
            )
        except Exception as e:
            yield format_sse("error", {"detail": str(e)})

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/autonomous", response_model=AutonomousResponseModel)
def api_autonomous(req: AutonomousRequest):
    try:
        result = run_autonomous(
            req.target,
            req.objective,
            model=req.model or None,
            fallback_model=req.fallback_model or None,
        )
        return AutonomousResponseModel(
            message=result.message,
            tool_executions=[_tool_execution_response(e) for e in result.tool_executions],
            report=result.report,
            objective_met=result.objective_met,
            rounds=result.rounds,
            stopped_reason=result.stopped_reason,
            tools_executed=result.tools_executed,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/generate-report")
def api_generate_report(req: ReportRequest):
    try:
        history = [{"role": m.role, "content": m.content} for m in req.history]
        executions = [e.model_dump() for e in req.tool_executions]
        markdown = generate_report(history, executions, title=req.title)
        filename = "relatorio-pentest.md"
        return Response(
            content=markdown,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
        '<rect width="32" height="32" rx="4" fill="#0d1117"/>'
        '<text x="16" y="22" text-anchor="middle" font-family="monospace" '
        'font-size="14" fill="#3fb950">$</text></svg>'
    )
    return Response(content=svg, media_type="image/svg+xml")


@app.get("/")
def index():
    return FileResponse(FRONTEND_DIR / "index.html")


app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
