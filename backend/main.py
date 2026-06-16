import subprocess
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent.parent

from backend.ai.agent import chat
from backend.config import KALI_CONTAINER, TOOL_CATEGORIES

FRONTEND_DIR = BASE_DIR / "frontend"

app = FastAPI(title="Chat IA Kali", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    history: list[ChatMessage] = Field(default_factory=list)
    preferred_tool: str = Field(default="auto", max_length=64)


class ToolExecutionResponse(BaseModel):
    command: str
    reason: str
    stdout: str
    stderr: str
    exit_code: int
    success: bool
    blocked: bool


class ChatResponseModel(BaseModel):
    message: str
    tool_executions: list[ToolExecutionResponse]


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
        "docker": docker_ok,
        "kali_container": kali_ok,
        "kali_error": kali_error,
        "wifi_ready": wifi_ok,
        "wifi_interfaces": wifi_interfaces,
        "wifi_message": wifi_message,
    }


@app.get("/api/tools")
def api_tools():
    return {"categories": TOOL_CATEGORIES}


@app.post("/api/chat", response_model=ChatResponseModel)
def api_chat(req: ChatRequest):
    try:
        history = [{"role": m.role, "content": m.content} for m in req.history]
        result = chat(history, req.message, preferred_tool=req.preferred_tool)
        return ChatResponseModel(
            message=result.message,
            tool_executions=[
                ToolExecutionResponse(
                    command=e.command,
                    reason=e.reason,
                    stdout=e.stdout,
                    stderr=e.stderr,
                    exit_code=e.exit_code,
                    success=e.success,
                    blocked=e.blocked,
                )
                for e in result.tool_executions
            ],
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
