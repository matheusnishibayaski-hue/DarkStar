"""Modelos Pydantic compartilhados da API."""

from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    history: list[ChatMessage] = Field(default_factory=list)
    preferred_tool: str = Field(default="auto", max_length=64)
    model: str = Field(default="", max_length=128)
    fallback_model: str = Field(default="", max_length=128)
    mission_id: str = Field(default="", max_length=64)
    chat_session_id: str = Field(default="", max_length=128)


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
    surface_target: str = Field(
        default="",
        max_length=253,
        description="Alvo do Attack Surface — usa findings confirmados no relatório comercial",
    )
    chat_session_id: str = Field(
        default="",
        max_length=128,
        description="Conversa — agrega achados de todos os alvos testados neste chat",
    )


class AutonomousRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=253)
    objective: str = Field(..., min_length=3, max_length=2000)
    model: str = Field(default="", max_length=128)
    fallback_model: str = Field(default="", max_length=128)
    mission_id: str = Field(default="", max_length=64)
    chat_session_id: str = Field(default="", max_length=128)
    risk_profile: str = Field(
        default="",
        max_length=32,
        description="passive | safe-active | full (vazio = RISK_PROFILE do .env)",
    )
    scan_profile: str = Field(
        default="basic",
        max_length=32,
        description="basic | intermediate | full | custom",
    )
    custom_tools: list[str] = Field(default_factory=list, max_length=200)


class LoginRequest(BaseModel):
    token: str = Field(..., min_length=1, max_length=256)


class PlaybookRunRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=253)
    mission_id: str = Field(default="", max_length=64)
    chat_session_id: str = Field(default="", max_length=128)


class SessionLogsDeleteRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=128)
    log_ids: list[str] = Field(default_factory=list, max_length=200)


class AutonomousResponseModel(BaseModel):
    message: str
    tool_executions: list[ToolExecutionResponse]
    report: str
    objective_met: bool
    rounds: int
    stopped_reason: str
    tools_executed: int
