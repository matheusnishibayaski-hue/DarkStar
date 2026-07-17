"""Rotas de chat e relatórios."""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response, StreamingResponse

from backend.ai.agent import chat, chat_stream, generate_report
from backend.deps import tool_execution_response
from backend.schemas import ChatRequest, ChatResponseModel, ReportRequest

router = APIRouter(prefix="/api", tags=["chat"])


@router.post("/chat/stream")
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
                mission_id=req.mission_id or None,
            )
        except Exception as e:
            yield f'event: error\ndata: {{"detail": {json.dumps(str(e))}}}\n\n'

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/chat", response_model=ChatResponseModel)
def api_chat(req: ChatRequest):
    try:
        history = [{"role": m.role, "content": m.content} for m in req.history]
        result = chat(
            history,
            req.message,
            preferred_tool=req.preferred_tool,
            model=req.model or None,
            fallback_model=req.fallback_model or None,
            mission_id=req.mission_id or None,
        )
        return ChatResponseModel(
            message=result.message,
            tool_executions=[tool_execution_response(e) for e in result.tool_executions],
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/generate-report")
def api_generate_report(req: ReportRequest):
    try:
        history = [{"role": m.role, "content": m.content} for m in req.history]
        executions = [e.model_dump() for e in req.tool_executions]
        target = (req.surface_target or "").strip()
        if not target:
            # Inferir alvo a partir do histórico / executions
            from backend.executor.recon_db import extract_targets, is_recon_target

            texts = [m.content for m in req.history] + [
                e.command for e in req.tool_executions
            ]
            found = [t for t in extract_targets(*texts) if is_recon_target(t)]
            target = found[0] if found else ""
        markdown = generate_report(
            history,
            executions,
            title=req.title,
            surface_target=target or None,
        )
        filename = "relatorio-pentest.md"
        return Response(
            content=markdown,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
