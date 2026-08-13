"""Rotas de chat e relatórios."""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response, StreamingResponse

from backend.ai.agent import chat, chat_stream
from backend.ai.pdf_report import generate_report_pdf
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
                chat_session_id=req.chat_session_id or None,
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
            chat_session_id=req.chat_session_id or None,
        )
        return ChatResponseModel(
            message=result.message,
            tool_executions=[tool_execution_response(e) for e in result.tool_executions],
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/generate-report/preview")
def api_generate_report_preview(req: ReportRequest):
    """HTML da pré-visualização ao vivo (mesmo conteúdo-base do PDF)."""
    try:
        from backend.ai.live_report import generate_live_report_html

        history = [{"role": m.role, "content": m.content} for m in req.history]
        executions = [e.model_dump() for e in req.tool_executions]
        html_doc = generate_live_report_html(
            history=history,
            tool_executions=executions,
            session_id=(req.chat_session_id or "").strip(),
            title=req.title or "Relatório de Pentest",
        )
        return Response(content=html_doc, media_type="text/html; charset=utf-8")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/generate-report")
def api_generate_report(req: ReportRequest):
    try:
        history = [{"role": m.role, "content": m.content} for m in req.history]
        executions = [e.model_dump() for e in req.tool_executions]
        session_id = (req.chat_session_id or "").strip()
        target = (req.surface_target or "").strip()

        if session_id:
            raw = generate_report_pdf(
                session_id=session_id,
                title=req.title,
                tool_executions=executions or None,
                history=history,
            )
        else:
            if not target:
                from backend.executor.recon_db import extract_targets, is_recon_target

                texts = [m.content for m in req.history] + [
                    e.command for e in req.tool_executions
                ]
                found = [t for t in extract_targets(*texts) if is_recon_target(t)]
                target = found[0] if found else ""

            raw = generate_report_pdf(
                surface_target=target or None,
                title=req.title,
                tool_executions=executions,
            )
        filename = "relatorio-pentest.pdf"
        return Response(
            content=raw,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
