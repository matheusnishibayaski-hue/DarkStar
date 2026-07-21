"""Rotas do modo Auto-Pilot."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from backend.ai.autopilot import run_autonomous, run_autonomous_stream
from backend.ai.sse import format_sse
from backend.deps import tool_execution_response
from backend.schemas import AutonomousRequest, AutonomousResponseModel
from backend.security.scope import validate_autonomous_target

router = APIRouter(prefix="/api", tags=["autonomous"])


def _ensure_scope(target: str) -> None:
    ok, err = validate_autonomous_target(target)
    if not ok:
        raise HTTPException(status_code=403, detail=err)


@router.post("/autonomous/stream")
def api_autonomous_stream(req: AutonomousRequest):
    _ensure_scope(req.target)

    def event_generator():
        try:
            yield from run_autonomous_stream(
                req.target,
                req.objective,
                model=req.model or None,
                fallback_model=req.fallback_model or None,
                mission_id=req.mission_id or None,
                risk_profile=req.risk_profile or None,
                chat_session_id=req.chat_session_id or None,
                scan_profile=req.scan_profile or None,
                custom_tools=req.custom_tools or None,
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


@router.post("/autonomous", response_model=AutonomousResponseModel)
def api_autonomous(req: AutonomousRequest):
    _ensure_scope(req.target)
    try:
        result = run_autonomous(
            req.target,
            req.objective,
            model=req.model or None,
            fallback_model=req.fallback_model or None,
            mission_id=req.mission_id or None,
            risk_profile=req.risk_profile or None,
            chat_session_id=req.chat_session_id or None,
            scan_profile=req.scan_profile or None,
            custom_tools=req.custom_tools or None,
        )
        return AutonomousResponseModel(
            message=result.message,
            tool_executions=[tool_execution_response(e) for e in result.tool_executions],
            report=result.report,
            objective_met=result.objective_met,
            rounds=result.rounds,
            stopped_reason=result.stopped_reason,
            tools_executed=result.tools_executed,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
