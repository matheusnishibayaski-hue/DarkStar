"""Rotas de autenticação e cancelamento de missões."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from backend.config import CHAT_API_TOKEN, SESSION_TTL_HOURS
from backend.deps import valid_mission_id
from backend.schemas import LoginRequest, MasterKeyRequest
from backend.security.missions import get_mission_registry
from backend.security.privileges import (
    PRIVILEGE_COOKIE,
    create_privilege_token,
    master_key_configured,
    privilege_status,
    revoke_privilege_token,
    verify_master_key,
)
from backend.security.sessions import SESSION_COOKIE_NAME, get_session_store

router = APIRouter(prefix="/api", tags=["auth"])


@router.get("/auth/session")
def auth_session(request: Request):
    if not CHAT_API_TOKEN:
        return {
            "authenticated": True,
            "sessionAuth": False,
            **privilege_status(),
        }
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    return {
        "authenticated": get_session_store(SESSION_TTL_HOURS * 3600).validate(session_id),
        "sessionAuth": True,
        **privilege_status(),
    }


@router.get("/auth/privilege")
def auth_privilege():
    return privilege_status()


@router.post("/auth/master-key")
def auth_master_key(req: MasterKeyRequest):
    if not master_key_configured():
        raise HTTPException(
            status_code=503,
            detail="MASTER_KEY não configurada no servidor (.env).",
        )
    if not verify_master_key(req.key):
        raise HTTPException(status_code=401, detail="Master key inválida.")

    token = create_privilege_token()
    response = JSONResponse(
        {
            "ok": True,
            "elevated": True,
            "profile": "full",
            "profile_label": "full (master key)",
        }
    )
    response.set_cookie(
        key=PRIVILEGE_COOKIE,
        value=token,
        httponly=True,
        samesite="lax",
        max_age=SESSION_TTL_HOURS * 3600,
        path="/",
    )
    return response


@router.post("/auth/master-key/lock")
def auth_master_key_lock(request: Request):
    token = request.cookies.get(PRIVILEGE_COOKIE)
    revoke_privilege_token(token)
    response = JSONResponse(
        {
            "ok": True,
            "elevated": False,
            "profile": "B",
            "profile_label": "B (restrito)",
        }
    )
    response.delete_cookie(PRIVILEGE_COOKIE, path="/")
    return response


@router.post("/auth/login")
def auth_login(req: LoginRequest):
    if not CHAT_API_TOKEN:
        return {"ok": True, "message": "Auth desabilitada."}
    if req.token.strip() != CHAT_API_TOKEN:
        raise HTTPException(status_code=401, detail="Token inválido.")

    session_id = get_session_store(SESSION_TTL_HOURS * 3600).create()
    response = JSONResponse({"ok": True})
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        samesite="lax",
        max_age=SESSION_TTL_HOURS * 3600,
        path="/",
    )
    return response


@router.post("/auth/logout")
def auth_logout(request: Request):
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    get_session_store(SESSION_TTL_HOURS * 3600).revoke(session_id)
    token = request.cookies.get(PRIVILEGE_COOKIE)
    revoke_privilege_token(token)
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    response.delete_cookie(PRIVILEGE_COOKIE, path="/")
    return response


@router.post("/missions/{mission_id}/cancel")
def cancel_mission(mission_id: str):
    if not valid_mission_id(mission_id):
        raise HTTPException(status_code=400, detail="ID de missão inválido.")
    if not get_mission_registry().cancel(mission_id):
        raise HTTPException(status_code=404, detail="Missão não encontrada ou já encerrada.")
    return {"ok": True, "mission_id": mission_id}
