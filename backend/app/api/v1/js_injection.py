from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Any, Dict, Optional

from backend.js_injection.service import JsInjectionConfig, JsInjectionManager, JsInjectionDependencyError

router = APIRouter()


class JsInjectionStartRequest(BaseModel):
    endpoint: str
    target_url_contains: Optional[str] = None
    sample_rate: float = 0.2
    capture_stack: bool = True
    max_stack_lines: int = 25
    max_body_length: int = 1200
    enable_ws_messages: bool = False
    proxy_session_id: Optional[str] = None


@router.get("/sessions")
async def list_js_injection_sessions():
    manager = JsInjectionManager.get_instance()
    sessions = await manager.list_sessions()
    return {"sessions": sessions}


@router.post("/start")
async def start_js_injection(req: JsInjectionStartRequest):
    # 默认绑定当前 proxy session，便于联动/落盘
    proxy_session_id = req.proxy_session_id
    if not proxy_session_id:
        try:
            from backend.proxy.service_manager import ProxyServiceManager

            proxy_session_id = ProxyServiceManager.get_instance().get_proxy_session_id()
        except Exception:
            proxy_session_id = None

    config = JsInjectionConfig(
        endpoint=req.endpoint,
        target_url_contains=req.target_url_contains,
        sample_rate=req.sample_rate,
        capture_stack=req.capture_stack,
        max_stack_lines=req.max_stack_lines,
        max_body_length=req.max_body_length,
        enable_ws_messages=req.enable_ws_messages,
        proxy_session_id=proxy_session_id,
    )

    manager = JsInjectionManager.get_instance()
    try:
        result = await manager.start_session(config)
        return {**result, "proxy_session_id": proxy_session_id}
    except JsInjectionDependencyError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/stop/{session_id}")
async def stop_js_injection(session_id: str):
    manager = JsInjectionManager.get_instance()
    result = await manager.stop_session(session_id)
    return result


@router.get("/sessions/{session_id}")
async def get_js_injection_session(session_id: str):
    manager = JsInjectionManager.get_instance()
    session = await manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="session_not_found")
    # rely on manager serialization
    sessions = await manager.list_sessions()
    for s in sessions:
        if s.get("session_id") == session_id:
            return s
    return {"session_id": session_id, "status": session.status}


@router.get("/sessions/{session_id}/events")
async def list_js_injection_events(
    session_id: str,
    limit: int = 200,
    offset: int = 0,
    correlated_request_id: Optional[str] = None,
):
    manager = JsInjectionManager.get_instance()
    session = await manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="session_not_found")

    events = list(session.events)
    if correlated_request_id:
        events = [e for e in events if str(e.get("correlated_request_id") or "") == str(correlated_request_id)]

    total = len(events)
    sliced = events[int(offset) : int(offset) + int(limit)]
    return {"session_id": session_id, "events": sliced, "total": total, "limit": limit, "offset": offset}
