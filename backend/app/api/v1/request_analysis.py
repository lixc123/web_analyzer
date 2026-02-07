"""
HTTP 请求分析和重放 API 路由（request-analysis）

当前实现以「Proxy 捕获」作为真实数据源：
- start-recording/stop-recording 通过时间窗口对 proxy 请求做快照（不再返回 mock 调用栈）。
- /requests 返回快照（录制中则返回实时窗口内请求）。
- /replay-request 支持按 request_id 重放（可修改 headers/body）。

说明：Proxy 本身无法可靠获得“JS 调用栈”；如需调用栈请配合 JS 注入（js-injection）或 Crawler 录制。
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()
logger = logging.getLogger(__name__)

# -----------------------------
# In-memory recorder state
# -----------------------------

_state_lock = threading.Lock()
_recording_active: bool = False
_recording_id: Optional[str] = None
_recording_started_at: Optional[float] = None  # seconds (epoch)
_recording_ended_at: Optional[float] = None  # seconds (epoch)
_snapshot_requests: List[Dict[str, Any]] = []
_snapshot_by_id: Dict[str, Dict[str, Any]] = {}


class ReplayRequestByIdModel(BaseModel):
    request_id: str
    modify_headers: Optional[Any] = None  # dict or JSON string
    modify_body: Optional[Any] = None  # any; string will be sent as-is unless valid JSON
    follow_redirects: Optional[bool] = True
    verify_ssl: Optional[bool] = True


def _now_s() -> float:
    return time.time()


def _get_proxy_storage_requests(*, limit: int = 10000) -> List[Dict[str, Any]]:
    """Fetch a copy of proxy-captured requests from in-memory storage (best-effort)."""
    try:
        from backend.proxy.service_manager import ProxyServiceManager  # local import to avoid hard cycles

        manager = ProxyServiceManager.get_instance()
        storage = manager.get_storage()
        if storage is None:
            return []

        max_limit = int(getattr(storage, "MAX_REQUESTS", 10000) or 10000)
        want = min(int(limit or 0) if limit else max_limit, max_limit)
        page = storage.get_requests_page(limit=want, offset=0)
        items = page.get("requests") if isinstance(page, dict) else None
        return list(items) if isinstance(items, list) else []
    except Exception as e:
        logger.warning(f"获取 proxy requests 失败: {e}")
        return []


def _normalize_timestamp_s(value: Any) -> float:
    try:
        return float(value)
    except Exception:
        return 0.0


def _time_window(
    requests: List[Dict[str, Any]],
    *,
    start_s: Optional[float],
    end_s: Optional[float],
) -> List[Dict[str, Any]]:
    if start_s is None and end_s is None:
        return list(requests)

    start_s = float(start_s or 0.0)
    end_s = float(end_s) if end_s is not None else None

    filtered: List[Dict[str, Any]] = []
    for r in requests:
        ts = _normalize_timestamp_s(r.get("timestamp"))
        if ts <= 0:
            continue
        if ts < start_s:
            continue
        if end_s is not None and ts > end_s:
            continue
        filtered.append(r)
    return filtered


def _convert_proxy_request_to_recorded(r: Dict[str, Any]) -> Dict[str, Any]:
    """Convert internal UnifiedRequest(dict) into the frontend-friendly shape."""
    rid = str(r.get("id") or "")
    if not rid:
        rid = str(uuid.uuid4())

    method = str(r.get("method") or "GET").upper()
    url = str(r.get("url") or "")
    headers = r.get("headers") if isinstance(r.get("headers"), dict) else {}

    ts_s = _normalize_timestamp_s(r.get("timestamp")) or _now_s()
    timestamp = int(ts_s)

    body = r.get("body")
    if body is None:
        body = ""

    status_code = r.get("status_code")
    response_headers = r.get("response_headers") if isinstance(r.get("response_headers"), dict) else {}
    response_body = r.get("response_body")
    if response_body is None:
        response_body = ""

    response_obj = None
    if status_code is not None or response_headers or response_body:
        try:
            status_int = int(status_code) if status_code is not None else 0
        except Exception:
            status_int = 0
        response_obj = {
            "status": status_int,
            "headers": response_headers,
            "body": str(response_body),
        }

    duration_ms = 0
    try:
        rt = r.get("response_time")
        if rt is not None:
            duration_ms = int(float(rt) * 1000)
    except Exception:
        duration_ms = 0

    # call_stack: only when the source provides it (proxy default is none)
    call_stack = r.get("call_stack")
    if not isinstance(call_stack, list):
        call_stack = []

    recorded: Dict[str, Any] = {
        "id": rid,
        "method": method,
        "url": url,
        "headers": headers,
        "body": body,
        "response": response_obj,
        "timestamp": timestamp,
        "call_stack": call_stack,
        "duration_ms": duration_ms,
    }

    # keep artifact references for large bodies (optional, frontend may ignore)
    if r.get("body_artifact") is not None:
        recorded["body_artifact"] = r.get("body_artifact")
    if r.get("response_body_artifact") is not None:
        recorded["response_body_artifact"] = r.get("response_body_artifact")

    return recorded


def _get_live_view() -> Tuple[List[Dict[str, Any]], bool]:
    with _state_lock:
        active = _recording_active
        start_s = _recording_started_at

    if not active:
        return ([], False)

    end_s = _now_s()
    proxy_requests = _get_proxy_storage_requests(limit=10000)
    windowed = _time_window(proxy_requests, start_s=start_s, end_s=end_s)
    return ([_convert_proxy_request_to_recorded(r) for r in windowed], True)


def _get_snapshot_view() -> List[Dict[str, Any]]:
    with _state_lock:
        return list(_snapshot_requests)


def _parse_status_range(status_range: str) -> Optional[Tuple[int, int]]:
    raw = str(status_range or "").strip()
    if not raw or raw == "all":
        return None
    parts = raw.split("-", 1)
    if len(parts) != 2:
        return None
    try:
        start = int(parts[0])
        end = int(parts[1])
    except Exception:
        return None
    return (start, end) if start <= end else (end, start)


def _normalize_modify_headers(value: Any) -> Dict[str, str]:
    if value is None or value == "":
        return {}
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"modify_headers 解析失败: {e}") from e
        if not isinstance(parsed, dict):
            raise HTTPException(status_code=400, detail="modify_headers 必须是 JSON 对象")
        return {str(k): str(v) for k, v in parsed.items()}
    raise HTTPException(status_code=400, detail="modify_headers 必须是对象或 JSON 字符串")


def _normalize_modify_body(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        # If it's valid JSON, send as JSON; otherwise send as raw string.
        try:
            return json.loads(text)
        except Exception:
            return value
    return value


def _strip_hop_by_hop_headers(headers: Dict[str, str]) -> Dict[str, str]:
    hop_by_hop = {
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "host",
        "content-length",
        "accept-encoding",
    }
    cleaned: Dict[str, str] = {}
    for k, v in (headers or {}).items():
        if str(k).lower() in hop_by_hop:
            continue
        cleaned[str(k)] = str(v)
    return cleaned


def _compute_statistics(requests: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(requests)
    if total <= 0:
        return {
            "total_requests": 0,
            "api_requests": 0,
            "success_rate": 0,
            "avg_response_time": 0,
        }

    api = 0
    ok = 0
    durations: List[int] = []
    for r in requests:
        url = str(r.get("url") or "").lower()
        method = str(r.get("method") or "").upper()
        resp = r.get("response") if isinstance(r.get("response"), dict) else None
        status = int(resp.get("status") or 0) if resp else 0
        if 200 <= status < 300:
            ok += 1

        # best-effort "API request" heuristic
        if "/api" in url or "/graphql" in url or method in {"POST", "PUT", "PATCH", "DELETE"}:
            api += 1

        try:
            d = int(r.get("duration_ms") or 0)
            if d > 0:
                durations.append(d)
        except Exception:
            pass

    success_rate = round(ok / total * 100, 2)
    avg_ms = int(sum(durations) / len(durations)) if durations else 0
    return {
        "total_requests": total,
        "api_requests": api,
        "success_rate": success_rate,
        "avg_response_time": avg_ms,
    }


@router.get("/requests")
async def get_recorded_requests(
    method: Optional[str] = None,
    status_range: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
):
    """获取录制的HTTP请求列表（录制中返回实时窗口；停止后返回快照）。"""
    try:
        live, is_live = _get_live_view()
        data = live if is_live else _get_snapshot_view()

        # 方法筛选
        if method and method != "all":
            m = str(method).upper()
            data = [r for r in data if str(r.get("method") or "").upper() == m]

        # 状态码筛选
        rng = _parse_status_range(status_range or "")
        if rng:
            start, end = rng

            def _match_status(rec: Dict[str, Any]) -> bool:
                resp = rec.get("response") if isinstance(rec.get("response"), dict) else None
                if not resp:
                    return False
                try:
                    s = int(resp.get("status") or 0)
                except Exception:
                    return False
                return start <= s <= end

            data = [r for r in data if _match_status(r)]

        # 搜索筛选
        if search:
            q = str(search).lower()
            data = [r for r in data if q in str(r.get("url") or "").lower() or q in str(r.get("method") or "").lower()]

        total = len(data)
        sliced = data[int(offset) : int(offset) + int(limit)]

        with _state_lock:
            recording = _recording_active
            rid = _recording_id

        return {
            "requests": sliced,
            "total": total,
            "limit": limit,
            "offset": offset,
            "recording": recording,
            "recording_id": rid,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取请求列表失败: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/request/{request_id}")
async def get_request_details(request_id: str):
    """获取请求详细信息（返回单条记录本身，适配前端）。"""
    rid = str(request_id or "").strip()
    if not rid:
        raise HTTPException(status_code=400, detail="request_id 不能为空")

    with _state_lock:
        hit = _snapshot_by_id.get(rid)
    if hit:
        return hit

    # best-effort: try find in proxy storage by id
    try:
        from backend.proxy.service_manager import ProxyServiceManager

        manager = ProxyServiceManager.get_instance()
        storage = manager.get_storage()
        raw = storage.get_request_by_id(rid) if storage else None
        if raw and isinstance(raw, dict):
            return _convert_proxy_request_to_recorded(raw)
    except Exception:
        pass

    raise HTTPException(status_code=404, detail=f"请求记录不存在: {rid}")


@router.get("/request/{request_id}/call-stack")
async def get_request_call_stack(request_id: str):
    """获取请求的调用栈信息（best-effort，来源提供才有）。"""
    rec = await get_request_details(request_id)
    call_stack = rec.get("call_stack") if isinstance(rec, dict) else None
    if not isinstance(call_stack, list):
        call_stack = []
    return {
        "request_id": request_id,
        "callStack": call_stack,
        "analysis": {
            "total_frames": len(call_stack),
        },
    }


@router.post("/start-recording")
async def start_request_recording():
    """开始 HTTP 请求录制（仅影响 request-analysis 的快照窗口）。"""
    ts = _now_s()
    rid = str(uuid.uuid4())

    proxy_running = None
    try:
        from backend.proxy.service_manager import ProxyServiceManager

        proxy_running = bool(ProxyServiceManager.get_instance().is_running())
    except Exception:
        proxy_running = None

    with _state_lock:
        global _recording_active, _recording_id, _recording_started_at, _recording_ended_at, _snapshot_requests, _snapshot_by_id
        _recording_active = True
        _recording_id = rid
        _recording_started_at = ts
        _recording_ended_at = None
        _snapshot_requests = []
        _snapshot_by_id = {}

    msg = "请求录制已启动（基于 Proxy 捕获）"
    if proxy_running is False:
        msg = "请求录制已启动（等待 Proxy 流量）。请先在“代理录制”页启动代理服务。"

    return {
        "success": True,
        "message": msg,
        "recording_id": rid,
        "timestamp": ts,
    }


@router.post("/stop-recording")
async def stop_request_recording():
    """停止 HTTP 请求录制并固化快照。"""
    ts = _now_s()
    with _state_lock:
        global _recording_active, _recording_ended_at
        active = _recording_active
        start_s = _recording_started_at
        recording_id = _recording_id
        _recording_active = False
        _recording_ended_at = ts

    if not active or start_s is None:
        return {
            "success": True,
            "message": "录制已停止（此前未开始）",
            "recorded_count": 0,
            "recording_id": recording_id,
            "timestamp": ts,
        }

    proxy_requests = _get_proxy_storage_requests(limit=10000)
    windowed = _time_window(proxy_requests, start_s=start_s, end_s=ts)
    snapshot = [_convert_proxy_request_to_recorded(r) for r in windowed]
    by_id = {str(r.get("id")): r for r in snapshot if r.get("id")}

    with _state_lock:
        global _snapshot_requests, _snapshot_by_id
        _snapshot_requests = snapshot
        _snapshot_by_id = by_id

    return {
        "success": True,
        "message": "请求录制已停止",
        "recorded_count": len(snapshot),
        "recording_id": recording_id,
        "timestamp": ts,
    }


@router.delete("/requests")
async def clear_recorded_requests():
    """清空 request-analysis 的快照（不影响 proxy/crawler 的原始数据）。"""
    with _state_lock:
        global _snapshot_requests, _snapshot_by_id, _recording_active, _recording_id, _recording_started_at, _recording_ended_at
        count = len(_snapshot_requests)
        _snapshot_requests = []
        _snapshot_by_id = {}
        _recording_active = False
        _recording_id = None
        _recording_started_at = None
        _recording_ended_at = None

    return {
        "success": True,
        "message": f"已清除 {count} 条请求记录",
        "cleared_count": count,
    }


@router.get("/statistics")
async def get_request_statistics():
    """获取 request-analysis 的统计信息（适配前端字段）。"""
    live, is_live = _get_live_view()
    data = live if is_live else _get_snapshot_view()
    return _compute_statistics(data)


@router.post("/replay-request")
async def replay_request(body: Dict[str, Any]):
    """重放 HTTP 请求（支持前端按 request_id 的格式，也支持标准格式）。"""
    try:
        # ---- resolve request ----
        if "request_id" in body:
            req_id = str(body.get("request_id") or "").strip()
            if not req_id:
                raise HTTPException(status_code=400, detail="request_id 不能为空")
            original = await get_request_details(req_id)
            method = str(original.get("method") or "GET").upper()
            url = str(original.get("url") or "")
            headers = dict(original.get("headers") or {})
            payload = original.get("body")

            modify_headers = _normalize_modify_headers(body.get("modify_headers"))
            headers.update(modify_headers)

            modify_body = _normalize_modify_body(body.get("modify_body"))
            if modify_body is not None:
                payload = modify_body

            follow_redirects = bool(body.get("follow_redirects", True))
            verify_ssl = bool(body.get("verify_ssl", True))
        else:
            method = str(body.get("method") or "GET").upper()
            url = str(body.get("url") or "")
            headers = dict(body.get("headers") or {})
            payload = body.get("payload")
            follow_redirects = bool(body.get("follow_redirects", True))
            verify_ssl = bool(body.get("verify_ssl", True))

        if not url:
            raise HTTPException(status_code=400, detail="url 不能为空")

        headers = _strip_hop_by_hop_headers(headers)

        # ---- send request ----
        start = time.monotonic()
        ssl_opt = None if verify_ssl else False
        async with aiohttp.ClientSession() as session:
            kwargs: Dict[str, Any] = {"headers": headers, "allow_redirects": follow_redirects}
            if ssl_opt is not None:
                kwargs["ssl"] = ssl_opt

            if payload is not None and method in {"POST", "PUT", "PATCH", "DELETE"}:
                if isinstance(payload, (dict, list)):
                    kwargs["json"] = payload
                else:
                    kwargs["data"] = str(payload)

            async with session.request(method=method, url=url, **kwargs) as resp:
                text = await resp.text(errors="replace")
                duration_ms = int((time.monotonic() - start) * 1000)
                # avoid rendering huge response in UI
                if len(text) > 50000:
                    text = text[:50000] + "\n...[truncated]"

                # Optionally append replay record into snapshot for visibility
                replay_id = str(uuid.uuid4())
                replay_record = {
                    "id": replay_id,
                    "method": method,
                    "url": url,
                    "headers": headers,
                    "body": payload,
                    "response": {"status": int(resp.status), "headers": dict(resp.headers), "body": text},
                    "timestamp": int(_now_s()),
                    "call_stack": [],
                    "duration_ms": duration_ms,
                }
                with _state_lock:
                    if _snapshot_requests is not None:
                        _snapshot_requests.insert(0, replay_record)
                        _snapshot_by_id[replay_id] = replay_record

                return {
                    "success": True,
                    "status_code": int(resp.status),
                    "duration_ms": duration_ms,
                    "response_body": text,
                }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"请求重放失败: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e
