"""代理抓包脱敏工具。

默认在 API 返回/导出时对敏感 header（Cookie/Authorization 等）做脱敏。
如需完整导出，可通过接口参数 include_sensitive=true 获取原始内容。
"""

from __future__ import annotations

from typing import Dict, Any, Optional


_SENSITIVE_HEADER_KEYS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-token",
}


def _mask_authorization(value: str) -> str:
    if not value:
        return value
    parts = value.split(" ", 1)
    if len(parts) == 2:
        return f"{parts[0]} ***"
    return "***"


def _mask_cookie_kv(cookie_kv: str) -> str:
    cookie_kv = cookie_kv.strip()
    if not cookie_kv:
        return cookie_kv
    if "=" not in cookie_kv:
        return cookie_kv
    name, _ = cookie_kv.split("=", 1)
    return f"{name}=***"


def _mask_cookie_header(value: str) -> str:
    if not value:
        return value
    parts = [p.strip() for p in value.split(";")]
    return "; ".join(_mask_cookie_kv(p) for p in parts if p)


def _mask_set_cookie_header(value: str) -> str:
    if not value:
        return value
    # Set-Cookie 形如: name=value; Path=/; HttpOnly
    segments = [s.strip() for s in value.split(";")]
    if not segments:
        return value
    segments[0] = _mask_cookie_kv(segments[0])
    return "; ".join(segments)


def sanitize_headers(headers: Optional[Dict[str, str]]) -> Dict[str, str]:
    if not headers:
        return {}
    sanitized: Dict[str, str] = {}
    for k, v in headers.items():
        key_lower = str(k).lower()
        if key_lower not in _SENSITIVE_HEADER_KEYS:
            sanitized[str(k)] = v
            continue

        if key_lower in {"authorization", "proxy-authorization"}:
            sanitized[str(k)] = _mask_authorization(str(v))
        elif key_lower == "cookie":
            sanitized[str(k)] = _mask_cookie_header(str(v))
        elif key_lower == "set-cookie":
            sanitized[str(k)] = _mask_set_cookie_header(str(v))
        else:
            sanitized[str(k)] = "***"
    return sanitized


def sanitize_request_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """对单条请求记录做脱敏（复制后返回，不修改原对象）。"""
    if not record:
        return {}
    data = dict(record)
    data["headers"] = sanitize_headers(record.get("headers") or {})
    if record.get("response_headers") is not None:
        data["response_headers"] = sanitize_headers(record.get("response_headers") or {})
    return data

