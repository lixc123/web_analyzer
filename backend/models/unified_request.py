"""统一请求数据模型"""
from enum import Enum
from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel
import os


class RequestSource(str, Enum):
    """请求来源类型"""
    WEB_BROWSER = "web_browser"
    DESKTOP_APP = "desktop_app"
    MOBILE_IOS = "mobile_ios"
    MOBILE_ANDROID = "mobile_android"


class UnifiedRequest(BaseModel):
    """统一的请求记录模型"""
    # 基础信息
    id: Optional[str] = None
    source: RequestSource
    device_info: Optional[Dict[str, Any]] = None

    # 请求信息
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str] = None
    body_artifact: Optional[Dict[str, Any]] = None
    body_preview_hex: Optional[str] = None
    timestamp: float

    # 响应信息
    status_code: Optional[int] = None
    response_headers: Optional[Dict[str, str]] = None
    response_body: Optional[str] = None
    response_body_artifact: Optional[Dict[str, Any]] = None
    response_body_preview_hex: Optional[str] = None
    response_size: Optional[int] = None
    response_time: Optional[float] = None

    # 元数据
    content_type: Optional[str] = None
    is_https: bool = False
    host: Optional[str] = None
    path: Optional[str] = None
    tags: Optional[list] = None

    # 应用层协议/长连接辅助信息（best-effort）
    grpc: Optional[Dict[str, Any]] = None
    protobuf: Optional[Dict[str, Any]] = None
    streaming: Optional[Dict[str, Any]] = None

    # 连接/协议元数据（用于排障与分析）
    http_version: Optional[str] = None
    server_address: Optional[Dict[str, Any]] = None
    client_address: Optional[Dict[str, Any]] = None
    client_process: Optional[Dict[str, Any]] = None
    tls: Optional[Dict[str, Any]] = None
    is_websocket_handshake: bool = False
    proxy_state: Optional[Dict[str, Any]] = None
    proxy_session_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        # 使用 JSON mode，确保 Enum 等可序列化（用于导出/落盘）
        return self.model_dump(mode="json")

    @staticmethod
    def from_proxy_request(request_data: Dict[str, Any], response_data: Optional[Dict[str, Any]] = None) -> 'UnifiedRequest':
        """从代理请求数据创建 UnifiedRequest"""
        # 识别来源类型
        device_info = request_data.get('device', {})
        platform = device_info.get('platform', 'unknown')

        client_process = request_data.get("client_process") or {}
        proc_name = str(client_process.get("name") or "").lower()
        exe_path = str(client_process.get("exe") or "")
        try:
            exe_base = os.path.basename(exe_path.replace("\\", "/")).lower() if exe_path else proc_name
        except Exception:
            exe_base = proc_name

        # 常见“完整浏览器”进程（偏向 web_browser）
        full_browser_names = {
            "chrome.exe",
            "msedge.exe",
            "firefox.exe",
            "brave.exe",
            "opera.exe",
            "iexplore.exe",
            "chromium.exe",
            "vivaldi.exe",
            "yandex.exe",
            "qqbrowser.exe",
            "360chrome.exe",
            "sogouexplorer.exe",
        }
        # 常见“内嵌浏览器/渲染进程”（偏向 desktop_app）
        embedded_browser_names = {
            "msedgewebview2.exe",
            "webview2.exe",
            "cefclient.exe",
            "cef.exe",
            "electron.exe",
            "nw.exe",
        }

        is_full_browser_proc = (exe_base in full_browser_names) or (proc_name in full_browser_names)
        is_embedded_proc = (exe_base in embedded_browser_names) or (proc_name in embedded_browser_names)

        # exe 路径进一步兜底（不同发行版可能 name 不同）
        try:
            exe_lower = exe_path.lower()
            exe_norm = exe_lower.replace("/", "\\")
            if any(
                s in exe_norm
                for s in (
                    "\\google\\chrome\\application\\chrome.exe",
                    "\\microsoft\\edge\\application\\msedge.exe",
                    "\\mozilla firefox\\firefox.exe",
                    "\\brave-browser\\application\\brave.exe",
                    "\\opera\\launcher.exe",
                    "\\vivaldi\\application\\vivaldi.exe",
                )
            ):
                is_full_browser_proc = True
            if ("edgewebview" in exe_lower) or ("webview2" in exe_lower):
                is_embedded_proc = True
        except Exception:
            pass

        browser_hint = str((device_info or {}).get("browser") or "").lower()
        is_browser_hint = browser_hint in {"chrome", "edge", "firefox", "safari"}

        if platform == 'iOS':
            source = RequestSource.MOBILE_IOS
        elif platform == 'Android':
            source = RequestSource.MOBILE_ANDROID
        elif platform in ['Windows', 'macOS', 'Linux']:
            # 桌面平台：优先使用进程名/路径判断浏览器 vs 桌面应用；UA 仅做兜底
            if is_embedded_proc:
                source = RequestSource.DESKTOP_APP
            elif is_full_browser_proc:
                source = RequestSource.WEB_BROWSER
            elif is_browser_hint:
                # 有 UA 浏览器特征但进程不是“完整浏览器”时，更可能是 WebView2/Electron/CEF
                source = RequestSource.DESKTOP_APP if proc_name else RequestSource.WEB_BROWSER
            else:
                source = RequestSource.DESKTOP_APP
        else:
            source = RequestSource.WEB_BROWSER

        # 解析URL
        url = request_data.get('url', '')
        is_https = url.startswith('https://')

        # 提取host和path
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path

        tags: list = []
        try:
            req_ct = str(request_data.get('headers', {}).get('Content-Type') or "")
            req_ct_norm = req_ct.split(";", 1)[0].strip().lower()
            if req_ct_norm.startswith("application/grpc"):
                tags.append("grpc")
            if req_ct_norm in {"application/x-protobuf", "application/protobuf"} or "protobuf" in req_ct_norm:
                tags.append("protobuf")
        except Exception:
            pass

        grpc_meta = request_data.get("grpc") if isinstance(request_data.get("grpc"), dict) else None
        protobuf_meta = request_data.get("protobuf") if isinstance(request_data.get("protobuf"), dict) else None

        # 创建统一请求对象
        unified_request = UnifiedRequest(
            id=request_data.get('id'),
            source=source,
            device_info=device_info,
            method=request_data.get('method', 'GET'),
            url=url,
            headers=request_data.get('headers', {}),
            body=request_data.get('body'),
            body_artifact=request_data.get('body_artifact'),
            body_preview_hex=request_data.get("body_preview_hex"),
            timestamp=request_data.get('timestamp', datetime.now().timestamp()),
            is_https=is_https,
            host=host,
            path=path,
            content_type=request_data.get('headers', {}).get('Content-Type'),
            http_version=request_data.get('http_version'),
            server_address=request_data.get('server_address'),
            client_address=request_data.get('client_address'),
            client_process=request_data.get('client_process'),
            tls=request_data.get('tls'),
            is_websocket_handshake=bool(request_data.get('is_websocket_handshake', False)),
            proxy_state=request_data.get('proxy_state'),
            proxy_session_id=request_data.get("proxy_session_id"),
            tags=tags or None,
            grpc=grpc_meta,
            protobuf=protobuf_meta,
        )

        # 添加响应信息
        if response_data:
            unified_request.status_code = response_data.get('status_code')
            unified_request.response_headers = response_data.get('headers', {})
            unified_request.response_body = response_data.get('body')
            unified_request.response_body_artifact = response_data.get('body_artifact')
            unified_request.response_body_preview_hex = response_data.get("body_preview_hex")
            unified_request.response_size = response_data.get('content_length')
            # 统一使用已计算的响应时间
            unified_request.response_time = response_data.get('response_time')
            # 尽量使用响应 Content-Type
            resp_ct = response_data.get("headers", {}).get("Content-Type")
            if resp_ct:
                unified_request.content_type = resp_ct.split(";", 1)[0].strip()
                try:
                    resp_ct_norm = unified_request.content_type.lower()
                    if resp_ct_norm.startswith("application/grpc") and "grpc" not in tags:
                        tags.append("grpc")
                    if resp_ct_norm == "text/event-stream" and "sse" not in tags:
                        tags.append("sse")
                except Exception:
                    pass

            # streaming meta（例如 SSE 长连接）
            if isinstance(response_data.get("streaming"), dict):
                unified_request.streaming = response_data.get("streaming")

            # gRPC meta merge（response 侧帧信息）
            if isinstance(response_data.get("grpc"), dict):
                if unified_request.grpc and isinstance(unified_request.grpc, dict):
                    merged = dict(unified_request.grpc)
                    merged.update(response_data.get("grpc") or {})
                    unified_request.grpc = merged
                else:
                    unified_request.grpc = response_data.get("grpc")

        if tags:
            unified_request.tags = tags

        return unified_request
