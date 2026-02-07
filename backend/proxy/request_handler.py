"""mitmproxy 请求/响应/WS 事件拦截器。"""

from __future__ import annotations

from typing import Callable, Optional, Dict, Any
from mitmproxy import http
import logging
import os
import time
import socket
from .device_detector import DeviceDetector
from backend.app.config import settings
from backend.proxy.artifacts import ProxyArtifactStore, capture_body, maybe_decompress
from backend.proxy.grpc import (
    is_grpc_content_type,
    is_protobuf_content_type,
    normalize_content_type,
    parse_grpc_frames,
    parse_grpc_method_path,
)
from backend.proxy.streaming import StreamingCaptureStats

logger = logging.getLogger(__name__)


class RequestInterceptor:
    """请求拦截器"""

    def __init__(self, on_request: Callable, on_response: Callable, on_websocket: Optional[Callable] = None):
        """
        初始化拦截器

        Args:
            on_request: 请求回调函数
            on_response: 响应回调函数
            on_websocket: WebSocket 事件回调函数
        """
        self.on_request = on_request
        self.on_response = on_response
        self.on_websocket = on_websocket
        self._artifact_store = ProxyArtifactStore()
        self._pid_cache: Dict[str, Dict[str, Any]] = {}  # key -> {ts,pid,name,exe}
        self._local_ips_cache: Dict[str, Any] = {"ts": 0.0, "ips": set()}

    def _get_local_ips(self) -> set[str]:
        now = time.time()
        cached_ts = float(self._local_ips_cache.get("ts", 0.0) or 0.0)
        if now - cached_ts < 60 and self._local_ips_cache.get("ips"):
            return set(self._local_ips_cache.get("ips") or set())

        ips: set[str] = {"127.0.0.1", "::1"}
        try:
            import psutil

            for addrs in psutil.net_if_addrs().values():
                for a in addrs:
                    try:
                        if a.family in {socket.AF_INET, socket.AF_INET6} and a.address:
                            ips.add(str(a.address).split("%", 1)[0])
                    except Exception:
                        continue
        except Exception:
            pass

        self._local_ips_cache = {"ts": now, "ips": ips}
        return ips

    def _lookup_client_process(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """best-effort 从 TCP 连接反查发起进程（Windows 优先）。"""
        if os.name != "nt":
            return None

        try:
            client = getattr(flow, "client_conn", None)
            if not client or not getattr(client, "address", None):
                return None
            client_ip, client_port = str(client.address[0]), int(client.address[1])
            # 仅对本机进程做归因；来自手机/局域网设备的连接无法映射到本机 PID
            if client_ip not in self._get_local_ips():
                return None

            local_port = None
            sockname = getattr(client, "sockname", None)
            if sockname and isinstance(sockname, tuple) and len(sockname) >= 2:
                local_port = int(sockname[1])
            if not local_port:
                return None

            cache_key = f"{client_ip}:{client_port}->{local_port}"
            cached = self._pid_cache.get(cache_key)
            now = time.time()
            if cached and now - float(cached.get("ts", 0)) < 20:
                return {k: v for k, v in cached.items() if k != "ts"}

            import psutil

            pid = None
            for c in psutil.net_connections(kind="tcp"):
                try:
                    if not c.raddr or not c.laddr:
                        continue
                    if int(c.laddr.port) == client_port and int(c.raddr.port) == local_port:
                        pid = c.pid
                        break
                except Exception:
                    continue

            if not pid:
                return None

            p = psutil.Process(pid)
            info = {
                "pid": pid,
                "name": p.name(),
                "exe": p.exe() if hasattr(p, "exe") else None,
            }
            self._pid_cache[cache_key] = {"ts": now, **info}
            return info
        except Exception:
            return None

    def _extract_connection_meta(self, flow: http.HTTPFlow) -> Dict[str, Any]:
        meta: Dict[str, Any] = {}

        # HTTP version
        try:
            meta["http_version"] = getattr(flow.request, "http_version", None)
        except Exception:
            meta["http_version"] = None

        # Remote/Client addresses
        try:
            server_addr = getattr(flow, "server_conn", None)
            if server_addr and getattr(server_addr, "address", None):
                meta["server_address"] = {"host": server_addr.address[0], "port": server_addr.address[1]}
        except Exception:
            pass

        try:
            client_addr = getattr(flow, "client_conn", None)
            if client_addr and getattr(client_addr, "address", None):
                meta["client_address"] = {"host": client_addr.address[0], "port": client_addr.address[1]}
        except Exception:
            pass

        # 客户端进程（Windows best-effort）
        proc = self._lookup_client_process(flow)
        if proc:
            meta["client_process"] = proc

        # TLS info (best-effort)
        try:
            server_conn = getattr(flow, "server_conn", None)
            if server_conn:
                tls_info: Dict[str, Any] = {}
                for key in ("tls_established", "sni", "alpn", "cipher"):
                    value = getattr(server_conn, key, None)
                    if value is not None:
                        tls_info[key] = value

                cert = getattr(server_conn, "cert", None)
                if cert:
                    # mitmproxy may expose OpenSSL.X509-like or cryptography objects; stringify only
                    tls_info["cert_subject"] = getattr(getattr(cert, "subject", None), "human_friendly", None) or str(getattr(cert, "subject", cert))
                    tls_info["cert_issuer"] = getattr(getattr(cert, "issuer", None), "human_friendly", None) or str(getattr(cert, "issuer", ""))
                if tls_info:
                    meta["tls"] = tls_info
        except Exception:
            pass

        # 上游服务端地址（best-effort）：用于与 Native Hook 侧 peer(host/port) 做多因子关联
        try:
            server_conn = getattr(flow, "server_conn", None)
            addr = getattr(server_conn, "address", None) if server_conn else None
            if addr and isinstance(addr, (list, tuple)) and len(addr) >= 2:
                meta["server_address"] = {"host": addr[0], "port": addr[1]}
        except Exception:
            pass

        return meta

    def request(self, flow: http.HTTPFlow):
        """拦截HTTP请求"""
        try:
            # 检查是否应该捕获此请求
            from .service_manager import ProxyServiceManager
            manager = ProxyServiceManager.get_instance()
            request_filter = manager.get_filter()

            if not request_filter.should_capture(flow.request.pretty_url, flow.request.method):
                return

            # 生成唯一请求ID
            import uuid
            request_id = str(uuid.uuid4())
            flow.metadata['request_id'] = request_id

            # 提取设备信息
            user_agent = flow.request.headers.get('User-Agent', '')
            device_info = DeviceDetector.detect(user_agent)
            device_info['user_agent'] = user_agent

            # Body capture (preview + optional artifact)
            content_type = flow.request.headers.get("Content-Type", "")
            content_encoding = flow.request.headers.get("Content-Encoding", "")
            request_raw = getattr(flow.request, "raw_content", b"") or b""
            request_content = maybe_decompress(request_raw, content_encoding)
            body_preview_hex = None
            try:
                if request_content:
                    body_preview_hex = request_content[: int(settings.proxy_body_preview_bytes)].hex()
            except Exception:
                body_preview_hex = None

            # gRPC/Protobuf best-effort 识别（不解码）
            grpc_meta = None
            protobuf_meta = None
            try:
                if is_grpc_content_type(content_type):
                    from urllib.parse import urlparse

                    parsed = urlparse(flow.request.pretty_url)
                    meta = parse_grpc_method_path(parsed.path)
                    meta["content_type"] = normalize_content_type(content_type)
                    meta["grpc_timeout"] = flow.request.headers.get("grpc-timeout")
                    meta["grpc_encoding"] = flow.request.headers.get("grpc-encoding") or flow.request.headers.get("grpc-accept-encoding")
                    meta["request"] = parse_grpc_frames(request_content)
                    grpc_meta = meta
                elif is_protobuf_content_type(content_type):
                    protobuf_meta = {
                        "content_type": normalize_content_type(content_type),
                        "data_bytes": len(request_content or b""),
                    }
            except Exception:
                grpc_meta = grpc_meta
                protobuf_meta = protobuf_meta

            body_preview, body_artifact = capture_body(
                content=request_content,
                content_type=content_type,
                inline_limit_chars=settings.proxy_body_inline_limit,
                preview_bytes=settings.proxy_body_preview_bytes,
                store=self._artifact_store,
                prefix="request",
            )

            # 提取请求信息
            request_data = {
                'id': request_id,
                'method': flow.request.method,
                'url': flow.request.pretty_url,
                'headers': dict(flow.request.headers),
                'body': body_preview or "",
                'body_artifact': body_artifact,
                'body_preview_hex': body_preview_hex,
                'timestamp': flow.request.timestamp_start,
                'device': device_info,
                'grpc': grpc_meta,
                'protobuf': protobuf_meta,
            }

            request_data.update(self._extract_connection_meta(flow))

            # 标记是否为 WebSocket 握手
            try:
                request_data["is_websocket_handshake"] = bool(flow.request.headers.get("Upgrade", "").lower() == "websocket")
            except Exception:
                request_data["is_websocket_handshake"] = False

            # 调用回调函数
            if self.on_request:
                try:
                    self.on_request(request_data)
                except Exception as e:
                    logger.error(f"请求回调函数执行错误: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"请求拦截错误: {e}", exc_info=True)

    def response(self, flow: http.HTTPFlow):
        """拦截HTTP响应"""
        try:
            # 计算响应时间
            response_time = 0
            if flow.response.timestamp_end and flow.request.timestamp_start:
                response_time = flow.response.timestamp_end - flow.request.timestamp_start

            response_ct = ""
            response_ce = ""
            try:
                response_ct = flow.response.headers.get("Content-Type", "")
                response_ce = flow.response.headers.get("Content-Encoding", "")
            except Exception:
                response_ct = ""
                response_ce = ""

            # Streaming/SSE：使用 responseheaders 中的统计信息
            streaming_stats = None
            try:
                streaming_stats = flow.metadata.get("streaming_stats")
            except Exception:
                streaming_stats = None

            response_body_preview = None
            response_body_artifact = None
            streaming_meta = None
            grpc_resp_meta = None
            protobuf_resp_meta = None
            response_preview_hex = None

            if isinstance(streaming_stats, StreamingCaptureStats):
                # finalize streaming summary
                streaming_meta = streaming_stats.summary(state="closed")
                captured = streaming_stats.get_captured_bytes()
                try:
                    if captured:
                        response_preview_hex = captured[: int(settings.proxy_body_preview_bytes)].hex()
                except Exception:
                    response_preview_hex = None
                if captured:
                    try:
                        artifact = self._artifact_store.store_bytes(captured, content_type=response_ct, prefix="stream")
                        response_body_artifact = {
                            **artifact.to_dict(),
                            "is_binary": not streaming_stats.is_text,
                            "truncated": True,
                            "partial": True,
                            "captured_bytes": len(captured),
                            "total_bytes": int(streaming_stats.total_bytes),
                        }
                    except Exception:
                        response_body_artifact = None

                # Preview in body (first/last)
                try:
                    first_p = str(streaming_meta.get("first_preview") or "")
                    last_p = str(streaming_meta.get("last_preview") or "")
                    response_body_preview = (
                        f"[Streaming/SSE] chunks={streaming_meta.get('chunk_count')} bytes={streaming_meta.get('total_bytes')} duration={streaming_meta.get('duration_ms')}ms\n"
                        f"--- first ---\n{first_p}\n--- last ---\n{last_p}\n"
                    )
                    if response_body_artifact and response_body_artifact.get("artifact_id"):
                        response_body_preview += f"[已捕获前{response_body_artifact.get('captured_bytes')}字节: {response_body_artifact.get('artifact_id')}]\n"
                except Exception:
                    response_body_preview = "[Streaming/SSE] (captured)"
            else:
                response_raw = getattr(flow.response, "raw_content", b"") or b""
                response_content = maybe_decompress(response_raw, response_ce)
                try:
                    if response_content:
                        response_preview_hex = response_content[: int(settings.proxy_body_preview_bytes)].hex()
                except Exception:
                    response_preview_hex = None

                # gRPC/Protobuf best-effort 识别（不解码）
                try:
                    if is_grpc_content_type(response_ct):
                        grpc_resp_meta = {
                            "response": parse_grpc_frames(response_content),
                            "response_content_type": normalize_content_type(response_ct),
                        }
                    elif is_protobuf_content_type(response_ct):
                        protobuf_resp_meta = {
                            "response_content_type": normalize_content_type(response_ct),
                            "data_bytes": len(response_content or b""),
                        }
                except Exception:
                    grpc_resp_meta = grpc_resp_meta
                    protobuf_resp_meta = protobuf_resp_meta

                response_body_preview, response_body_artifact = capture_body(
                    content=response_content,
                    content_type=response_ct,
                    inline_limit_chars=settings.proxy_body_inline_limit,
                    preview_bytes=settings.proxy_body_preview_bytes,
                    store=self._artifact_store,
                    prefix="response",
                )

            # 提取响应信息
            response_data = {
                'url': flow.request.pretty_url,
                'status_code': flow.response.status_code,
                'headers': dict(flow.response.headers),
                'body': response_body_preview or "",
                'body_artifact': response_body_artifact,
                'body_preview_hex': response_preview_hex,
                'content_length': int(getattr(streaming_stats, "total_bytes", 0) or 0) if isinstance(streaming_stats, StreamingCaptureStats) else (len(flow.response.content) if flow.response.content else 0),
                'timestamp': flow.response.timestamp_end,
                'response_time': response_time
            }
            if streaming_meta:
                response_data["streaming"] = streaming_meta
            if grpc_resp_meta:
                response_data["grpc"] = grpc_resp_meta
            if protobuf_resp_meta:
                response_data["protobuf"] = protobuf_resp_meta

            # 从flow中获取请求ID
            if 'request_id' in flow.metadata:
                response_data['request_id'] = flow.metadata['request_id']

            # 调用回调函数
            if self.on_response:
                try:
                    self.on_response(response_data)
                except Exception as e:
                    logger.error(f"响应回调函数执行错误: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"响应拦截错误: {e}", exc_info=True)

    def responseheaders(self, flow: http.HTTPFlow):
        """处理响应头（用于 Streaming/SSE 的早期状态与片段统计）。"""
        try:
            if not getattr(flow, "response", None) or not getattr(flow, "request", None):
                return

            request_id = None
            try:
                request_id = flow.metadata.get("request_id")
            except Exception:
                request_id = None
            if not request_id:
                return

            ct = ""
            try:
                ct = flow.response.headers.get("Content-Type", "")
            except Exception:
                ct = ""
            ct_norm = normalize_content_type(ct)
            if ct_norm != "text/event-stream":
                return

            stats = StreamingCaptureStats(
                content_type=ct_norm,
                preview_bytes=settings.proxy_stream_preview_bytes,
                capture_max_bytes=settings.proxy_stream_capture_max_bytes,
                is_text=True,
            )
            flow.metadata["streaming_stats"] = stats

            def _stream(chunk: bytes):
                try:
                    stats.consume(chunk or b"")
                except Exception:
                    pass
                return chunk

            # Enable streaming to avoid buffering infinite responses
            try:
                flow.response.stream = _stream
            except Exception:
                pass

            # Early response update: set status/headers, mark as streaming
            try:
                ts = getattr(flow.response, "timestamp_start", None) or time.time()
                response_time = 0
                try:
                    if flow.request.timestamp_start:
                        response_time = float(ts) - float(flow.request.timestamp_start)
                except Exception:
                    response_time = 0

                response_data = {
                    "url": flow.request.pretty_url,
                    "status_code": flow.response.status_code,
                    "headers": dict(flow.response.headers),
                    "body": "[Streaming/SSE] 响应已建立，正在接收数据...",
                    "body_artifact": None,
                    "content_length": 0,
                    "timestamp": ts,
                    "response_time": response_time,
                    "request_id": request_id,
                    "streaming": stats.summary(state="open"),
                }
                if self.on_response:
                    self.on_response(response_data)
            except Exception:
                pass
        except Exception as e:
            logger.error(f"responseheaders 处理错误: {e}", exc_info=True)

    # --------------------------
    # WebSocket events
    # --------------------------

    def websocket_start(self, flow: http.HTTPFlow):
        try:
            if not self.on_websocket:
                return
            event = {
                "event": "ws_start",
                "url": flow.request.pretty_url,
                "timestamp": getattr(flow.request, "timestamp_start", None),
                "request_id": flow.metadata.get("request_id"),
            }
            event.update(self._extract_connection_meta(flow))
            self.on_websocket(event)
        except Exception as e:
            logger.error(f"WebSocket start 处理错误: {e}", exc_info=True)

    def websocket_message(self, flow: http.HTTPFlow):
        try:
            if not self.on_websocket:
                return
            ws = getattr(flow, "websocket", None)
            if not ws or not getattr(ws, "messages", None):
                return

            message = ws.messages[-1]
            from_client = bool(getattr(message, "from_client", False))
            content = getattr(message, "content", b"") or b""
            is_text = bool(getattr(message, "is_text", False))

            content_type = "text/plain" if is_text else "application/octet-stream"
            preview, artifact = capture_body(
                content=content,
                content_type=content_type,
                inline_limit_chars=settings.proxy_body_inline_limit,
                preview_bytes=settings.proxy_ws_message_preview_bytes,
                store=self._artifact_store,
                prefix="ws",
            )

            event = {
                "event": "ws_message",
                "url": flow.request.pretty_url,
                "timestamp": getattr(message, "timestamp", None) or getattr(flow.request, "timestamp_start", None),
                "request_id": flow.metadata.get("request_id"),
                "direction": "send" if from_client else "receive",
                "is_text": is_text,
                "size": len(content),
                "data": preview or "",
                "data_artifact": artifact,
            }
            self.on_websocket(event)
        except Exception as e:
            logger.error(f"WebSocket message 处理错误: {e}", exc_info=True)

    def websocket_end(self, flow: http.HTTPFlow):
        try:
            if not self.on_websocket:
                return
            event = {
                "event": "ws_end",
                "url": flow.request.pretty_url,
                "timestamp": getattr(flow.response, "timestamp_end", None) if getattr(flow, "response", None) else None,
                "request_id": flow.metadata.get("request_id"),
            }
            self.on_websocket(event)
        except Exception as e:
            logger.error(f"WebSocket end 处理错误: {e}", exc_info=True)

    # --------------------------
    # Errors
    # --------------------------

    def error(self, flow: http.HTTPFlow):
        """拦截 mitmproxy 流错误（TLS/连接/协议等）。"""
        try:
            err = getattr(flow, "error", None)
            if not err:
                return

            request_id = None
            try:
                request_id = flow.metadata.get("request_id")
            except Exception:
                request_id = None

            url = ""
            try:
                if getattr(flow, "request", None):
                    url = flow.request.pretty_url
            except Exception:
                url = ""

            message = str(getattr(err, "msg", None) or err)
            error_data = {
                "type": getattr(err, "__class__", type("E", (), {})).__name__,
                "message": message,
                "url": url,
                "request_id": request_id,
                "timestamp": time.time(),
            }

            from backend.proxy.service_manager import ProxyServiceManager

            manager = ProxyServiceManager.get_instance()
            manager.get_statistics().record_error(error_data)

            try:
                storage = manager.get_storage()
                if request_id:
                    storage.update_error(str(request_id), error_data)
            except Exception:
                pass

            # session 落盘（best-effort）
            try:
                recorder = manager.get_proxy_session_recorder()
                if recorder and request_id:
                    recorder.record_error(str(request_id), {"error": error_data})
            except Exception:
                pass
        except Exception as e:
            logger.error(f"错误拦截处理失败: {e}", exc_info=True)
