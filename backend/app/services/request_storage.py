"""请求存储服务"""
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid
import threading

from backend.models.unified_request import UnifiedRequest, RequestSource


class RequestStorage:
    """请求存储服务"""

    MAX_REQUESTS = 10000  # 最多保留10000个请求记录
    MAX_WS_MESSAGES = 20000  # 最多保留20000条 WS 消息（内存）

    def __init__(self):
        self.requests: List[Dict[str, Any]] = []
        self.requests_by_id: Dict[str, Dict[str, Any]] = {}  # 按ID索引的请求字典
        self.ws_connections: Dict[str, Dict[str, Any]] = {}  # connection_id -> connection info
        self.ws_messages: List[Dict[str, Any]] = []  # 平铺消息列表（按时间顺序追加）
        self.ws_messages_by_connection: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def save_request(self, request: UnifiedRequest) -> str:
        """保存请求到存储"""
        if not request.id:
            request.id = str(uuid.uuid4())

        request_dict = request.to_dict()
        with self._lock:
            self.requests.append(request_dict)
            self.requests_by_id[request.id] = request_dict
            # 限制列表大小，保留最新的记录
            if len(self.requests) > self.MAX_REQUESTS:
                removed = self.requests.pop(0)
                # 同时从字典中删除
                if 'id' in removed:
                    self.requests_by_id.pop(removed['id'], None)
        return request.id

    def get_requests(
        self,
        source: Optional[RequestSource] = None,
        platform: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """查询请求（兼容旧接口：仅返回分页数据）。

        新代码建议使用 get_requests_page 获取 total/overall_total。
        """
        page = self.get_requests_page(source=source, platform=platform, limit=limit, offset=offset)
        return page.get("requests") or []

    def get_requests_page(
        self,
        *,
        source: Optional[RequestSource] = None,
        platform: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        q: Optional[str] = None,
        protocol: Optional[str] = None,  # all|http|ws
        status_group: Optional[str] = None,  # all|2xx|3xx|4xx|5xx|no_status
        content_type_group: Optional[str] = None,  # all|json|html|text|image|other
        proxy_stack: Optional[str] = None,  # all|wininet|winhttp|both|none
        process_name: Optional[str] = None,
        tag: Optional[str] = None,
        proxy_session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """分页查询（带 filtered_total + overall_total）。"""
        with self._lock:
            all_requests = list(self.requests)
        overall_total = len(all_requests)

        filtered = all_requests

        if source:
            filtered = [r for r in filtered if r.get("source") == source]

        if platform:
            filtered = [r for r in filtered if (r.get("device_info") or {}).get("platform") == platform]

        if proxy_session_id:
            filtered = [r for r in filtered if str(r.get("proxy_session_id") or "") == str(proxy_session_id)]

        if protocol and protocol != "all":
            if protocol == "http":
                filtered = [r for r in filtered if not r.get("is_websocket_handshake")]
            elif protocol == "ws":
                filtered = [r for r in filtered if bool(r.get("is_websocket_handshake"))]

        if status_group and status_group != "all":
            def _match_status(r: Dict[str, Any]) -> bool:
                s = r.get("status_code")
                if not s:
                    return status_group == "no_status"
                try:
                    s = int(s)
                except Exception:
                    return status_group == "no_status"
                if status_group == "2xx":
                    return 200 <= s < 300
                if status_group == "3xx":
                    return 300 <= s < 400
                if status_group == "4xx":
                    return 400 <= s < 500
                if status_group == "5xx":
                    return s >= 500
                return True

            filtered = [r for r in filtered if _match_status(r)]

        if content_type_group and content_type_group != "all":
            def _match_ct(r: Dict[str, Any]) -> bool:
                ct = (r.get("content_type") or (r.get("response_headers") or {}).get("Content-Type") or "").lower()
                if not ct:
                    return content_type_group == "other"
                if content_type_group == "json":
                    return "application/json" in ct
                if content_type_group == "html":
                    return "text/html" in ct
                if content_type_group == "text":
                    return ct.startswith("text/") or "javascript" in ct or "xml" in ct
                if content_type_group == "image":
                    return ct.startswith("image/")
                if content_type_group == "other":
                    return not ("application/json" in ct or "text/html" in ct or ct.startswith("text/") or ct.startswith("image/"))
                return True

            filtered = [r for r in filtered if _match_ct(r)]

        if proxy_stack and proxy_stack != "all":
            def _match_stack(r: Dict[str, Any]) -> bool:
                st = r.get("proxy_state") or {}
                wininet = bool(st.get("wininet_enabled"))
                winhttp = bool(st.get("winhttp_enabled"))
                if proxy_stack == "wininet":
                    return wininet and not winhttp
                if proxy_stack == "winhttp":
                    return winhttp and not wininet
                if proxy_stack == "both":
                    return wininet and winhttp
                if proxy_stack == "none":
                    return (not wininet) and (not winhttp)
                return True

            filtered = [r for r in filtered if _match_stack(r)]

        if process_name:
            pn = str(process_name).lower()
            filtered = [r for r in filtered if str(((r.get("client_process") or {}).get("name") or "")).lower() == pn]

        if tag:
            tl = str(tag).lower()
            filtered = [r for r in filtered if tl in [str(t).lower() for t in (r.get("tags") or [])]]

        if q:
            ql = str(q).lower()

            def _match_q(r: Dict[str, Any]) -> bool:
                try:
                    device = r.get("device_info") or {}
                    proc = r.get("client_process") or {}
                    hay = " ".join(
                        [
                            str(r.get("url") or ""),
                            str(r.get("method") or ""),
                            str(device.get("device") or ""),
                            str(device.get("platform") or ""),
                            str(proc.get("name") or ""),
                            str(proc.get("exe") or ""),
                        ]
                    ).lower()
                    return ql in hay
                except Exception:
                    return False

            filtered = [r for r in filtered if _match_q(r)]

        filtered_total = len(filtered)
        try:
            filtered.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
        except Exception:
            pass

        sliced = filtered[int(offset) : int(offset) + int(limit)]
        return {"requests": sliced, "total": filtered_total, "overall_total": overall_total, "limit": limit, "offset": offset}

    def get_recent_requests(self, limit: int = 50) -> List[Dict[str, Any]]:
        """获取最近 N 条请求（从旧到新）。"""
        n = int(limit or 0)
        if n <= 0:
            return []
        with self._lock:
            return list(self.requests[-n:])

    def get_request_by_id(self, request_id: str) -> Optional[Dict[str, Any]]:
        """根据ID获取请求"""
        with self._lock:
            request = self.requests_by_id.get(request_id)
            return request.copy() if request else None

    def update_response(self, request_id: str, response_data: Dict[str, Any]) -> bool:
        """更新请求的响应信息"""
        with self._lock:
            request = self.requests_by_id.get(request_id)
            if request:
                request['status_code'] = response_data.get('status_code')
                request['response_headers'] = response_data.get('headers', {})
                request['response_body'] = response_data.get('body')
                request['response_body_artifact'] = response_data.get('body_artifact')
                request['response_body_preview_hex'] = response_data.get('body_preview_hex')
                request['response_size'] = response_data.get('content_length')
                # 使用已计算的响应时间，不重复计算
                request['response_time'] = response_data.get('response_time')
                # content_type 尽量使用响应头
                try:
                    ct = (response_data.get("headers") or {}).get("Content-Type") or ""
                    ct_norm = str(ct).split(";", 1)[0].strip()
                    if ct_norm:
                        request["content_type"] = ct_norm
                except Exception:
                    pass

                # tags: grpc/sse best-effort
                try:
                    tags = request.get("tags") or []
                    if not isinstance(tags, list):
                        tags = []
                    ct_norm_l = str(request.get("content_type") or "").lower()
                    if ct_norm_l.startswith("application/grpc") and "grpc" not in tags:
                        tags.append("grpc")
                    if ct_norm_l == "text/event-stream" and "sse" not in tags:
                        tags.append("sse")
                    if ("protobuf" in ct_norm_l or ct_norm_l in {"application/x-protobuf", "application/protobuf"}) and "protobuf" not in tags:
                        tags.append("protobuf")
                    request["tags"] = tags or None
                except Exception:
                    pass

                # streaming/grpc meta merge
                if isinstance(response_data.get("streaming"), dict):
                    request["streaming"] = response_data.get("streaming")
                if isinstance(response_data.get("grpc"), dict):
                    existing = request.get("grpc")
                    if isinstance(existing, dict):
                        merged = dict(existing)
                        merged.update(response_data.get("grpc") or {})
                        request["grpc"] = merged
                    else:
                        request["grpc"] = response_data.get("grpc")
                if isinstance(response_data.get("protobuf"), dict):
                    request["protobuf"] = response_data.get("protobuf")
                return True
        return False

    def update_error(self, request_id: str, error_data: Dict[str, Any]) -> bool:
        """更新请求的错误信息（例如 TLS 握手失败/连接中断）。"""
        if not request_id:
            return False
        with self._lock:
            request = self.requests_by_id.get(request_id)
            if request is None:
                return False
            request["error"] = error_data
            return True

    def attach_js_event(self, request_id: str, js_event: Dict[str, Any], max_events: int = 20) -> bool:
        """将 JS 注入事件弱关联到请求（用于前端联动展示）。"""
        if not request_id or not js_event:
            return False
        with self._lock:
            request = self.requests_by_id.get(request_id)
            if request is None:
                return False
            events = request.get("js_events") or []
            if not isinstance(events, list):
                events = []
            events.append(dict(js_event))
            try:
                events = events[-int(max_events) :]
            except Exception:
                pass
            request["js_events"] = events
            return True

    def clear_requests(self) -> None:
        """清空内存中的请求与索引。"""
        with self._lock:
            self.requests = []
            self.requests_by_id = {}

    def find_recent_request_id(self, url: str, method: str, window_seconds: float = 5.0, search_limit: int = 800, base_timestamp: Optional[float] = None) -> Optional[str]:
        """在最近的请求中按 URL+Method 查找最可能对应的 request_id。

        用途：将 Native Hook 侧捕获到的 WinHTTP/WinINet 调用与代理抓包请求做弱关联，方便前端联动。
        """
        if not url or not method:
            return None
        def _norm(u: str) -> str:
            u = str(u or "").strip()
            # drop fragment (#)
            if "#" in u:
                u = u.split("#", 1)[0]
            return u

        def _match(record_url: str, hook_url: str) -> bool:
            ru = _norm(record_url)
            hu = _norm(hook_url)
            if not ru or not hu:
                return False
            if ru == hu:
                return True
            # hook_url 可能是相对路径
            if hu.startswith("/") and ru.endswith(hu):
                return True
            # best-effort: compare parsed path/query
            try:
                from urllib.parse import urlparse

                pru = urlparse(ru)
                phu = urlparse(hu)
                if phu.scheme and phu.netloc:
                    if pru.scheme == phu.scheme and pru.netloc == phu.netloc and pru.path == phu.path and pru.query == phu.query:
                        return True
                else:
                    # hu lacks scheme/netloc: compare against pru.path+query
                    path_q = pru.path + (("?" + pru.query) if pru.query else "")
                    if hu == pru.path or hu == path_q or path_q.endswith(hu):
                        return True
            except Exception:
                pass
            return False
        try:
            now = float(base_timestamp) if base_timestamp is not None else datetime.now().timestamp()
            method_upper = str(method).upper()
            with self._lock:
                candidates = list(self.requests)[-int(search_limit):]
            best_id = None
            best_delta = None
            for r in reversed(candidates):
                try:
                    if str(r.get("method", "")).upper() != method_upper:
                        continue
                    if not _match(str(r.get("url", "")), str(url)):
                        continue
                    ts = float(r.get("timestamp", 0) or 0)
                    delta = abs(now - ts)
                    if delta <= float(window_seconds) and (best_delta is None or delta < best_delta):
                        best_delta = delta
                        best_id = r.get("id")
                except Exception:
                    continue
            return str(best_id) if best_id else None
        except Exception:
            return None

    def find_recent_request_id_multi_factor(
        self,
        *,
        url: str,
        method: Optional[str] = None,
        window_seconds: float = 8.0,
        search_limit: int = 1200,
        base_timestamp: Optional[float] = None,
        target_host: Optional[str] = None,
        target_port: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """多因子关联：URL/Method + 时间窗 + 目标域名/上游地址（best-effort）。

        目标：将 Native Hook 侧（WinHTTP/WinINet/Winsock）捕获到的事件与代理抓包请求做更稳关联。
        """
        if not url and not target_host:
            return None

        def _norm_url(u: str) -> str:
            u = str(u or "").strip()
            if "#" in u:
                u = u.split("#", 1)[0]
            return u

        def _extract_domain(u: str) -> str:
            try:
                from urllib.parse import urlparse

                parsed = urlparse(_norm_url(u))
                return parsed.netloc or ""
            except Exception:
                return ""

        def _extract_path(u: str) -> str:
            try:
                from urllib.parse import urlparse

                parsed = urlparse(_norm_url(u))
                return parsed.path or "/"
            except Exception:
                return "/"

        def _match_url(record_url: str, hook_url: str) -> bool:
            ru = _norm_url(record_url)
            hu = _norm_url(hook_url)
            if not ru or not hu:
                return False
            if ru == hu:
                return True
            if hu.startswith("/") and ru.endswith(hu):
                return True
            try:
                from urllib.parse import urlparse

                pru = urlparse(ru)
                phu = urlparse(hu)
                if phu.scheme and phu.netloc:
                    if pru.scheme == phu.scheme and pru.netloc == phu.netloc and pru.path == phu.path and pru.query == phu.query:
                        return True
                else:
                    path_q = pru.path + (("?" + pru.query) if pru.query else "")
                    if hu == pru.path or hu == path_q or path_q.endswith(hu):
                        return True
            except Exception:
                pass
            return False

        try:
            now = float(base_timestamp) if base_timestamp is not None else datetime.now().timestamp()
            method_upper = str(method).upper() if method else None

            with self._lock:
                candidates = list(self.requests)[-int(search_limit):]

            hook_domain = _extract_domain(url) if url else ""
            hook_path = _extract_path(url) if url else ""
            host_hint = str(target_host or "").strip().lower() if target_host else ""
            port_hint = int(target_port) if target_port is not None else None

            best: Optional[Dict[str, Any]] = None
            best_score: float = -1.0

            for r in reversed(candidates):
                try:
                    r_method = str(r.get("method", "")).upper()
                    if method_upper and r_method != method_upper:
                        continue

                    ts = float(r.get("timestamp", 0) or 0)
                    delta = abs(now - ts)
                    if delta > float(window_seconds):
                        continue

                    score = 0.0

                    r_url = str(r.get("url", "") or "")
                    if url and _match_url(r_url, url):
                        score += 6.0
                    elif url:
                        # fallback: path match
                        r_path = _extract_path(r_url)
                        if r_path and hook_path and r_path == hook_path:
                            score += 2.0

                    # domain match
                    r_domain = _extract_domain(r_url)
                    if hook_domain and r_domain and hook_domain == r_domain:
                        score += 2.0

                    # upstream address match (requires proxy request to have server_address)
                    try:
                        srv = r.get("server_address") or {}
                        srv_host = str(srv.get("host") or "").lower()
                        srv_port = int(srv.get("port") or 0)
                    except Exception:
                        srv_host = ""
                        srv_port = 0

                    if host_hint and srv_host and host_hint == srv_host:
                        score += 3.0
                    if port_hint and srv_port and port_hint == srv_port:
                        score += 1.0

                    # time closeness (0~2)
                    score += max(0.0, 2.0 * (1.0 - (delta / max(float(window_seconds), 0.001))))

                    if score > best_score:
                        best_score = score
                        best = {
                            "request_id": r.get("id"),
                            "score": round(float(score), 3),
                            "delta_seconds": round(float(delta), 3),
                            "matched": {
                                "method": method_upper or "",
                                "url": url or "",
                                "domain": hook_domain,
                                "target_host": host_hint,
                                "target_port": port_hint,
                            },
                            "candidate": {
                                "method": r.get("method"),
                                "url": r.get("url"),
                                "timestamp": r.get("timestamp"),
                                "server_address": r.get("server_address"),
                            },
                        }
                except Exception:
                    continue

            # 经验阈值：至少命中 URL 或 (domain + host) 才认为可信
            if best and best.get("request_id") and float(best.get("score", 0) or 0) >= 6.0:
                best["request_id"] = str(best["request_id"])
                return best
            return None
        except Exception:
            return None

    # --------------------------
    # WebSocket storage
    # --------------------------

    def upsert_ws_connection(self, connection_id: str, url: str, event: str, timestamp: Optional[float] = None):
        if not connection_id:
            return

        with self._lock:
            conn = self.ws_connections.get(connection_id)
            if not conn:
                conn = {
                    "id": connection_id,
                    "url": url,
                    "started_at": timestamp,
                    "ended_at": None,
                    "status": "open" if event != "ws_end" else "closed",
                    "message_count": 0,
                    "last_seen": timestamp,
                }
                self.ws_connections[connection_id] = conn
                self.ws_messages_by_connection.setdefault(connection_id, [])
            else:
                conn["last_seen"] = timestamp or conn.get("last_seen")
                if event == "ws_end":
                    conn["ended_at"] = timestamp
                    conn["status"] = "closed"

    def add_ws_message(self, connection_id: str, message: Dict[str, Any]):
        if not connection_id:
            return
        with self._lock:
            self.ws_messages.append(message)
            self.ws_messages_by_connection.setdefault(connection_id, []).append(message)
            conn = self.ws_connections.get(connection_id)
            if conn:
                conn["message_count"] = int(conn.get("message_count", 0)) + 1
                conn["last_seen"] = message.get("timestamp") or conn.get("last_seen")

            # 截断全局列表
            if len(self.ws_messages) > self.MAX_WS_MESSAGES:
                removed = self.ws_messages.pop(0)
                removed_conn = removed.get("connection_id")
                if removed_conn and removed_conn in self.ws_messages_by_connection:
                    # 同步从连接列表中删除最早一条（O(n)，但 MAX_WS_MESSAGES 有上限）
                    try:
                        self.ws_messages_by_connection[removed_conn].remove(removed)
                    except ValueError:
                        pass

    def get_ws_connections(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        with self._lock:
            conns = list(self.ws_connections.values())

        # 按 last_seen 倒序
        conns = sorted(conns, key=lambda x: x.get("last_seen") or 0, reverse=True)
        return conns[offset : offset + limit]

    def count_ws_connections(self) -> int:
        with self._lock:
            return int(len(self.ws_connections))

    def get_all_ws_connections(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(v) for v in self.ws_connections.values()]

    def get_ws_connection(self, connection_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self.ws_connections.get(connection_id)
            return conn.copy() if conn else None

    def get_ws_messages(self, connection_id: str, limit: int = 200, offset: int = 0) -> List[Dict[str, Any]]:
        with self._lock:
            messages = list(self.ws_messages_by_connection.get(connection_id, []))
        # 默认按时间正序
        return messages[offset : offset + limit]

    def get_ws_messages_page(
        self,
        connection_id: str,
        *,
        limit: int = 200,
        offset: int = 0,
        direction: Optional[str] = None,
        min_size: Optional[int] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            messages = list(self.ws_messages_by_connection.get(connection_id, []))

        if direction in {"send", "receive"}:
            messages = [m for m in messages if str(m.get("direction") or "") == direction]

        if min_size is not None:
            try:
                ms = int(min_size)
            except Exception:
                ms = 0
            if ms > 0:
                messages = [m for m in messages if int(m.get("size") or 0) >= ms]

        total = len(messages)
        sliced = messages[int(offset) : int(offset) + int(limit)]
        return {"messages": sliced, "total": total, "limit": limit, "offset": offset}

    def count_ws_messages(self, connection_id: str) -> int:
        with self._lock:
            return int(len(self.ws_messages_by_connection.get(connection_id, []) or []))

    def get_all_ws_messages(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(m) for m in self.ws_messages]

    def clear_ws(self):
        with self._lock:
            self.ws_connections = {}
            self.ws_messages = []
            self.ws_messages_by_connection = {}

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._lock:
            total = len(self.requests)
            by_source = {}
            by_platform = {}

            for request in self.requests:
                source = request.get('source')
                if source:
                    by_source[source] = by_source.get(source, 0) + 1

                platform = request.get('device_info', {}).get('platform')
                if platform:
                    by_platform[platform] = by_platform.get(platform, 0) + 1

        return {
            'total': total,
            'by_source': by_source,
            'by_platform': by_platform
        }
