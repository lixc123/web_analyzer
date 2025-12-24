"""HTTP 请求记录数据模型。

对应任务清单 M2-1-2、M2-1-3：定义并文档化 RequestRecord 的所有字段。

RequestRecord 是 Web Recorder 的核心数据结构，用于存储单个 HTTP 请求/响应
的完整信息，包括：
- 请求基本信息（method/url/headers/body）
- 响应信息（status/headers/body_path/size）
- 元数据（timestamp/content_type/resource_type）
- 调试信息（call_stack）

该结构会被：
- 序列化到 ``requests.json`` 供持久化存储
- 索引模块用于构建 Request Snippet 文本
- Agent 工具用于分析和代码生成
"""

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class RequestRecord:
    """单个 HTTP 请求/响应的完整记录。

    Attributes:
        id: 请求唯一标识符，通常为 Python 对象 id 的字符串形式。
            用于在 session 内唯一标识一个请求，也用于关联响应文件路径。

        timestamp: 请求发起时间戳（Unix timestamp，秒级浮点数）。
            由 Playwright request 事件触发时的 ``time.time()`` 生成。

        method: HTTP 请求方法，如 GET/POST/PUT/DELETE/PATCH/OPTIONS 等。
            直接从 Playwright Request 对象获取。

        url: 完整的请求 URL，包含协议、域名、路径、查询参数。
            示例: ``https://api.example.com/v1/login?from=web``

        headers: 请求头字典，键为 header 名称，值为 header 值。
            包含 Cookie、Authorization、Content-Type、User-Agent 等。
            敏感信息（如 Cookie、Authorization）在索引时会被特殊处理。

        post_data: POST/PUT 等请求的请求体内容（字符串形式）。
            对于 JSON 请求体，此字段包含 JSON 字符串；
            对于 form-data，包含 URL 编码的表单数据；
            GET 请求此字段为 None。

        status: HTTP 响应状态码，如 200/201/400/401/500 等。
            响应到达前为 None，响应事件触发后填充。

        response_headers: 响应头字典，结构同 headers。
            包含 Content-Type、Set-Cookie、Cache-Control 等。

        response_body_path: 响应体文件的相对路径（相对于 session 目录）。
            示例: ``responses/123456789.json`` 或 ``scripts/main.js``
            根据 Content-Type 自动分类到不同子目录。

        response_size: 响应体大小（字节数）。
            用于快速判断响应体量，无需读取文件。

        content_type: 响应的 Content-Type（已解析，不含 charset 等参数）。
            示例: ``application/json``、``text/html``、``image/png``
            由 ResourceArchiver 在保存响应时从 response_headers 提取并设置。

        response_timestamp: 响应到达时间戳（Unix timestamp）。
            用于计算请求耗时: ``response_timestamp - timestamp``。

        call_stack: JavaScript 调用栈字符串。
            通过注入的 Hook 脚本捕获 fetch/XHR 调用时的 JS 调用栈。
            格式为多行文本，每行包含函数名、文件名、行号等信息。
            对于逆向分析签名逻辑非常重要，可追溯到发起请求的 JS 代码位置。
            无法捕获时为 None。

        resource_type: Playwright 报告的资源类型。
            可能的值: xhr, fetch, script, stylesheet, image, font,
            document, websocket, manifest, other 等。
            用于过滤和分类请求（如仅分析 xhr/fetch 类型的 API 请求）。

    Example:
        >>> record = RequestRecord(
        ...     id="123456789",
        ...     timestamp=1702454400.123,
        ...     method="POST",
        ...     url="https://api.example.com/login",
        ...     headers={"Content-Type": "application/json", "Cookie": "..."},
        ...     post_data='{"username": "test", "sign": "abc123"}',
        ...     status=200,
        ...     response_headers={"Content-Type": "application/json"},
        ...     response_body_path="responses/123456789.json",
        ...     response_size=256,
        ...     content_type="application/json",
        ...     response_timestamp=1702454400.456,
        ...     call_stack="at makeSign (main.js:123)\\nat login (main.js:456)",
        ...     resource_type="xhr",
        ... )
    """

    # ===== 请求基本信息（必填字段） =====
    id: str
    """请求唯一标识符"""

    timestamp: float
    """请求发起时间戳（Unix timestamp）"""

    method: str
    """HTTP 方法: GET/POST/PUT/DELETE/PATCH/OPTIONS 等"""

    url: str
    """完整请求 URL"""

    headers: Dict[str, str]
    """请求头字典"""

    post_data: Optional[str]
    """请求体内容（POST/PUT 等方法），GET 请求为 None"""

    # ===== 响应信息（可选字段，响应到达后填充） =====
    status: Optional[int] = None
    """HTTP 响应状态码: 200/201/400/401/500 等"""

    response_headers: Optional[Dict[str, str]] = None
    """响应头字典"""

    response_body_path: Optional[str] = None
    """响应体文件相对路径，如 responses/xxx.json"""

    response_size: Optional[int] = None
    """响应体大小（字节）"""

    # ===== 元数据（由 archiver 填充） =====
    content_type: Optional[str] = None
    """响应 Content-Type（不含 charset），如 application/json"""

    response_timestamp: Optional[float] = None
    """响应到达时间戳，用于计算请求耗时"""

    # ===== 调试信息（由 Hook 填充） =====
    call_stack: Optional[str] = None
    """JS 调用栈，多行文本，用于追溯请求发起位置"""

    resource_type: Optional[str] = None
    """资源类型: xhr/fetch/script/stylesheet/image/document 等"""

    @staticmethod
    def from_dict(data: Dict) -> "RequestRecord":
        timestamp = data.get("timestamp")
        if timestamp is None:
            timestamp_value = 0.0
        else:
            try:
                timestamp_value = float(timestamp)
            except Exception:
                timestamp_value = 0.0

        return RequestRecord(
            id=str(data.get("id") or ""),
            timestamp=timestamp_value,
            method=str(data.get("method") or ""),
            url=str(data.get("url") or ""),
            headers=data.get("headers") or data.get("request_headers") or {},
            post_data=data.get("post_data") if data.get("post_data") is not None else data.get("request_body"),
            status=data.get("status") if data.get("status") is not None else data.get("status_code"),
            response_headers=data.get("response_headers"),
            response_body_path=data.get("response_body_path"),
            response_size=data.get("response_size"),
            content_type=data.get("content_type"),
            response_timestamp=data.get("response_timestamp"),
            call_stack=data.get("call_stack"),
            resource_type=data.get("resource_type"),
        )

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "post_data": self.post_data,
            "status": self.status,
            "response_headers": self.response_headers,
            "response_body_path": self.response_body_path,
            "response_size": self.response_size,
            "content_type": self.content_type,
            "response_timestamp": self.response_timestamp,
            "call_stack": self.call_stack,
            "resource_type": self.resource_type,
        }
