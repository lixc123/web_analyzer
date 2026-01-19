"""统一请求数据模型"""
from enum import Enum
from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel


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
    timestamp: float

    # 响应信息
    status_code: Optional[int] = None
    response_headers: Optional[Dict[str, str]] = None
    response_body: Optional[str] = None
    response_size: Optional[int] = None
    response_time: Optional[float] = None

    # 元数据
    content_type: Optional[str] = None
    is_https: bool = False
    host: Optional[str] = None
    path: Optional[str] = None
    tags: Optional[list] = None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return self.model_dump()

    @staticmethod
    def from_proxy_request(request_data: Dict[str, Any], response_data: Optional[Dict[str, Any]] = None) -> 'UnifiedRequest':
        """从代理请求数据创建 UnifiedRequest"""
        # 识别来源类型
        device_info = request_data.get('device', {})
        platform = device_info.get('platform', 'unknown')

        if platform == 'iOS':
            source = RequestSource.MOBILE_IOS
        elif platform == 'Android':
            source = RequestSource.MOBILE_ANDROID
        elif platform in ['Windows', 'macOS', 'Linux']:
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

        # 创建统一请求对象
        unified_request = UnifiedRequest(
            id=request_data.get('id'),
            source=source,
            device_info=device_info,
            method=request_data.get('method', 'GET'),
            url=url,
            headers=request_data.get('headers', {}),
            body=request_data.get('body'),
            timestamp=request_data.get('timestamp', datetime.now().timestamp()),
            is_https=is_https,
            host=host,
            path=path,
            content_type=request_data.get('headers', {}).get('Content-Type')
        )

        # 添加响应信息
        if response_data:
            unified_request.status_code = response_data.get('status_code')
            unified_request.response_headers = response_data.get('headers', {})
            unified_request.response_body = response_data.get('body')
            unified_request.response_size = response_data.get('content_length')
            # 统一使用已计算的响应时间
            unified_request.response_time = response_data.get('response_time')

        return unified_request
