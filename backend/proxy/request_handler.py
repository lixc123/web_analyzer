"""
请求处理器
"""

from typing import Callable
from mitmproxy import http
import logging
from .device_detector import DeviceDetector

logger = logging.getLogger(__name__)


class RequestInterceptor:
    """请求拦截器"""

    # 请求体和响应体的最大长度限制（字符数）
    MAX_BODY_LENGTH = 10000

    def __init__(self, on_request: Callable, on_response: Callable):
        """
        初始化拦截器

        Args:
            on_request: 请求回调函数
            on_response: 响应回调函数
        """
        self.on_request = on_request
        self.on_response = on_response

    def _get_request_body(self, request) -> str:
        """获取请求体，限制大小"""
        if not request.content:
            return ''

        try:
            body = request.get_text()
            if len(body) > self.MAX_BODY_LENGTH:
                return body[:self.MAX_BODY_LENGTH] + f'\n... [请求体已截断，仅显示前{self.MAX_BODY_LENGTH}字符]'
            return body
        except (UnicodeDecodeError, AttributeError):
            return '[二进制数据]'

    def _get_response_body(self, response) -> str:
        """获取响应体，限制大小"""
        if not response.content:
            return ''

        try:
            body = response.get_text()
            if len(body) > self.MAX_BODY_LENGTH:
                return body[:self.MAX_BODY_LENGTH] + f'\n... [响应体已截断，仅显示前{self.MAX_BODY_LENGTH}字符]'
            return body
        except (UnicodeDecodeError, AttributeError):
            return '[二进制数据]'

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

            # 提取请求信息
            request_data = {
                'id': request_id,
                'method': flow.request.method,
                'url': flow.request.pretty_url,
                'headers': dict(flow.request.headers),
                'body': self._get_request_body(flow.request),
                'timestamp': flow.request.timestamp_start,
                'device': device_info
            }

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

            # 提取响应信息
            response_data = {
                'url': flow.request.pretty_url,
                'status_code': flow.response.status_code,
                'headers': dict(flow.response.headers),
                'body': self._get_response_body(flow.response),
                'content_length': len(flow.response.content) if flow.response.content else 0,
                'timestamp': flow.response.timestamp_end,
                'response_time': response_time
            }

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
