"""
请求处理器
"""

from typing import Callable
from mitmproxy import http


class RequestInterceptor:
    """请求拦截器"""

    def __init__(self, on_request: Callable, on_response: Callable):
        """
        初始化拦截器

        Args:
            on_request: 请求回调函数
            on_response: 响应回调函数
        """
        self.on_request = on_request
        self.on_response = on_response

    def request(self, flow: http.HTTPFlow):
        """拦截HTTP请求"""
        try:
            # 提取请求信息
            request_data = {
                'method': flow.request.method,
                'url': flow.request.pretty_url,
                'headers': dict(flow.request.headers),
                'body': flow.request.get_text() if flow.request.content else '',
                'timestamp': flow.request.timestamp_start
            }

            # 调用回调函数
            if self.on_request:
                try:
                    self.on_request(request_data)
                except Exception as e:
                    print(f"请求回调函数执行错误: {e}")
        except Exception as e:
            print(f"请求拦截错误: {e}")

    def response(self, flow: http.HTTPFlow):
        """拦截HTTP响应"""
        try:
            # 提取响应信息
            response_body = ''
            if flow.response.content:
                try:
                    response_body = flow.response.get_text()
                    # 限制响应体大小为10000字符
                    if len(response_body) > 10000:
                        response_body = response_body[:10000]
                except:
                    response_body = '[二进制数据]'

            response_data = {
                'url': flow.request.pretty_url,
                'status_code': flow.response.status_code,
                'headers': dict(flow.response.headers),
                'body': response_body,
                'content_length': len(flow.response.content) if flow.response.content else 0,
                'timestamp': flow.response.timestamp_end
            }

            # 调用回调函数
            if self.on_response:
                try:
                    self.on_response(response_data)
                except Exception as e:
                    print(f"响应回调函数执行错误: {e}")
        except Exception as e:
            print(f"响应拦截错误: {e}")
