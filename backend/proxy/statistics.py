"""
请求统计功能
"""

from typing import Dict
from datetime import datetime


class RequestStatistics:
    """请求统计类"""

    def __init__(self):
        self.total_requests = 0
        self.success_requests = 0
        self.failed_requests = 0
        self.total_upload_bytes = 0
        self.total_download_bytes = 0
        self.response_times = []
        self.source_stats = {}  # 按来源统计
        self.domain_stats = {}  # 按域名统计

    def record_request(self, request_data: dict):
        """记录单个请求的统计信息"""
        self.total_requests += 1

        # 统计上传流量
        if 'body' in request_data and request_data['body']:
            self.total_upload_bytes += len(request_data['body'])

        # 提取域名
        url = request_data.get('url', '')
        if url:
            try:
                from urllib.parse import urlparse
                domain = urlparse(url).netloc
                self.domain_stats[domain] = self.domain_stats.get(domain, 0) + 1
            except:
                pass

    def record_response(self, response_data: dict):
        """记录响应统计信息"""
        # 统计成功/失败
        status_code = response_data.get('status_code', 0)
        if 200 <= status_code < 400:
            self.success_requests += 1
        else:
            self.failed_requests += 1

        # 统计下载流量
        content_length = response_data.get('content_length', 0)
        self.total_download_bytes += content_length

    def get_summary(self) -> dict:
        """获取统计摘要"""
        avg_response_time = sum(self.response_times) / len(self.response_times) if self.response_times else 0

        return {
            'total_requests': self.total_requests,
            'success_requests': self.success_requests,
            'failed_requests': self.failed_requests,
            'total_upload_bytes': self.total_upload_bytes,
            'total_download_bytes': self.total_download_bytes,
            'average_response_time': avg_response_time,
            'source_stats': self.source_stats,
            'domain_stats': self.domain_stats
        }

    def reset(self):
        """重置统计数据"""
        self.__init__()
