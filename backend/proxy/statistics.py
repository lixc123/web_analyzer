"""
请求统计功能
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from urllib.parse import urlparse
from collections import deque
import threading
import logging

logger = logging.getLogger(__name__)


class RequestStatistics:
    """请求统计类"""

    MAX_RESPONSE_TIMES = 1000  # 最多保留1000个响应时间样本
    MAX_DOMAIN_STATS = 500  # 最多保留500个域名统计
    MAX_RECENT_ERRORS = 80  # 最多保留80条最近错误（用于诊断）

    def __init__(self):
        self.total_requests = 0
        self.total_responses = 0
        self.success_requests = 0
        self.failed_requests = 0
        self.total_errors = 0
        self.total_upload_bytes = 0
        self.total_download_bytes = 0
        self.response_times = deque(maxlen=self.MAX_RESPONSE_TIMES)
        self.source_stats = {}  # 按来源统计
        self.domain_stats = {}  # 按域名统计
        self.recent_errors = deque(maxlen=self.MAX_RECENT_ERRORS)
        self._lock = threading.Lock()

    def record_request(self, request_data: dict):
        """记录单个请求的统计信息"""
        with self._lock:
            self.total_requests += 1

            # 按来源统计（proxy capture）
            try:
                source = request_data.get("source") or request_data.get("device", {}).get("platform") or "unknown"
                source = str(source)
                self.source_stats[source] = self.source_stats.get(source, 0) + 1
            except Exception:
                pass

            # 统计上传流量
            if 'body' in request_data and request_data['body']:
                self.total_upload_bytes += len(request_data['body'])

            # 提取域名
            url = request_data.get('url', '')
            if url:
                try:
                    domain = urlparse(url).netloc
                    self.domain_stats[domain] = self.domain_stats.get(domain, 0) + 1

                    # 限制域名统计数量，移除请求数最少的域名
                    if len(self.domain_stats) > self.MAX_DOMAIN_STATS:
                        min_domain = min(self.domain_stats, key=self.domain_stats.get)
                        del self.domain_stats[min_domain]
                except Exception as e:
                    logger.warning(f"URL解析失败: {e}")

    def record_response(self, response_data: dict):
        """记录响应统计信息"""
        with self._lock:
            self.total_responses += 1

            # 统计成功/失败
            status_code = response_data.get('status_code', 0)
            if 200 <= status_code < 400:
                self.success_requests += 1
            else:
                self.failed_requests += 1

            # 统计下载流量
            content_length = response_data.get('content_length', 0)
            self.total_download_bytes += content_length

            # 记录响应时间（deque自动限制大小）
            if 'response_time' in response_data:
                self.response_times.append(response_data['response_time'])

    def record_error(self, error_data: Dict[str, Any]):
        """记录代理抓包错误（TLS握手/连接中断等）。"""
        with self._lock:
            self.total_errors += 1
            item = dict(error_data or {})
            if "timestamp" not in item:
                item["timestamp"] = datetime.now().timestamp()
            self.recent_errors.append(item)

    def get_summary(self) -> dict:
        """获取统计摘要"""
        with self._lock:
            avg_response_time = sum(self.response_times) / len(self.response_times) if self.response_times else 0

            return {
                'total_requests': self.total_requests,
                'total_responses': self.total_responses,
                'success_requests': self.success_requests,
                'failed_requests': self.failed_requests,
                'pending_requests': self.total_requests - self.total_responses,
                'total_errors': self.total_errors,
                'recent_errors': list(self.recent_errors),
                'total_upload_bytes': self.total_upload_bytes,
                'total_download_bytes': self.total_download_bytes,
                'average_response_time': avg_response_time,
                'source_stats': self.source_stats.copy(),
                'domain_stats': self.domain_stats.copy()
            }

    def reset(self):
        """重置统计数据"""
        with self._lock:
            self.total_requests = 0
            self.total_responses = 0
            self.success_requests = 0
            self.failed_requests = 0
            self.total_errors = 0
            self.total_upload_bytes = 0
            self.total_download_bytes = 0
            self.response_times = deque(maxlen=self.MAX_RESPONSE_TIMES)
            self.source_stats = {}
            self.domain_stats = {}
            self.recent_errors = deque(maxlen=self.MAX_RECENT_ERRORS)
