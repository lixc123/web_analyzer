"""请求存储服务"""
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid
import threading

from backend.models.unified_request import UnifiedRequest, RequestSource


class RequestStorage:
    """请求存储服务"""

    MAX_REQUESTS = 10000  # 最多保留10000个请求记录

    def __init__(self):
        self.requests: List[Dict[str, Any]] = []
        self.requests_by_id: Dict[str, Dict[str, Any]] = {}  # 按ID索引的请求字典
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
        """查询请求"""
        with self._lock:
            filtered = self.requests.copy()

        # 按来源过滤
        if source:
            filtered = [r for r in filtered if r.get('source') == source]

        # 按平台过滤
        if platform:
            filtered = [
                r for r in filtered
                if r.get('device_info', {}).get('platform') == platform
            ]

        # 排序（最新的在前）
        filtered = sorted(filtered, key=lambda x: x.get('timestamp', 0), reverse=True)

        # 分页
        return filtered[offset:offset + limit]

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
                request['response_size'] = response_data.get('content_length')
                # 使用已计算的响应时间，不重复计算
                request['response_time'] = response_data.get('response_time')
                return True
        return False

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
