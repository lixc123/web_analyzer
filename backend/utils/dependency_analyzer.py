"""请求依赖关系分析工具"""
from typing import List, Dict, Any, Set, Tuple
import json

class DependencyAnalyzer:
    """分析请求间的依赖关系"""

    def analyze_dependencies(self, requests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析请求依赖关系"""
        sorted_requests = sorted(requests, key=lambda x: x.get('timestamp', 0))

        nodes = []
        edges = []

        for i, req in enumerate(sorted_requests):
            nodes.append({
                'id': req.get('id', f'req_{i}'),
                'url': req.get('url', ''),
                'method': req.get('method', 'GET'),
                'timestamp': req.get('timestamp', 0)
            })

        # 分析数据传递关系
        for i in range(len(sorted_requests)):
            for j in range(i + 1, len(sorted_requests)):
                if self._has_data_dependency(sorted_requests[i], sorted_requests[j]):
                    edges.append({
                        'source': nodes[i]['id'],
                        'target': nodes[j]['id'],
                        'type': 'data_flow'
                    })

        return {'nodes': nodes, 'edges': edges}

    def _has_data_dependency(self, req1: Dict, req2: Dict) -> bool:
        """检测两个请求间是否存在数据依赖"""
        response1 = req1.get('response', {})
        request2_params = self._extract_params(req2)

        if not response1 or not request2_params:
            return False

        response_values = self._extract_values(response1)

        for param_value in request2_params.values():
            if param_value in response_values:
                return True

        return False

    def _extract_params(self, req: Dict) -> Dict[str, str]:
        """提取请求参数"""
        params = {}

        url = req.get('url', '')
        if '?' in url:
            query = url.split('?')[1]
            for pair in query.split('&'):
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    params[k] = v

        body = req.get('request_body')
        if body:
            try:
                body_data = json.loads(body) if isinstance(body, str) else body
                if isinstance(body_data, dict):
                    params.update(body_data)
            except:
                pass

        return params

    def _extract_values(self, data: Any) -> Set[str]:
        """递归提取所有值"""
        values = set()

        if isinstance(data, dict):
            for v in data.values():
                values.update(self._extract_values(v))
        elif isinstance(data, list):
            for item in data:
                values.update(self._extract_values(item))
        elif isinstance(data, (str, int, float)):
            values.add(str(data))

        return values
