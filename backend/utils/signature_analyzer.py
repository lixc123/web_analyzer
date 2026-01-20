"""
参数签名分析工具

自动识别请求中的签名参数，分析签名算法特征
"""

import re
import hashlib
from typing import List, Dict, Any, Optional
from collections import Counter


class SignatureAnalyzer:
    """签名分析器"""

    # 常见签名参数名
    SIGNATURE_PARAMS = [
        'sign', 'signature', 'sig', '_sign', '_signature',
        'token', '_token', 'auth', 'authorization',
        'hash', 'checksum', 'verify', 'mac', 'hmac'
    ]

    # 常见时间戳参数名
    TIMESTAMP_PARAMS = [
        'timestamp', 'ts', 'time', '_t', 't',
        'nonce', 'random', 'rand'
    ]

    def __init__(self):
        self.signature_patterns = {}
        self.timestamp_patterns = {}

    def analyze_requests(self, requests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        分析一组请求记录，识别签名模式

        Args:
            requests: 请求记录列表

        Returns:
            分析结果
        """
        results = {
            'total_requests': len(requests),
            'signature_params': [],
            'timestamp_params': [],
            'algorithm_hints': [],
            'patterns': []
        }

        # 收集所有参数
        all_params = []
        for req in requests:
            params = self._extract_params(req)
            all_params.extend(params.keys())

        # 统计参数频率
        param_counter = Counter(all_params)

        # 识别签名参数
        for param, count in param_counter.items():
            if self._is_signature_param(param):
                results['signature_params'].append({
                    'name': param,
                    'frequency': count,
                    'confidence': self._calculate_confidence(param, 'signature')
                })

            if self._is_timestamp_param(param):
                results['timestamp_params'].append({
                    'name': param,
                    'frequency': count,
                    'confidence': self._calculate_confidence(param, 'timestamp')
                })

        # 分析签名算法特征
        for req in requests[:10]:  # 只分析前10个请求
            params = self._extract_params(req)
            for sig_param in results['signature_params']:
                if sig_param['name'] in params:
                    value = params[sig_param['name']]
                    algorithm = self._detect_algorithm(value)
                    if algorithm:
                        results['algorithm_hints'].append({
                            'param': sig_param['name'],
                            'algorithm': algorithm,
                            'value_length': len(value),
                            'sample': value[:20] + '...' if len(value) > 20 else value
                        })

        # 分析参数依赖关系
        results['patterns'] = self._analyze_patterns(requests)

        return results

    def _extract_params(self, request: Dict[str, Any]) -> Dict[str, str]:
        """从请求中提取参数"""
        params = {}

        # 从URL查询参数提取
        url = request.get('url', '')
        if '?' in url:
            query_string = url.split('?', 1)[1]
            for pair in query_string.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    params[key] = value

        # 从POST数据提取
        post_data = request.get('post_data', '')
        if post_data:
            try:
                import json
                data = json.loads(post_data)
                if isinstance(data, dict):
                    params.update(data)
            except:
                # 尝试解析表单数据
                for pair in post_data.split('&'):
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        params[key] = value

        return params

    def _is_signature_param(self, param_name: str) -> bool:
        """判断是否为签名参数"""
        param_lower = param_name.lower()
        return any(sig in param_lower for sig in self.SIGNATURE_PARAMS)

    def _is_timestamp_param(self, param_name: str) -> bool:
        """判断是否为时间戳参数"""
        param_lower = param_name.lower()
        return any(ts in param_lower for ts in self.TIMESTAMP_PARAMS)

    def _calculate_confidence(self, param_name: str, param_type: str) -> float:
        """计算参数识别的置信度"""
        param_lower = param_name.lower()

        if param_type == 'signature':
            # 精确匹配
            if param_lower in self.SIGNATURE_PARAMS:
                return 1.0
            # 包含匹配
            for sig in self.SIGNATURE_PARAMS:
                if sig in param_lower:
                    return 0.8
            return 0.5

        elif param_type == 'timestamp':
            if param_lower in self.TIMESTAMP_PARAMS:
                return 1.0
            for ts in self.TIMESTAMP_PARAMS:
                if ts in param_lower:
                    return 0.8
            return 0.5

        return 0.0

    def _detect_algorithm(self, signature_value: str) -> Optional[str]:
        """根据签名值特征检测可能的算法"""
        if not signature_value:
            return None

        length = len(signature_value)

        # MD5: 32字符十六进制
        if length == 32 and re.match(r'^[a-fA-F0-9]{32}$', signature_value):
            return 'MD5'

        # SHA1: 40字符十六进制
        if length == 40 and re.match(r'^[a-fA-F0-9]{40}$', signature_value):
            return 'SHA1'

        # SHA256: 64字符十六进制
        if length == 64 and re.match(r'^[a-fA-F0-9]{64}$', signature_value):
            return 'SHA256'

        # Base64编码（可能是HMAC或其他）
        if re.match(r'^[A-Za-z0-9+/]+=*$', signature_value):
            if length % 4 == 0:
                return 'Base64 (HMAC/RSA/Custom)'

        # JWT格式
        if signature_value.count('.') == 2:
            return 'JWT'

        return 'Unknown/Custom'

    def _analyze_patterns(self, requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """分析签名生成模式"""
        patterns = []

        # 分析参数组合模式
        param_combinations = Counter()
        for req in requests:
            params = self._extract_params(req)
            param_keys = tuple(sorted(params.keys()))
            param_combinations[param_keys] += 1

        # 找出最常见的参数组合
        for combo, count in param_combinations.most_common(3):
            if count > 1:
                patterns.append({
                    'type': 'parameter_combination',
                    'params': list(combo),
                    'frequency': count,
                    'description': f'这些参数经常一起出现，可能参与签名计算'
                })

        return patterns


def analyze_signature(requests: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    便捷函数：分析请求签名

    Args:
        requests: 请求记录列表

    Returns:
        分析结果
    """
    analyzer = SignatureAnalyzer()
    return analyzer.analyze_requests(requests)
