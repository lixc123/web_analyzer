import pytest
import requests
from backend.proxy.service_manager import ProxyServiceManager


class TestE2E:
    def test_http_capture(self):
        """测试HTTP请求捕获"""
        manager = ProxyServiceManager()
        manager.start(port=8891)

        proxies = {"http": "http://127.0.0.1:8891"}
        response = requests.get("http://httpbin.org/get", proxies=proxies)
        assert response.status_code == 200

        stats = manager.get_statistics()
        assert stats["total_requests"] > 0
        manager.stop()

    def test_filter_rules(self):
        """测试过滤规则"""
        manager = ProxyServiceManager()
        manager.start(port=8892)

        from backend.proxy.filters import FilterRule
        manager.filter.add_rule(FilterRule(pattern="*.blocked.com", type="blacklist"))

        proxies = {"http": "http://127.0.0.1:8892"}
        requests.get("http://allowed.com", proxies=proxies)
        requests.get("http://test.blocked.com", proxies=proxies)

        manager.stop()
