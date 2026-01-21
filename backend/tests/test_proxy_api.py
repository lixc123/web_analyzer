"""代理服务API测试"""
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


class TestProxyAPI:
    """代理服务API测试"""

    def test_get_proxy_status(self):
        """测试获取代理状态"""
        response = client.get("/api/v1/proxy/status")
        assert response.status_code == 200
        data = response.json()
        assert "running" in data
        assert "host" in data
        assert "port" in data

    def test_get_local_ip(self):
        """测试获取本机IP"""
        response = client.get("/api/v1/proxy/local-ip")
        assert response.status_code == 200
        data = response.json()
        assert "ip" in data
        assert len(data["ip"]) > 0

    def test_get_devices(self):
        """测试获取设备列表"""
        response = client.get("/api/v1/proxy/devices")
        assert response.status_code == 200
        data = response.json()
        assert "devices" in data
        assert "total" in data
        assert isinstance(data["devices"], list)

    def test_get_statistics(self):
        """测试获取统计数据"""
        response = client.get("/api/v1/proxy/statistics")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict)

    def test_get_requests(self):
        """测试获取请求列表"""
        response = client.get("/api/v1/proxy/requests")
        assert response.status_code == 200
        data = response.json()
        assert "requests" in data
        assert "total" in data
        assert isinstance(data["requests"], list)

    def test_get_requests_with_filters(self):
        """测试带过滤条件的请求列表"""
        response = client.get("/api/v1/proxy/requests?limit=10&offset=0")
        assert response.status_code == 200
        data = response.json()
        assert len(data["requests"]) <= 10

    def test_export_requests_har(self):
        """测试导出HAR格式"""
        response = client.get("/api/v1/proxy/requests/export?format=har&limit=10")
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/json"

    def test_export_requests_csv(self):
        """测试导出CSV格式"""
        response = client.get("/api/v1/proxy/requests/export?format=csv&limit=10")
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/csv; charset=utf-8"

    def test_export_invalid_format(self):
        """测试无效的导出格式"""
        response = client.get("/api/v1/proxy/requests/export?format=invalid")
        assert response.status_code == 400


class TestCertAPI:
    """证书管理API测试"""

    def test_get_cert_status(self):
        """测试获取证书状态"""
        response = client.get("/api/v1/proxy/cert/status")
        assert response.status_code == 200
        data = response.json()
        assert "exists" in data
        assert "path" in data

    def test_get_cert_info(self):
        """测试获取证书详细信息"""
        response = client.get("/api/v1/proxy/cert/info")
        assert response.status_code == 200
        data = response.json()
        # 可能返回错误信息或证书信息
        assert isinstance(data, dict)

    def test_check_cert_expiry(self):
        """测试检查证书过期状态"""
        response = client.get("/api/v1/proxy/cert/expiry-check")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "message" in data
        assert data["status"] in ["valid", "expiring_soon", "expired", "error"]

    def test_get_cert_instructions(self):
        """测试获取证书安装说明（需要代理运行）"""
        # 这个测试可能失败，因为代理可能未运行
        response = client.get("/api/v1/proxy/cert/instructions")
        # 允许400错误（代理未运行）
        assert response.status_code in [200, 400]

    def test_download_cert(self):
        """测试下载证书"""
        response = client.get("/api/v1/proxy/cert/download")
        # 可能返回404（证书不存在）或200（成功）
        assert response.status_code in [200, 404]


class TestFirewallAPI:
    """防火墙检查API测试"""

    def test_get_firewall_status(self):
        """测试获取防火墙状态"""
        response = client.get("/api/v1/proxy/firewall/status")
        assert response.status_code == 200
        data = response.json()
        assert "supported" in data
        assert "enabled" in data or data["enabled"] is None

    def test_check_firewall_port(self):
        """测试检查端口防火墙规则"""
        response = client.get("/api/v1/proxy/firewall/check-port?port=8888")
        assert response.status_code == 200
        data = response.json()
        assert "supported" in data
        assert "port" in data

    def test_get_firewall_recommendations(self):
        """测试获取防火墙配置建议"""
        response = client.get("/api/v1/proxy/firewall/recommendations")
        assert response.status_code == 200
        data = response.json()
        assert "port" in data
        assert "recommendations" in data
        assert isinstance(data["recommendations"], list)


class TestFilterAPI:
    """过滤规则API测试"""

    def test_get_rules(self):
        """测试获取过滤规则列表"""
        response = client.get("/api/v1/filters/rules")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_add_and_delete_rule(self):
        """测试添加和删除过滤规则"""
        # 添加规则
        rule_data = {
            "id": "test-rule-123",
            "name": "测试规则",
            "type": "exclude",
            "pattern": "*.test.com",
            "enabled": True
        }
        response = client.post("/api/v1/filters/rules", json=rule_data)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

        # 删除规则
        response = client.delete(f"/api/v1/filters/rules/{rule_data['id']}")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

    def test_update_rule(self):
        """测试更新过滤规则"""
        # 先添加规则
        rule_data = {
            "id": "test-rule-456",
            "name": "测试规则",
            "type": "exclude",
            "pattern": "*.test.com",
            "enabled": True
        }
        client.post("/api/v1/filters/rules", json=rule_data)

        # 更新规则
        updated_data = {
            "id": "test-rule-456",
            "name": "更新后的规则",
            "type": "include",
            "pattern": "*.updated.com",
            "enabled": False
        }
        response = client.put(f"/api/v1/filters/rules/{rule_data['id']}", json=updated_data)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

        # 清理
        client.delete(f"/api/v1/filters/rules/{rule_data['id']}")


class TestHealthCheck:
    """健康检查测试"""

    def test_root_endpoint(self):
        """测试根路径"""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] == "running"

    def test_health_check(self):
        """测试健康检查"""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    def test_api_health_check(self):
        """测试API健康检查"""
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
