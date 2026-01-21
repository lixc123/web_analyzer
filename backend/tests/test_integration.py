"""集成测试 - 测试完整的工作流程"""
import pytest
import time
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


class TestProxyWorkflow:
    """代理服务完整工作流程测试"""

    def test_complete_proxy_workflow(self):
        """测试完整的代理服务工作流程"""
        
        # 1. 检查初始状态
        response = client.get("/api/v1/proxy/status")
        assert response.status_code == 200
        initial_status = response.json()
        print(f"初始状态: {initial_status}")

        # 2. 获取本机IP
        response = client.get("/api/v1/proxy/local-ip")
        assert response.status_code == 200
        local_ip = response.json()["ip"]
        print(f"本机IP: {local_ip}")

        # 3. 检查证书状态
        response = client.get("/api/v1/proxy/cert/status")
        assert response.status_code == 200
        cert_status = response.json()
        print(f"证书状态: {cert_status}")

        # 4. 检查防火墙状态
        response = client.get("/api/v1/proxy/firewall/status")
        assert response.status_code == 200
        firewall_status = response.json()
        print(f"防火墙状态: {firewall_status}")

        # 5. 获取设备列表
        response = client.get("/api/v1/proxy/devices")
        assert response.status_code == 200
        devices = response.json()
        print(f"设备数量: {devices['total']}")

        # 6. 获取请求列表
        response = client.get("/api/v1/proxy/requests?limit=10")
        assert response.status_code == 200
        requests = response.json()
        print(f"请求数量: {requests['total']}")

        # 7. 测试导出功能
        response = client.get("/api/v1/proxy/requests/export?format=har&limit=5")
        assert response.status_code == 200
        print("HAR导出成功")

        response = client.get("/api/v1/proxy/requests/export?format=csv&limit=5")
        assert response.status_code == 200
        print("CSV导出成功")


class TestFilterWorkflow:
    """过滤规则完整工作流程测试"""

    def test_filter_crud_workflow(self):
        """测试过滤规则的完整CRUD流程"""
        
        # 1. 获取初始规则列表
        response = client.get("/api/v1/filters/rules")
        assert response.status_code == 200
        initial_rules = response.json()
        initial_count = len(initial_rules)
        print(f"初始规则数量: {initial_count}")

        # 2. 添加新规则
        new_rule = {
            "id": "integration-test-rule",
            "name": "集成测试规则",
            "type": "exclude",
            "pattern": "*.ads.com",
            "enabled": True,
            "order": 0
        }
        response = client.post("/api/v1/filters/rules", json=new_rule)
        assert response.status_code == 200
        print("规则添加成功")

        # 3. 验证规则已添加
        response = client.get("/api/v1/filters/rules")
        assert response.status_code == 200
        rules = response.json()
        assert len(rules) == initial_count + 1
        print(f"当前规则数量: {len(rules)}")

        # 4. 更新规则
        updated_rule = {
            "id": "integration-test-rule",
            "name": "更新后的集成测试规则",
            "type": "include",
            "pattern": "*.api.com",
            "enabled": False,
            "order": 1
        }
        response = client.put("/api/v1/filters/rules/integration-test-rule", json=updated_rule)
        assert response.status_code == 200
        print("规则更新成功")

        # 5. 验证规则已更新
        response = client.get("/api/v1/filters/rules")
        assert response.status_code == 200
        rules = response.json()
        updated = next((r for r in rules if r["id"] == "integration-test-rule"), None)
        assert updated is not None
        assert updated["name"] == "更新后的集成测试规则"
        assert updated["type"] == "include"
        assert updated["enabled"] == False
        print("规则更新验证成功")

        # 6. 删除规则
        response = client.delete("/api/v1/filters/rules/integration-test-rule")
        assert response.status_code == 200
        print("规则删除成功")

        # 7. 验证规则已删除
        response = client.get("/api/v1/filters/rules")
        assert response.status_code == 200
        rules = response.json()
        assert len(rules) == initial_count
        print(f"最终规则数量: {len(rules)}")


class TestCertWorkflow:
    """证书管理完整工作流程测试"""

    def test_cert_management_workflow(self):
        """测试证书管理的完整流程"""
        
        # 1. 获取证书状态
        response = client.get("/api/v1/proxy/cert/status")
        assert response.status_code == 200
        status = response.json()
        print(f"证书存在: {status['exists']}")
        print(f"证书路径: {status['path']}")

        # 2. 获取证书详细信息
        response = client.get("/api/v1/proxy/cert/info")
        assert response.status_code == 200
        info = response.json()
        print(f"证书信息: {info}")

        # 3. 检查证书过期状态
        response = client.get("/api/v1/proxy/cert/expiry-check")
        assert response.status_code == 200
        expiry = response.json()
        print(f"过期检查: {expiry['status']} - {expiry['message']}")

        # 4. 如果证书存在，测试下载
        if status['exists']:
            response = client.get("/api/v1/proxy/cert/download")
            assert response.status_code == 200
            print("证书下载成功")


class TestDataPersistence:
    """数据持久化测试"""

    def test_filter_persistence(self):
        """测试过滤规则持久化"""
        
        # 1. 添加规则
        rule = {
            "id": "persistence-test-rule",
            "name": "持久化测试",
            "type": "exclude",
            "pattern": "*.test.com",
            "enabled": True
        }
        response = client.post("/api/v1/filters/rules", json=rule)
        assert response.status_code == 200

        # 2. 验证规则存在
        response = client.get("/api/v1/filters/rules")
        rules = response.json()
        found = any(r["id"] == "persistence-test-rule" for r in rules)
        assert found
        print("规则持久化验证成功")

        # 3. 清理
        client.delete("/api/v1/filters/rules/persistence-test-rule")


class TestErrorHandling:
    """错误处理测试"""

    def test_invalid_request_id(self):
        """测试无效的请求ID"""
        response = client.get("/api/v1/proxy/request/invalid-id-12345")
        assert response.status_code == 404

    def test_invalid_export_format(self):
        """测试无效的导出格式"""
        response = client.get("/api/v1/proxy/requests/export?format=invalid")
        assert response.status_code == 400

    def test_delete_nonexistent_rule(self):
        """测试删除不存在的规则"""
        response = client.delete("/api/v1/filters/rules/nonexistent-rule")
        # 应该成功（幂等操作）
        assert response.status_code == 200

    def test_invalid_filter_source(self):
        """测试无效的过滤来源"""
        response = client.get("/api/v1/proxy/requests?source=invalid_source")
        assert response.status_code == 400


class TestPerformance:
    """性能测试"""

    def test_api_response_time(self):
        """测试API响应时间"""
        endpoints = [
            "/api/v1/proxy/status",
            "/api/v1/proxy/devices",
            "/api/v1/filters/rules",
            "/api/v1/proxy/cert/status",
            "/health"
        ]

        for endpoint in endpoints:
            start_time = time.time()
            response = client.get(endpoint)
            end_time = time.time()
            
            response_time = (end_time - start_time) * 1000  # 转换为毫秒
            assert response.status_code == 200
            assert response_time < 1000  # 响应时间应小于1秒
            print(f"{endpoint}: {response_time:.2f}ms")

    def test_bulk_filter_operations(self):
        """测试批量过滤规则操作"""
        # 添加多个规则
        rule_ids = []
        for i in range(10):
            rule = {
                "id": f"bulk-test-rule-{i}",
                "name": f"批量测试规则{i}",
                "type": "exclude",
                "pattern": f"*.test{i}.com",
                "enabled": True
            }
            response = client.post("/api/v1/filters/rules", json=rule)
            assert response.status_code == 200
            rule_ids.append(rule["id"])

        # 验证所有规则都已添加
        response = client.get("/api/v1/filters/rules")
        rules = response.json()
        for rule_id in rule_ids:
            assert any(r["id"] == rule_id for r in rules)

        # 清理所有规则
        for rule_id in rule_ids:
            response = client.delete(f"/api/v1/filters/rules/{rule_id}")
            assert response.status_code == 200

        print("批量操作测试完成")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
