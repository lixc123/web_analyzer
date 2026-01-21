import pytest
import uuid
from backend.proxy.filters import FilterRule, RequestFilter


class TestRequestFilter:
    def test_add_rule(self):
        """测试添加规则"""
        filter = RequestFilter()
        rule = FilterRule(
            id=str(uuid.uuid4()),
            name="测试规则",
            pattern="*.example.com",
            type="exclude",
            enabled=True
        )
        filter.add_rule(rule)
        assert len(filter.rules) >= 1  # 可能从数据库加载了其他规则

    def test_exclude_match(self):
        """测试排除规则匹配"""
        filter = RequestFilter()
        rule_id = str(uuid.uuid4())
        filter.add_rule(FilterRule(
            id=rule_id,
            name="排除广告",
            pattern="*.ads.com",
            type="exclude",
            enabled=True
        ))
        assert not filter.should_capture("http://tracker.ads.com/pixel")
        assert filter.should_capture("http://example.com/page")
        
        # 清理
        filter.remove_rule(rule_id)

    def test_include_match(self):
        """测试包含规则匹配"""
        filter = RequestFilter()
        rule_id = str(uuid.uuid4())
        filter.add_rule(FilterRule(
            id=rule_id,
            name="只包含API",
            pattern="api.example.com",
            type="include",
            enabled=True
        ))
        assert filter.should_capture("http://api.example.com/data")
        assert not filter.should_capture("http://other.com/data")
        
        # 清理
        filter.remove_rule(rule_id)

    def test_regex_pattern(self):
        """测试正则表达式模式"""
        filter = RequestFilter()
        rule_id = str(uuid.uuid4())
        filter.add_rule(FilterRule(
            id=rule_id,
            name="排除图片",
            pattern=r".*\.jpg$",
            type="exclude",
            enabled=True
        ))
        assert not filter.should_capture("http://example.com/image.jpg")
        assert filter.should_capture("http://example.com/page.html")
        
        # 清理
        filter.remove_rule(rule_id)

    def test_rule_persistence(self):
        """测试规则持久化"""
        # 创建新的过滤器并添加规则
        filter1 = RequestFilter()
        rule_id = str(uuid.uuid4())
        rule = FilterRule(
            id=rule_id,
            name="持久化测试",
            pattern="*.test.com",
            type="exclude",
            enabled=True
        )
        filter1.add_rule(rule)
        
        # 创建新的过滤器实例，应该能从数据库加载规则
        filter2 = RequestFilter()
        loaded_rules = [r for r in filter2.get_rules() if r.id == rule_id]
        assert len(loaded_rules) == 1
        assert loaded_rules[0].name == "持久化测试"
        assert loaded_rules[0].pattern == "*.test.com"
        
        # 清理
        filter2.remove_rule(rule_id)

    def test_update_rule(self):
        """测试更新规则"""
        filter = RequestFilter()
        rule_id = str(uuid.uuid4())
        
        # 添加规则
        rule = FilterRule(
            id=rule_id,
            name="原始规则",
            pattern="*.old.com",
            type="exclude",
            enabled=True
        )
        filter.add_rule(rule)
        
        # 更新规则
        updated_rule = FilterRule(
            id=rule_id,
            name="更新后的规则",
            pattern="*.new.com",
            type="include",
            enabled=False
        )
        filter.update_rule(rule_id, updated_rule)
        
        # 验证更新
        rules = [r for r in filter.get_rules() if r.id == rule_id]
        assert len(rules) == 1
        assert rules[0].name == "更新后的规则"
        assert rules[0].pattern == "*.new.com"
        assert rules[0].type == "include"
        assert rules[0].enabled == False
        
        # 清理
        filter.remove_rule(rule_id)

    def test_disabled_rule(self):
        """测试禁用的规则不生效"""
        filter = RequestFilter()
        rule_id = str(uuid.uuid4())
        
        # 添加禁用的规则
        filter.add_rule(FilterRule(
            id=rule_id,
            name="禁用规则",
            pattern="*.disabled.com",
            type="exclude",
            enabled=False
        ))
        
        # 禁用的规则不应该生效
        assert filter.should_capture("http://test.disabled.com/page")
        
        # 清理
        filter.remove_rule(rule_id)
