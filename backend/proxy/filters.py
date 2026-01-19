"""请求过滤器模块"""
import re
from typing import List, Optional
from pydantic import BaseModel
import threading
import logging

logger = logging.getLogger(__name__)


class FilterRule(BaseModel):
    """过滤规则数据模型"""
    id: str
    name: str
    type: str  # "include" 或 "exclude"
    pattern: str
    enabled: bool = True


class RequestFilter:
    """请求过滤器"""

    def __init__(self):
        self.rules: List[FilterRule] = []
        self._lock = threading.Lock()

    def add_rule(self, rule: FilterRule):
        """添加过滤规则"""
        with self._lock:
            self.rules.append(rule)

    def remove_rule(self, rule_id: str):
        """删除过滤规则"""
        with self._lock:
            self.rules = [r for r in self.rules if r.id != rule_id]

    def update_rule(self, rule_id: str, rule: FilterRule):
        """更新过滤规则"""
        with self._lock:
            for i, r in enumerate(self.rules):
                if r.id == rule_id:
                    self.rules[i] = rule
                    break

    def get_rules(self) -> List[FilterRule]:
        """获取所有规则"""
        with self._lock:
            return self.rules.copy()

    def should_capture(self, url: str, method: str = "GET") -> bool:
        """判断请求是否应该被捕获"""
        with self._lock:
            rules_copy = self.rules.copy()

        # 如果没有规则，默认捕获所有请求
        if not rules_copy:
            return True

        # 检查是否有 include 规则
        include_rules = [r for r in rules_copy if r.enabled and r.type == "include"]

        # 如果有 include 规则，先检查是否匹配
        if include_rules:
            matched_include = False
            for rule in include_rules:
                if self._match_pattern(url, rule.pattern):
                    matched_include = True
                    break

            # 如果没有匹配任何 include 规则，直接拒绝
            if not matched_include:
                return False

        # 检查 exclude 规则（黑名单）
        for rule in rules_copy:
            if not rule.enabled or rule.type != "exclude":
                continue
            if self._match_pattern(url, rule.pattern):
                return False

        # 通过所有检查，允许捕获
        return True

    def _match_pattern(self, url: str, pattern: str) -> bool:
        """匹配模式"""
        # 支持通配符
        if "*" in pattern:
            pattern = pattern.replace(".", r"\.")
            pattern = pattern.replace("*", ".*")
            try:
                return bool(re.search(pattern, url))
            except re.error as e:
                logger.error(f"正则表达式编译失败: {e}, pattern: {pattern}")
                return False

        # 支持正则表达式
        try:
            return bool(re.search(pattern, url))
        except re.error as e:
            logger.error(f"正则表达式匹配失败: {e}, pattern: {pattern}")
            return False
