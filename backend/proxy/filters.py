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
    order: int = 0  # 规则顺序


class RequestFilter:
    """请求过滤器"""

    def __init__(self):
        self.rules: List[FilterRule] = []
        self._lock = threading.Lock()
        self._load_rules_from_db()

    def _load_rules_from_db(self):
        """从数据库加载规则"""
        try:
            from backend.app.database import SessionLocal
            from backend.models.filter_rule import FilterRuleModel

            db = SessionLocal()
            try:
                db_rules = db.query(FilterRuleModel).order_by(FilterRuleModel.order).all()
                self.rules = [
                    FilterRule(
                        id=rule.id,
                        name=rule.name,
                        type=rule.type,
                        pattern=rule.pattern,
                        enabled=rule.enabled,
                        order=rule.order
                    )
                    for rule in db_rules
                ]
                logger.info(f"从数据库加载了 {len(self.rules)} 条过滤规则")
            finally:
                db.close()
        except Exception as e:
            logger.error(f"从数据库加载规则失败: {e}")
            self.rules = []

    def _save_rule_to_db(self, rule: FilterRule):
        """保存规则到数据库"""
        try:
            from backend.app.database import SessionLocal
            from backend.models.filter_rule import FilterRuleModel

            db = SessionLocal()
            try:
                db_rule = FilterRuleModel(
                    id=rule.id,
                    name=rule.name,
                    type=rule.type,
                    pattern=rule.pattern,
                    enabled=rule.enabled,
                    order=rule.order
                )
                db.merge(db_rule)  # 使用merge来处理新增和更新
                db.commit()
                logger.info(f"规则 {rule.id} 已保存到数据库")
            finally:
                db.close()
        except Exception as e:
            logger.error(f"保存规则到数据库失败: {e}")

    def _delete_rule_from_db(self, rule_id: str):
        """从数据库删除规则"""
        try:
            from backend.app.database import SessionLocal
            from backend.models.filter_rule import FilterRuleModel

            db = SessionLocal()
            try:
                db.query(FilterRuleModel).filter(FilterRuleModel.id == rule_id).delete()
                db.commit()
                logger.info(f"规则 {rule_id} 已从数据库删除")
            finally:
                db.close()
        except Exception as e:
            logger.error(f"从数据库删除规则失败: {e}")

    def add_rule(self, rule: FilterRule):
        """添加过滤规则"""
        with self._lock:
            # 设置规则顺序
            if rule.order == 0:
                rule.order = len(self.rules)
            self.rules.append(rule)
            self._save_rule_to_db(rule)

    def remove_rule(self, rule_id: str):
        """删除过滤规则"""
        with self._lock:
            self.rules = [r for r in self.rules if r.id != rule_id]
            self._delete_rule_from_db(rule_id)

    def update_rule(self, rule_id: str, rule: FilterRule):
        """更新过滤规则"""
        with self._lock:
            for i, r in enumerate(self.rules):
                if r.id == rule_id:
                    self.rules[i] = rule
                    self._save_rule_to_db(rule)
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
