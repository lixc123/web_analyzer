"""过滤规则管理API"""
from fastapi import APIRouter, HTTPException
from typing import List
import uuid

from backend.proxy.filters import FilterRule
from backend.proxy.service_manager import ProxyServiceManager

router = APIRouter()


@router.get("/rules")
async def get_rules() -> List[FilterRule]:
    """获取所有过滤规则"""
    manager = ProxyServiceManager.get_instance()
    request_filter = manager.get_filter()
    return request_filter.get_rules()


@router.post("/rules")
async def add_rule(rule: FilterRule):
    """添加新的过滤规则"""
    manager = ProxyServiceManager.get_instance()
    request_filter = manager.get_filter()

    # 生成唯一ID
    if not rule.id:
        rule.id = str(uuid.uuid4())

    request_filter.add_rule(rule)
    return {"status": "success", "rule": rule}


@router.put("/rules/{rule_id}")
async def update_rule(rule_id: str, rule: FilterRule):
    """更新过滤规则"""
    manager = ProxyServiceManager.get_instance()
    request_filter = manager.get_filter()

    # 确保ID匹配
    rule.id = rule_id
    request_filter.update_rule(rule_id, rule)
    return {"status": "success", "rule": rule}


@router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: str):
    """删除过滤规则"""
    manager = ProxyServiceManager.get_instance()
    request_filter = manager.get_filter()

    request_filter.remove_rule(rule_id)
    return {"status": "success", "message": "规则已删除"}
