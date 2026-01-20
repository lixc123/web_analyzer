"""
Hook记录数据模型
"""

from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class HookRecord(BaseModel):
    """Hook记录模型"""
    hook_id: str = Field(..., description="Hook记录ID")
    process_name: str = Field(..., description="进程名称")
    pid: int = Field(..., description="进程ID")
    hook_type: str = Field(..., description="Hook类型: network/crypto/file/registry")
    api_name: str = Field(..., description="API函数名")
    args: Dict[str, Any] = Field(default_factory=dict, description="函数参数")
    return_value: Optional[Any] = Field(None, description="返回值")
    timestamp: datetime = Field(default_factory=datetime.now, description="时间戳")
    stack_trace: Optional[str] = Field(None, description="调用栈")
    thread_id: Optional[int] = Field(None, description="线程ID")

    class Config:
        json_schema_extra = {
            "example": {
                "hook_id": "hook_123456",
                "process_name": "chrome.exe",
                "pid": 12345,
                "hook_type": "network",
                "api_name": "send",
                "args": {
                    "socket": 1234,
                    "data": "GET / HTTP/1.1",
                    "length": 14
                },
                "return_value": 14,
                "timestamp": "2026-01-20T10:30:00",
                "stack_trace": None,
                "thread_id": 5678
            }
        }


class ProcessInfo(BaseModel):
    """进程信息模型"""
    pid: int = Field(..., description="进程ID")
    name: str = Field(..., description="进程名称")
    path: Optional[str] = Field(None, description="进程路径")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="进程参数")


class HookSession(BaseModel):
    """Hook会话模型"""
    session_id: str = Field(..., description="会话ID")
    process_name: str = Field(..., description="进程名称")
    pid: int = Field(..., description="进程ID")
    script_name: str = Field(..., description="脚本名称")
    started_at: datetime = Field(default_factory=datetime.now, description="开始时间")
    ended_at: Optional[datetime] = Field(None, description="结束时间")
    record_count: int = Field(default=0, description="记录数量")
    status: str = Field(default="active", description="状态: active/stopped/error")


class HookScriptTemplate(BaseModel):
    """Hook脚本模板"""
    template_id: str = Field(..., description="模板ID")
    name: str = Field(..., description="模板名称")
    description: str = Field(..., description="模板描述")
    category: str = Field(..., description="分类: network/crypto/file/registry/custom")
    script_code: str = Field(..., description="脚本代码")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="模板参数")

    class Config:
        json_schema_extra = {
            "example": {
                "template_id": "template_network_basic",
                "name": "网络API监控",
                "description": "监控WinHTTP、WinINet和Socket API",
                "category": "network",
                "script_code": "// Frida script code here",
                "parameters": {}
            }
        }
