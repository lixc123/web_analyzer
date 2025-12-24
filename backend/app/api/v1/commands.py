"""
命令处理API - Web版本qwen-code命令系统
实现/clear, /stats, /model, /help等30+命令功能
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from ...services.auth_service import AuthService
from ...services.session_service import SessionService
from ...services.command_service import CommandService, CommandResult

router = APIRouter()

class ExecuteCommandRequest(BaseModel):
    command: str
    args: List[str] = []
    session_id: Optional[str] = None

class CommandResponse(BaseModel):
    success: bool
    result: Any
    message: str
    command_type: str

def get_command_service():
    return CommandService()

def get_auth_service():
    return AuthService()

def get_session_service():
    return SessionService()

@router.post("/execute", response_model=CommandResponse)
async def execute_command(
    request: ExecuteCommandRequest,
    command_service: CommandService = Depends(get_command_service),
    auth_service: AuthService = Depends(get_auth_service),
    session_service: SessionService = Depends(get_session_service)
):
    """执行Web命令"""
    try:
        # 验证认证状态
        if request.session_id:
            auth_state = auth_service.get_auth_session(request.session_id)
            if not auth_state:
                raise HTTPException(status_code=401, detail="未认证")
        else:
            auth_state = None

        # 执行命令
        result = await command_service.execute_command(
            command=request.command,
            args=request.args,
            auth_state=auth_state,
            session_service=session_service
        )

        return CommandResponse(
            success=result.success,
            result=result.data,
            message=result.message,
            command_type=result.command_type
        )

    except Exception as e:
        return CommandResponse(
            success=False,
            result=None,
            message=f"命令执行失败: {str(e)}",
            command_type="error"
        )

@router.get("/list")
async def list_available_commands():
    """获取可用命令列表"""
    commands = {
        "session": [
            {
                "name": "clear",
                "description": "清除当前会话历史",
                "usage": "/clear",
                "examples": ["/clear"]
            },
            {
                "name": "compress", 
                "description": "压缩会话历史以节省token",
                "usage": "/compress",
                "examples": ["/compress"]
            },
            {
                "name": "stats",
                "description": "显示当前会话统计信息",
                "usage": "/stats",
                "examples": ["/stats"]
            },
            {
                "name": "memory",
                "description": "管理对话记忆",
                "usage": "/memory <action> [content]",
                "examples": ["/memory show", "/memory add '重要信息'", "/memory clear"]
            }
        ],
        "model": [
            {
                "name": "model",
                "description": "切换AI模型",
                "usage": "/model <model_name>",
                "examples": ["/model qwen-coder", "/model qwen-vision"]
            },
            {
                "name": "auth",
                "description": "切换认证方式", 
                "usage": "/auth",
                "examples": ["/auth"]
            }
        ],
        "analysis": [
            {
                "name": "analyze",
                "description": "分析指定内容",
                "usage": "/analyze <type> [target]",
                "examples": ["/analyze code", "/analyze requests session_123"]
            },
            {
                "name": "export",
                "description": "导出分析结果",
                "usage": "/export <format> [session_id]", 
                "examples": ["/export json", "/export csv session_123"]
            }
        ],
        "system": [
            {
                "name": "settings",
                "description": "打开设置面板",
                "usage": "/settings",
                "examples": ["/settings"]
            },
            {
                "name": "theme",
                "description": "切换主题",
                "usage": "/theme <theme>",
                "examples": ["/theme dark", "/theme light"]
            }
        ],
        "help": [
            {
                "name": "help",
                "description": "显示帮助信息",
                "usage": "/help [command]",
                "aliases": ["?"],
                "examples": ["/help", "/help model", "/?"]
            },
            {
                "name": "docs",
                "description": "打开文档",
                "usage": "/docs",
                "examples": ["/docs"]
            }
        ]
    }
    
    return {"commands": commands}

@router.post("/models/switch")
async def switch_model(
    model_id: str,
    reason: str = "user_selection",
    session_id: Optional[str] = None,
    auth_service: AuthService = Depends(get_auth_service),
    command_service: CommandService = Depends(get_command_service)
):
    """切换模型 - Web版/model命令"""
    try:
        if not session_id:
            raise HTTPException(status_code=401, detail="需要认证会话")
        
        auth_state = auth_service.get_auth_session(session_id)
        if not auth_state:
            raise HTTPException(status_code=401, detail="认证会话无效")

        # 执行模型切换
        result = await command_service.switch_model(
            auth_state=auth_state,
            target_model=model_id,
            reason=reason
        )

        if result.success:
            # 更新认证状态中的模型信息
            auth_state.model = model_id
            auth_service.update_auth_session(session_id, auth_state)

        return {
            "success": result.success,
            "message": result.message,
            "current_model": model_id if result.success else auth_state.model,
            "reason": reason
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"模型切换失败: {str(e)}")

@router.get("/session/stats/{session_id}")
async def get_session_stats(
    session_id: str,
    session_service: SessionService = Depends(get_session_service),
    auth_service: AuthService = Depends(get_auth_service)
):
    """获取会话统计信息 - Web版/stats命令"""
    try:
        auth_state = auth_service.get_auth_session(session_id)
        if not auth_state:
            raise HTTPException(status_code=401, detail="认证会话无效")

        stats = session_service.get_session_stats(session_id)
        
        return {
            "session_id": session_id,
            "auth_type": auth_state.auth_type.value,
            "current_model": getattr(auth_state, 'model', 'unknown'),
            "stats": {
                "messages_count": stats.get("messages_count", 0),
                "tokens_used": stats.get("tokens_used", 0),
                "tokens_limit": auth_state.quota_limit,
                "requests_count": stats.get("requests_count", 0),
                "session_duration": stats.get("session_duration", 0),
                "last_activity": stats.get("last_activity"),
                "memory_items": stats.get("memory_items", 0)
            },
            "quota": {
                "used": auth_state.quota_used,
                "limit": auth_state.quota_limit,
                "remaining": auth_state.quota_limit - auth_state.quota_used if auth_state.quota_limit else None,
                "reset_time": auth_state.quota_reset_time.isoformat() if auth_state.quota_reset_time else None
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取会话统计失败: {str(e)}")

@router.post("/session/clear/{session_id}")
async def clear_session(
    session_id: str,
    session_service: SessionService = Depends(get_session_service),
    auth_service: AuthService = Depends(get_auth_service)
):
    """清除会话历史 - Web版/clear命令"""
    try:
        auth_state = auth_service.get_auth_session(session_id)
        if not auth_state:
            raise HTTPException(status_code=401, detail="认证会话无效")

        # 清除会话数据
        cleared_items = session_service.clear_session_history(session_id)
        
        return {
            "success": True,
            "message": f"已清除 {cleared_items} 条会话记录",
            "cleared_items": cleared_items,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"清除会话失败: {str(e)}")

@router.post("/session/compress/{session_id}")
async def compress_session(
    session_id: str,
    session_service: SessionService = Depends(get_session_service),
    auth_service: AuthService = Depends(get_auth_service)
):
    """压缩会话历史 - Web版/compress命令"""
    try:
        auth_state = auth_service.get_auth_session(session_id)
        if not auth_state:
            raise HTTPException(status_code=401, detail="认证会话无效")

        # 压缩会话历史
        result = await session_service.compress_session_history(session_id)
        
        return {
            "success": True,
            "message": "会话历史已压缩",
            "before_tokens": result.get("before_tokens", 0),
            "after_tokens": result.get("after_tokens", 0),
            "compression_ratio": result.get("compression_ratio", 0),
            "summary": result.get("summary", "")
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"压缩会话失败: {str(e)}")

@router.get("/help")
async def get_help(command: Optional[str] = None):
    """获取帮助信息 - Web版/help命令"""
    if command:
        # 获取特定命令的帮助
        commands = await list_available_commands()
        all_commands = {}
        for category in commands["commands"].values():
            for cmd in category:
                all_commands[cmd["name"]] = cmd
                if "aliases" in cmd:
                    for alias in cmd["aliases"]:
                        all_commands[alias] = cmd

        if command in all_commands:
            cmd_info = all_commands[command]
            return {
                "command": command,
                "description": cmd_info["description"],
                "usage": cmd_info["usage"],
                "examples": cmd_info["examples"],
                "aliases": cmd_info.get("aliases", [])
            }
        else:
            raise HTTPException(status_code=404, detail=f"命令 '{command}' 不存在")
    else:
        # 获取全部帮助信息
        return {
            "title": "Web Analyzer 命令帮助",
            "description": "基于qwen-code CLI的Web命令系统",
            "categories": {
                "session": "会话管理 - 清除、压缩、统计会话数据",
                "model": "模型管理 - 切换AI模型和认证方式", 
                "analysis": "分析工具 - 数据分析和结果导出",
                "system": "系统设置 - 主题、配置等系统功能",
                "help": "帮助信息 - 命令说明和文档"
            },
            "quick_start": [
                "输入 /help 查看所有命令",
                "输入 /stats 查看当前会话统计",
                "输入 /model qwen-coder 切换到编程模型",
                "输入 /clear 清除会话历史"
            ],
            "features": [
                "🔐 多种认证方式 (Qwen OAuth, OpenAI API)",
                "🤖 智能模型切换 (编程/视觉模型自动切换)",
                "📊 实时会话统计和Token管理",
                "🛠️ 30+专业命令 (基于qwen-code CLI)",
                "💾 会话记忆和历史压缩",
                "🎨 现代化Web界面"
            ]
        }
