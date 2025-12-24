"""
命令服务 - 处理Web命令执行
"""

import asyncio
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class CommandType(Enum):
    SYSTEM = "system"
    MODEL = "model" 
    SESSION = "session"
    ANALYSIS = "analysis"
    MCP = "mcp"
    AGENT = "agent"
    FILE = "file"

@dataclass
class CommandResult:
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    command_type: str = "unknown"
    execution_time_ms: float = 0

class CommandService:
    def __init__(self):
        self.available_models = [
            "coder-model", "qwen-coder", 
            "gpt-4", "gpt-3.5-turbo", "claude-3"
        ]
    
    async def execute_command(
        self, 
        command: str, 
        args: Dict[str, Any] = None,
        auth_state = None,
        session_service = None
    ) -> CommandResult:
        """执行命令"""
        start_time = asyncio.get_event_loop().time()
        
        try:
            args = args or {}
            
            # 根据命令类型分发执行
            if command.startswith("/model"):
                result = await self._handle_model_command(command, args, auth_state)
            elif command.startswith("/clear"):
                result = await self._handle_clear_command(command, args, session_service)
            elif command.startswith("/stats"):
                result = await self._handle_stats_command(command, args, session_service)
            elif command.startswith("/compress"):
                result = await self._handle_compress_command(command, args, session_service)
            elif command.startswith("/help"):
                result = await self._handle_help_command(command, args)
            elif command.startswith("/mcp"):
                result = await self._handle_mcp_command(command, args)
            elif command.startswith("/agents"):
                result = await self._handle_agents_command(command, args)
            elif command.startswith("/directory"):
                result = await self._handle_directory_command(command, args)
            elif command.startswith("/init"):
                result = await self._handle_init_command(command, args)
            elif command.startswith("/settings"):
                result = await self._handle_settings_command(command, args)
            else:
                result = CommandResult(
                    success=False,
                    message=f"未知命令: {command}",
                    command_type="unknown"
                )
            
            # 记录执行时间
            end_time = asyncio.get_event_loop().time()
            result.execution_time_ms = (end_time - start_time) * 1000
            
            logger.info(f"命令执行完成: {command} ({result.execution_time_ms:.1f}ms)")
            return result
            
        except Exception as e:
            logger.error(f"命令执行失败: {command} - {e}")
            end_time = asyncio.get_event_loop().time()
            return CommandResult(
                success=False,
                message=f"命令执行失败: {str(e)}",
                command_type="error",
                execution_time_ms=(end_time - start_time) * 1000
            )
    
    async def _handle_model_command(self, command: str, args: Dict[str, Any], auth_state) -> CommandResult:
        """处理模型相关命令"""
        if not auth_state:
            return CommandResult(
                success=False,
                message="需要认证会话才能切换模型",
                command_type=CommandType.MODEL.value
            )
        
        model_id = args.get("model_id") or args.get("model")
        if not model_id:
            return CommandResult(
                success=True,
                message="可用模型列表",
                data={
                    "current_model": auth_state.model,
                    "available_models": self.available_models
                },
                command_type=CommandType.MODEL.value
            )
        
        if model_id not in self.available_models:
            return CommandResult(
                success=False,
                message=f"模型 {model_id} 不可用",
                data={"available_models": self.available_models},
                command_type=CommandType.MODEL.value
            )
        
        old_model = auth_state.model
        auth_state.model = model_id
        
        return CommandResult(
            success=True,
            message=f"模型已切换: {old_model} -> {model_id}",
            data={"old_model": old_model, "new_model": model_id},
            command_type=CommandType.MODEL.value
        )
    
    async def _handle_clear_command(self, command: str, args: Dict[str, Any], session_service) -> CommandResult:
        """处理清除命令"""
        if not session_service:
            return CommandResult(
                success=False,
                message="会话服务不可用",
                command_type=CommandType.SESSION.value
            )
        
        session_id = args.get("session_id")
        if not session_id:
            return CommandResult(
                success=False,
                message="需要指定session_id",
                command_type=CommandType.SESSION.value
            )
        
        cleared_count = session_service.clear_session_history(session_id)
        
        return CommandResult(
            success=True,
            message=f"已清除 {cleared_count} 条会话记录",
            data={"cleared_count": cleared_count},
            command_type=CommandType.SESSION.value
        )
    
    async def _handle_stats_command(self, command: str, args: Dict[str, Any], session_service) -> CommandResult:
        """处理统计命令"""
        if not session_service:
            return CommandResult(
                success=False,
                message="会话服务不可用",
                command_type=CommandType.SESSION.value
            )
        
        session_id = args.get("session_id")
        if not session_id:
            return CommandResult(
                success=False,
                message="需要指定session_id",
                command_type=CommandType.SESSION.value
            )
        
        stats = session_service.get_session_stats(session_id)
        summary = session_service.get_session_summary(session_id)
        
        if not stats:
            return CommandResult(
                success=False,
                message="会话不存在",
                command_type=CommandType.SESSION.value
            )
        
        return CommandResult(
            success=True,
            message="会话统计信息",
            data={"stats": stats.__dict__, "summary": summary},
            command_type=CommandType.SESSION.value
        )
    
    async def _handle_compress_command(self, command: str, args: Dict[str, Any], session_service) -> CommandResult:
        """处理压缩命令"""
        if not session_service:
            return CommandResult(
                success=False,
                message="会话服务不可用",
                command_type=CommandType.SESSION.value
            )
        
        session_id = args.get("session_id")
        if not session_id:
            return CommandResult(
                success=False,
                message="需要指定session_id",
                command_type=CommandType.SESSION.value
            )
        
        compression_result = await session_service.compress_session_history(session_id)
        
        return CommandResult(
            success=compression_result["success"],
            message=compression_result["message"],
            data=compression_result,
            command_type=CommandType.SESSION.value
        )
    
    async def _handle_help_command(self, command: str, args: Dict[str, Any]) -> CommandResult:
        """处理帮助命令"""
        help_info = {
            "commands": {
                "/model [model_id]": "切换或查看可用模型",
                "/clear": "清除当前会话历史",
                "/stats": "查看会话统计信息", 
                "/compress": "压缩会话历史以节省Token",
                "/help": "显示帮助信息",
                "/mcp": "管理MCP服务器和工具",
                "/agents": "管理智能体",
                "/directory": "文件目录分析",
                "/init": "初始化项目配置",
                "/settings": "全局设置管理"
            },
            "tips": [
                "使用Tab键可以自动补全命令",
                "大部分命令支持参数，使用 --help 查看详细用法",
                "命令执行结果会显示执行时间"
            ]
        }
        
        return CommandResult(
            success=True,
            message="命令帮助信息",
            data=help_info,
            command_type=CommandType.SYSTEM.value
        )
    
    async def _handle_mcp_command(self, command: str, args: Dict[str, Any]) -> CommandResult:
        """处理MCP命令"""
        return CommandResult(
            success=True,
            message="MCP管理功能已打开",
            data={"action": "open_mcp_manager"},
            command_type=CommandType.MCP.value
        )
    
    async def _handle_agents_command(self, command: str, args: Dict[str, Any]) -> CommandResult:
        """处理智能体命令"""
        return CommandResult(
            success=True,
            message="智能体管理功能已打开", 
            data={"action": "open_agent_manager"},
            command_type=CommandType.AGENT.value
        )
    
    async def _handle_directory_command(self, command: str, args: Dict[str, Any]) -> CommandResult:
        """处理目录分析命令"""
        return CommandResult(
            success=True,
            message="目录分析功能已打开",
            data={"action": "open_file_tree"},
            command_type=CommandType.FILE.value
        )
    
    async def _handle_init_command(self, command: str, args: Dict[str, Any]) -> CommandResult:
        """处理初始化命令"""
        return CommandResult(
            success=True,
            message="项目初始化向导已打开",
            data={"action": "open_project_init"},
            command_type=CommandType.SYSTEM.value
        )
    
    async def _handle_settings_command(self, command: str, args: Dict[str, Any]) -> CommandResult:
        """处理设置命令"""
        return CommandResult(
            success=True,
            message="全局设置已打开",
            data={"action": "open_global_settings"},
            command_type=CommandType.SYSTEM.value
        )
    
    async def switch_model(self, auth_state, target_model: str, reason: str = "user_selection") -> CommandResult:
        """切换模型"""
        return await self._handle_model_command(
            "/model", 
            {"model_id": target_model, "reason": reason}, 
            auth_state
        )
    
    def get_available_commands(self) -> List[str]:
        """获取可用命令列表"""
        return [
            "/model", "/clear", "/stats", "/compress", "/help",
            "/mcp", "/agents", "/directory", "/init", "/settings"
        ]
    
    def validate_command(self, command: str) -> bool:
        """验证命令格式"""
        if not command.startswith("/"):
            return False
        
        command_name = command.split()[0]
        return command_name in self.get_available_commands()
