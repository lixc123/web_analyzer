"""
认证服务 - 处理OAuth和API Key认证
"""

import uuid
import time
import json
import httpx
from enum import Enum
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)

class AuthType(Enum):
    QWEN_OAUTH = "qwen-oauth"
    OPENAI_API = "openai-api"

@dataclass
class AuthState:
    auth_type: AuthType
    user_id: Optional[str] = None
    user_name: str = "用户"
    user_email: Optional[str] = None
    provider: str = "qwen"
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    available_models: List[str] = field(default_factory=list)
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_at: Optional[datetime] = None
    model: str = "coder-model"
    quota_limit: Optional[int] = 10000
    quota_used: int = 0
    quota_reset_time: Optional[datetime] = None
    
    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        return datetime.now() > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "auth_type": self.auth_type.value,
            "user_id": self.user_id,
            "user_name": self.user_name,
            "provider": self.provider,
            "api_key": self.api_key,
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "model": self.model,
            "quota_limit": self.quota_limit,
            "quota_used": self.quota_used
        }

class AuthService:
    def __init__(self):
        self._auth_sessions: Dict[str, AuthState] = {}
        self._oauth_states: Dict[str, Dict[str, Any]] = {}
    
    def create_auth_session(self, auth_state: AuthState) -> str:
        """创建认证会话"""
        session_id = str(uuid.uuid4())
        self._auth_sessions[session_id] = auth_state
        logger.info(f"创建认证会话: {session_id} for {auth_state.user_name}")
        return session_id
    
    def get_auth_session(self, session_id: str) -> Optional[AuthState]:
        """获取认证会话"""
        auth_state = self._auth_sessions.get(session_id)
        if auth_state and auth_state.is_expired():
            del self._auth_sessions[session_id]
            return None
        return auth_state
    
    def update_auth_session(self, session_id: str, auth_state: AuthState):
        """更新认证会话"""
        if session_id in self._auth_sessions:
            self._auth_sessions[session_id] = auth_state
    
    def delete_auth_session(self, session_id: str) -> bool:
        """删除认证会话"""
        if session_id in self._auth_sessions:
            del self._auth_sessions[session_id]
            return True
        return False

    def revoke_auth_session(self, session_id: str) -> bool:
        return self.delete_auth_session(session_id)
    
    def save_oauth_state(self, state: str, data: Dict[str, Any]):
        """保存OAuth状态"""
        self._oauth_states[state] = data
    
    def validate_oauth_state(self, state: str) -> bool:
        """验证OAuth状态"""
        oauth_data = self._oauth_states.get(state)
        if not oauth_data:
            return False
        
        # 检查是否过期（5分钟）
        if time.time() - oauth_data.get("timestamp", 0) > 300:
            del self._oauth_states[state]
            return False
        
        return True
    
    async def exchange_oauth_token(self, code: str, state: str) -> Dict[str, Any]:
        """交换OAuth访问令牌"""
        oauth_data = self._oauth_states.get(state)
        if not oauth_data:
            raise ValueError("Invalid OAuth state")
        
        # 模拟token交换（实际应该调用真实的OAuth API）
        return {
            "access_token": f"qwen_token_{code[:10]}",
            "refresh_token": f"qwen_refresh_{code[:10]}",
            "expires_in": 3600,
            "token_type": "Bearer"
        }
    
    async def get_qwen_user_info(self, access_token: str) -> Dict[str, Any]:
        """获取Qwen用户信息"""
        # 模拟用户信息（实际应该调用真实的API）
        return {
            "id": "qwen_user_123",
            "name": "Qwen用户",
            "email": "user@qwen.ai"
        }
    
    async def validate_openai_api(self, api_key: str, base_url: str) -> bool:
        """验证OpenAI API配置"""
        try:
            async with httpx.AsyncClient() as client:
                headers = {"Authorization": f"Bearer {api_key}"}
                response = await client.get(f"{base_url}/models", headers=headers, timeout=10)
                return response.status_code == 200
        except Exception as e:
            logger.error(f"OpenAI API验证失败: {e}")
            return False

    async def validate_openai_connection(self, auth_state: AuthState) -> bool:
        base_url = auth_state.base_url or "https://api.openai.com/v1"
        if not auth_state.api_key:
            raise ValueError("Missing api_key")
        ok = await self.validate_openai_api(auth_state.api_key, base_url)
        if not ok:
            raise ValueError("OpenAI API validation failed")
        return True
    
    def detect_provider(self, base_url: str) -> str:
        """检测API提供商"""
        if "siliconflow" in base_url.lower():
            return "硅基流动"
        elif "openai" in base_url.lower():
            return "OpenAI"
        else:
            return "自定义API"

    async def refresh_qwen_token(self, refresh_token: str) -> Dict[str, Any]:
        return {
            "access_token": f"qwen_refreshed_{int(time.time())}",
            "refresh_token": refresh_token,
            "expires_in": 3600,
            "token_type": "Bearer"
        }

    async def revoke_qwen_token(self, access_token: str) -> bool:
        return True
    
    async def refresh_token(self, session_id: str) -> bool:
        """刷新访问令牌"""
        auth_state = self._auth_sessions.get(session_id)
        if not auth_state or not auth_state.refresh_token:
            return False
        
        try:
            # 模拟token刷新（实际应该调用真实的API）
            auth_state.access_token = f"refreshed_{int(time.time())}"
            auth_state.expires_at = datetime.now() + timedelta(hours=1)
            return True
        except Exception as e:
            logger.error(f"Token刷新失败: {e}")
            return False
