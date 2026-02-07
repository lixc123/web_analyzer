"""
认证API路由 - Web版AI认证功能
支持Qwen OAuth和OpenAI API两种认证方式
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
import httpx
import secrets
import time
from datetime import datetime, timedelta
import json
import os
from urllib.parse import quote
from ...services.auth_service import AuthService, AuthType, AuthState
from ...services.session_service import SessionService

router = APIRouter()

_auth_service_singleton = AuthService()
_session_service_singleton = SessionService()

# 请求/响应模型
class OAuthStartRequest(BaseModel):
    redirect_uri: Optional[str] = "http://localhost:3000/auth/callback"

class OAuthStartResponse(BaseModel):
    authorization_url: str
    state: str
    device_code: Optional[str] = None

class OpenAIValidateRequest(BaseModel):
    api_key: str
    base_url: Optional[str] = "https://api.openai.com/v1"
    model: Optional[str] = "gpt-4"

class AuthStatusResponse(BaseModel):
    isAuthenticated: bool
    authType: Optional[str] = None
    user: Optional[Dict[str, Any]] = None
    apiConfig: Optional[Dict[str, Any]] = None
    quota: Optional[Dict[str, Any]] = None

# 依赖注入
def get_auth_service():
    return _auth_service_singleton

def get_session_service():
    return _session_service_singleton

@router.post("/qwen/oauth/start", response_model=OAuthStartResponse)
async def start_qwen_oauth(
    http_request: Request,
    request: OAuthStartRequest = OAuthStartRequest(),
    auth_service: AuthService = Depends(get_auth_service)
):
    """启动Qwen OAuth认证流程"""
    try:
        # 生成状态参数防止CSRF攻击
        state = secrets.token_urlsafe(32)
        
        # Qwen OAuth配置
        client_id = os.getenv("QWEN_CLIENT_ID", "your_qwen_client_id")
        base = str(http_request.base_url).rstrip("/")

        redirect_uri = request.redirect_uri
        if (not redirect_uri) or client_id in ("your_qwen_client_id", "", None):
            redirect_uri = f"{base}/api/v1/auth/qwen/oauth/web-callback"

        if client_id in ("your_qwen_client_id", "", None):
            authorization_url = (
                f"{base}/api/v1/auth/qwen/oauth/mock?"
                f"state={quote(state)}&"
                f"redirect_uri={quote(redirect_uri)}"
            )
        else:
            auth_url = "https://oauth.qwen.ai/oauth/authorize"

            # 构建授权URL
            authorization_url = (
                f"{auth_url}?"
                f"client_id={client_id}&"
                f"response_type=code&"
                f"redirect_uri={redirect_uri}&"
                f"state={state}&"
                f"scope=openid profile qwen-api"
            )
        
        # 保存OAuth状态
        auth_service.save_oauth_state(state, {
            "redirect_uri": redirect_uri,
            "timestamp": time.time()
        })
        
        return OAuthStartResponse(
            authorization_url=authorization_url,
            state=state
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"启动OAuth失败: {str(e)}")


@router.get("/qwen/oauth/mock")
async def qwen_oauth_mock(
    state: str,
    redirect_uri: str,
    auth_service: AuthService = Depends(get_auth_service)
):
    if not auth_service.validate_oauth_state(state):
        raise HTTPException(status_code=400, detail="无效的OAuth状态")

    code = secrets.token_urlsafe(16)
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(url=f"{redirect_uri}{sep}code={quote(code)}&state={quote(state)}")


@router.get("/qwen/oauth/web-callback")
async def qwen_oauth_web_callback(
    code: str,
    state: str,
    auth_service: AuthService = Depends(get_auth_service)
):
    try:
        if not auth_service.validate_oauth_state(state):
            raise HTTPException(status_code=400, detail="无效的OAuth状态")

        token_data = await auth_service.exchange_oauth_token(code, state)
        user_info = await auth_service.get_qwen_user_info(token_data["access_token"])

        auth_state = AuthState(
            auth_type=AuthType.QWEN_OAUTH,
            user_id=user_info.get("id"),
            user_name=user_info.get("name"),
            user_email=user_info.get("email"),
            provider="qwen",
            access_token=token_data.get("access_token"),
            refresh_token=token_data.get("refresh_token"),
            expires_at=datetime.now() + timedelta(seconds=token_data.get("expires_in", 3600)),
            quota_limit=2000,
            quota_used=0,
            quota_reset_time=(datetime.now() + timedelta(days=1))
        )

        session_id = auth_service.create_auth_session(auth_state)
        payload = {
            "type": "qwen_oauth_success",
            "session_id": session_id,
            "user": {
                "id": user_info.get("id"),
                "name": user_info.get("name"),
                "email": user_info.get("email")
            },
            "quota": {
                "limit": 2000,
                "used": 0,
                "reset_time": (datetime.now() + timedelta(days=1)).isoformat()
            }
        }

        html = """<!doctype html><html><head><meta charset=\"utf-8\"/></head><body>
<script>
(function(){
  try {
    if (window.opener) {
      window.opener.postMessage(%s, '*');
    }
  } finally {
    window.close();
  }
})();
</script>
认证完成，可关闭窗口。
</body></html>""" % json.dumps(payload)

        return HTMLResponse(content=html)
    except HTTPException as e:
        html = f"""<!doctype html><html><body>OAuth失败: {e.detail}</body></html>"""
        return HTMLResponse(content=html, status_code=e.status_code)
    except Exception as e:
        html = f"""<!doctype html><html><body>OAuth失败: {str(e)}</body></html>"""
        return HTMLResponse(content=html, status_code=500)

@router.post("/qwen/oauth/callback")
async def qwen_oauth_callback(
    code: str,
    state: str,
    auth_service: AuthService = Depends(get_auth_service),
    session_service: SessionService = Depends(get_session_service)
):
    """处理Qwen OAuth回调"""
    try:
        # 验证状态参数
        if not auth_service.validate_oauth_state(state):
            raise HTTPException(status_code=400, detail="无效的OAuth状态")
        
        # 交换访问令牌
        token_data = await auth_service.exchange_oauth_token(code, state)
        
        # 获取用户信息
        user_info = await auth_service.get_qwen_user_info(token_data["access_token"])
        
        # 创建认证会话
        auth_state = AuthState(
            auth_type=AuthType.QWEN_OAUTH,
            user_id=user_info["id"],
            user_name=user_info["name"],
            user_email=user_info.get("email"),
            access_token=token_data["access_token"],
            refresh_token=token_data.get("refresh_token"),
            expires_at=datetime.now() + timedelta(seconds=token_data["expires_in"]),
            quota_limit=2000,  # Qwen免费额度
            quota_used=0
        )
        
        session_id = auth_service.create_auth_session(auth_state)
        
        return {
            "success": True,
            "session_id": session_id,
            "user": {
                "id": user_info["id"],
                "name": user_info["name"],
                "email": user_info.get("email")
            },
            "quota": {
                "limit": 2000,
                "used": 0,
                "reset_time": (datetime.now() + timedelta(days=1)).isoformat()
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OAuth回调处理失败: {str(e)}")

@router.post("/openai/validate")
async def validate_openai_config(
    request: OpenAIValidateRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    """验证OpenAI API配置"""
    try:
        # 测试API连接
        async with httpx.AsyncClient() as client:
            headers = {
                "Authorization": f"Bearer {request.api_key}",
                "Content-Type": "application/json"
            }
            
            # 发送测试请求
            test_url = f"{request.base_url}/models"
            response = await client.get(test_url, headers=headers, timeout=10.0)
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=400, 
                    detail="API密钥验证失败，请检查密钥和Base URL"
                )
            
            models = response.json()
            available_models = [model["id"] for model in models.get("data", [])]
            
            # 验证指定的模型是否存在
            if request.model and request.model not in available_models:
                # 如果模型不存在，使用第一个可用模型
                default_model = available_models[0] if available_models else "gpt-3.5-turbo"
            else:
                default_model = request.model or "gpt-3.5-turbo"
            
            # 创建认证状态
            auth_state = AuthState(
                auth_type=AuthType.OPENAI_API,
                api_key=request.api_key,
                base_url=request.base_url,
                model=default_model,
                available_models=available_models[:10],  # 限制返回模型数量
                quota_limit=None,  # API付费模式无限制
                quota_used=0
            )
            
            session_id = auth_service.create_auth_session(auth_state)
            
            return {
                "success": True,
                "session_id": session_id,
                "user": {
                    "name": "API用户",
                    "provider": auth_service.detect_provider(request.base_url)
                },
                "apiConfig": {
                    "baseUrl": request.base_url,
                    "model": default_model,
                    "availableModels": available_models[:10]
                },
                "quota": {
                    "limit": None,
                    "used": 0,
                    "type": "pay_per_use"
                }
            }
            
    except httpx.TimeoutException:
        raise HTTPException(status_code=408, detail="API连接超时，请检查网络或Base URL")
    except httpx.RequestError:
        raise HTTPException(status_code=400, detail="无法连接到API服务器")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"验证API配置失败: {str(e)}")

@router.get("/status", response_model=AuthStatusResponse)
async def get_auth_status(
    session_id: Optional[str] = None,
    auth_service: AuthService = Depends(get_auth_service)
):
    """获取当前认证状态"""
    try:
        if not session_id:
            return AuthStatusResponse(isAuthenticated=False)
        
        auth_state = auth_service.get_auth_session(session_id)
        if not auth_state:
            return AuthStatusResponse(isAuthenticated=False)
        
        # 检查会话是否过期
        if auth_state.is_expired():
            auth_service.revoke_auth_session(session_id)
            return AuthStatusResponse(isAuthenticated=False)
        
        # 构建响应
        user_info = {
            "id": getattr(auth_state, "user_id", None),
            "name": getattr(auth_state, "user_name", "用户"),
            "email": getattr(auth_state, "user_email", None)
        }
        
        api_config = None
        if auth_state.auth_type == AuthType.OPENAI_API:
            api_config = {
                "baseUrl": auth_state.base_url,
                "model": auth_state.model,
                "availableModels": getattr(auth_state, "available_models", [])
            }
        
        quota_info = {
            "used": auth_state.quota_used,
            "limit": auth_state.quota_limit,
            "resetTime": auth_state.quota_reset_time.isoformat() if auth_state.quota_reset_time else None
        }
        
        return AuthStatusResponse(
            isAuthenticated=True,
            authType=auth_state.auth_type.value,
            user=user_info,
            apiConfig=api_config,
            quota=quota_info
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取认证状态失败: {str(e)}")

@router.post("/refresh")
async def refresh_auth(
    session_id: str,
    auth_service: AuthService = Depends(get_auth_service)
):
    """刷新认证状态"""
    try:
        auth_state = auth_service.get_auth_session(session_id)
        if not auth_state:
            raise HTTPException(status_code=401, detail="认证会话不存在")
        
        if auth_state.auth_type == AuthType.QWEN_OAUTH:
            # 使用refresh_token刷新访问令牌
            new_token_data = await auth_service.refresh_qwen_token(auth_state.refresh_token)
            
            auth_state.access_token = new_token_data["access_token"]
            auth_state.expires_at = datetime.now() + timedelta(seconds=new_token_data["expires_in"])
            
            auth_service.update_auth_session(session_id, auth_state)
            
            return {"success": True, "message": "认证已刷新"}
        
        elif auth_state.auth_type == AuthType.OPENAI_API:
            # API密钥模式，重新验证连接
            await auth_service.validate_openai_connection(auth_state)
            return {"success": True, "message": "API连接验证成功"}
        
        return {"success": True, "message": "无需刷新"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"刷新认证失败: {str(e)}")

@router.post("/logout")
async def logout(
    session_id: str,
    auth_service: AuthService = Depends(get_auth_service)
):
    """退出登录"""
    try:
        auth_state = auth_service.get_auth_session(session_id)
        
        if auth_state and auth_state.auth_type == AuthType.QWEN_OAUTH:
            # 撤销Qwen OAuth令牌
            await auth_service.revoke_qwen_token(auth_state.access_token)
        
        # 删除认证会话
        auth_service.revoke_auth_session(session_id)
        
        return {"success": True, "message": "已退出登录"}
        
    except Exception as e:
        # 即使撤销失败，也删除本地会话
        auth_service.revoke_auth_session(session_id)
        return {"success": True, "message": "已退出登录"}

@router.get("/providers")
async def get_supported_providers():
    """获取支持的API提供商列表"""
    providers = {
        "qwen": {
            "name": "Qwen OAuth",
            "description": "通义千问官方OAuth认证",
            "free_quota": 2000,
            "features": ["免费额度", "自动管理", "零配置"]
        },
        "openai": {
            "name": "OpenAI",
            "base_url": "https://api.openai.com/v1",
            "models": ["gpt-4", "gpt-3.5-turbo", "gpt-4-vision-preview"]
        },
        "siliconflow": {
            "name": "硅基流动",
            "base_url": "https://api.siliconflow.cn/v1",
            "models": ["qwen-plus", "yi-lightning"]
        },
        "dashscope": {
            "name": "阿里云百炼",
            "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
            "models": ["qwen3-coder-plus", "qwen3-vl-plus"]
        },
        "modelscope": {
            "name": "ModelScope",
            "base_url": "https://api-inference.modelscope.cn/v1",
            "models": ["Qwen/Qwen3-Coder-480B-A35B-Instruct"]
        }
    }
    
    return {"providers": providers}
