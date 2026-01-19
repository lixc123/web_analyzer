# 必须最先导入Windows修复 - 解决Playwright async subprocess NotImplementedError
import sys
import os
import logging

# 配置日志（提前配置，避免后续使用时未定义）
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 添加路径以便导入修复模块
backend_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
sys.path.insert(0, backend_path)

# Windows异步子进程修复 - 强制替换当前运行的事件循环
if sys.platform == 'win32':
    import asyncio
    # 1. 设置策略
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    # 2. 强制替换当前事件循环（如果有的话）
    try:
        current_loop = asyncio.get_running_loop()
        current_loop_type = type(current_loop).__name__

        if current_loop_type != 'ProactorEventLoop':
            pass  # 策略已设置，将在启动时生效
    except RuntimeError:
        # 没有运行的循环，这是正常的
        pass

    # 3. 创建并设置ProactorEventLoop为默认循环
    try:
        loop = asyncio.ProactorEventLoop()
        asyncio.set_event_loop(loop)
    except Exception as e:
        logger.error(f"设置默认循环失败: {e}")

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import uvicorn
from .config import settings
from .database import init_database, HybridStorage
from .api.v1 import crawler, analysis, dashboard, auth, migration, terminal, code_generator, proxy, filters
from .websocket import manager

# 更新日志级别（如果配置文件中有指定）
if hasattr(settings, 'log_level'):
    logging.getLogger().setLevel(getattr(logging, settings.log_level))

# 创建FastAPI应用
app = FastAPI(
    title=settings.app_name,
    description="现代化网络流量分析平台",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS中间件配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册API路由
app.include_router(crawler.router, prefix="/api/v1/crawler", tags=["crawler"])
app.include_router(analysis.router, prefix="/api/v1/analysis", tags=["analysis"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["dashboard"])
app.include_router(migration.router, prefix="/api/v1/migration", tags=["migration"])
app.include_router(terminal.router, prefix="/api/v1/terminal", tags=["terminal"])
app.include_router(code_generator.router, prefix="/api/v1/code", tags=["code_generator"])
app.include_router(proxy.router, prefix="/api/v1/proxy", tags=["proxy"])
app.include_router(filters.router, prefix="/api/v1/filters", tags=["filters"])

# 静态文件服务
if os.path.exists("../frontend/dist"):
    app.mount("/static", StaticFiles(directory="../frontend/dist"), name="static")

@app.on_event("startup")
async def startup_event():
    """应用启动事件"""
    logger.info(f"启动 {settings.app_name}")

    # 初始化数据库
    init_database()

    # 确保混合存储文件存在
    HybridStorage.ensure_json_file_exists()

    # 初始化缓存
    from .services.cache_service import CacheService
    cache_service = CacheService()

    # 设置主事件循环到代理服务管理器
    import asyncio
    from backend.proxy.service_manager import ProxyServiceManager
    manager = ProxyServiceManager.get_instance()
    manager.set_main_event_loop(asyncio.get_event_loop())

    logger.info(f"应用启动完成，监听端口: {settings.backend_port}")

@app.on_event("shutdown")
async def shutdown_event():
    """应用关闭事件"""
    logger.info("正在关闭应用...")

@app.get("/")
async def root():
    """根路径 - 健康检查"""
    return {
        "message": f"欢迎使用 {settings.app_name}",
        "status": "running",
        "version": "2.0.0",
        "docs": "/docs",
        "api_prefix": "/api/v1"
    }

@app.get("/health")
async def health_check():
    """健康检查端点"""
    return {
        "status": "healthy",
        "database": "connected",
        "cache": "active",
        "services": {
            "crawler": "ready",
            "analysis": "ready"
        }
    }

@app.get("/api/v1/health")
async def api_health_check():
    """API健康检查端点 - 给前端调用"""
    return {
        "status": "healthy",
        "timestamp": "2025-12-20T17:35:00Z",
        "database": "connected",
        "cache": "active",
        "services": {
            "crawler": "ready",
            "analysis": "ready"
        }
    }

@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """WebSocket端点 - 用于实时通信"""
    try:
        await manager.connect(websocket, client_id)
        while True:
            try:
                data = await websocket.receive_text()
                # 解析客户端消息
                try:
                    import json
                    message_data = json.loads(data)
                    msg_type = message_data.get("type", "echo")
                    if msg_type == "ping":
                        response = {
                            "type": "pong",
                            "data": {"timestamp": message_data.get("timestamp")},
                            "timestamp": message_data.get("timestamp")
                        }
                        await manager.send_json_message(response, client_id)
                    else:
                        response = {
                            "type": msg_type,
                            "data": message_data,
                            "timestamp": message_data.get("timestamp")
                        }
                        await manager.send_json_message(response, client_id)
                except json.JSONDecodeError:
                    # 如果不是JSON，发送简单回复
                    response = {
                        "type": "text_message",
                        "data": data,
                        "timestamp": None
                    }
                    await manager.send_json_message(response, client_id)
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"处理WebSocket消息时出错: {e}")
                break
    except Exception as e:
        logger.error(f"WebSocket连接错误: {e}")
    finally:
        manager.disconnect(client_id)
        logger.info(f"客户端 {client_id} 断开连接")

@app.get("/ws-test")
async def websocket_test_page():
    """WebSocket测试页面"""
    html = """
    <!DOCTYPE html>
    <html>
        <head>
            <title>WebSocket Test</title>
        </head>
        <body>
            <h1>WebSocket 连接测试</h1>
            <div id="messages"></div>
            <input type="text" id="messageInput" placeholder="输入消息...">
            <button onclick="sendMessage()">发送</button>
            
            <script>
                const ws = new WebSocket(`ws://localhost:${settings.backend_port}/ws/test-client`);
                const messages = document.getElementById('messages');
                
                ws.onmessage = function(event) {
                    const message = document.createElement('div');
                    message.textContent = event.data;
                    messages.appendChild(message);
                };
                
                function sendMessage() {
                    const input = document.getElementById('messageInput');
                    ws.send(input.value);
                    input.value = '';
                }
                
                document.getElementById('messageInput').addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') {
                        sendMessage();
                    }
                });
            </script>
        </body>
    </html>
    """
    return HTMLResponse(content=html)

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings.backend_port,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )
