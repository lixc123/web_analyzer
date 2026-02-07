#!/usr/bin/env python3
"""
Windows-specific backend startup script
Windows异步子进程优化启动脚本
"""

import sys
import os
import asyncio
import uvicorn
import socket

# 添加backend路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

# Windows异步事件循环优化
if sys.platform == 'win32':
    # 设置Windows ProactorEventLoop策略来解决Playwright异步子进程问题
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    print("[OK] Windows ProactorEventLoop策略已设置")

# 从backend/app导入应用
from backend.app.main import app
from backend.app.config import settings

def get_local_ip() -> str:
    """获取首个可用的非回环IPv4地址"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            ip = sock.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
    except OSError:
        pass

    try:
        for addr_info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = addr_info[4][0]
            if ip and not ip.startswith("127."):
                return ip
    except OSError:
        pass

    return "127.0.0.1"

if __name__ == "__main__":
    local_ip = get_local_ip()
    print(f"[INFO] 启动Web Analyzer后端服务")
    print(f"[INFO] 端口: {settings.backend_port}")
    print(f"[INFO] Windows优化: ProactorEventLoop")
    print(f"[INFO] 后端地址(localhost): http://localhost:{settings.backend_port}")
    print(f"[INFO] 后端地址(127.0.0.1): http://127.0.0.1:{settings.backend_port}")
    print(f"[INFO] 后端地址(局域网): http://{local_ip}:{settings.backend_port}")
    print(f"[INFO] API文档(localhost): http://localhost:{settings.backend_port}/docs")
    print(f"[INFO] API文档(127.0.0.1): http://127.0.0.1:{settings.backend_port}/docs")
    print(f"[INFO] API文档(局域网): http://{local_ip}:{settings.backend_port}/docs")
    
    # 使用uvicorn启动，确保使用Windows兼容配置
    uvicorn.run(
        "backend.app.main:app",
        host="0.0.0.0",
        port=settings.backend_port,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
        access_log=True,
        # Windows特定配置
        loop="asyncio",  # 确保使用我们设置的ProactorEventLoop
    )
