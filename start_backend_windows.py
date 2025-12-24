#!/usr/bin/env python3
"""
Windows-specific backend startup script
Windows异步子进程优化启动脚本
"""

import sys
import os
import asyncio
import uvicorn

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

if __name__ == "__main__":
    print(f"[INFO] 启动Web Analyzer后端服务")
    print(f"[INFO] 端口: {settings.backend_port}")
    print(f"[INFO] Windows优化: ProactorEventLoop")
    print(f"[INFO] API文档: http://localhost:{settings.backend_port}/docs")
    
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
