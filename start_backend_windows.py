#!/usr/bin/env python3
"""
Windows专用后端启动脚本 - 确保在Uvicorn启动前设置ProactorEventLoop
解决Playwright async subprocess NotImplementedError问题
"""
import sys
import os
import asyncio

def setup_windows_event_loop():
    """在服务器启动前设置Windows ProactorEventLoop"""
    if sys.platform == 'win32':
        print("🔧 Windows系统检测到，设置ProactorEventLoop策略...")
        
        # 1. 设置全局事件循环策略
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        
        # 2. 创建ProactorEventLoop并设为当前循环
        loop = asyncio.ProactorEventLoop()
        asyncio.set_event_loop(loop)
        
        # 3. 验证设置
        current_policy = asyncio.get_event_loop_policy()
        current_loop = asyncio.get_event_loop()
        
        print(f"✅ 事件循环策略: {type(current_policy).__name__}")
        print(f"✅ 当前事件循环: {type(current_loop).__name__}")
        
        if isinstance(current_loop, asyncio.ProactorEventLoop):
            print("✅ ProactorEventLoop设置成功 - Playwright子进程支持已启用")
            return True
        else:
            print("❌ ProactorEventLoop设置失败")
            return False
    else:
        print("ℹ️ 非Windows系统，无需特殊处理")
        return True

def main():
    """主启动函数"""
    print("🚀 启动Web Analyzer V2后端服务器...")
    
    # 首先设置Windows事件循环
    if not setup_windows_event_loop():
        print("❌ Windows事件循环设置失败，退出")
        sys.exit(1)
    
    # 添加后端路径
    backend_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backend')
    sys.path.insert(0, backend_path)
    
    # 现在启动Uvicorn服务器
    try:
        import uvicorn
        from backend.app.main import app
        
        print("🔄 启动Uvicorn服务器...")
        
        # 使用当前已设置的事件循环运行服务器
        uvicorn.run(
            app, 
            host="0.0.0.0", 
            port=8000,
            reload=False,  # 禁用热重载避免事件循环重置
            loop="asyncio"  # 明确指定使用asyncio循环
        )
        
    except Exception as e:
        print(f"❌ 服务器启动失败: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
