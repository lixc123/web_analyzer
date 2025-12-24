"""
Windows异步事件循环修复模块
必须在任何其他异步操作之前导入此模块
"""
import asyncio
import sys

def fix_windows_event_loop():
    """修复Windows下的异步事件循环问题"""
    if sys.platform == 'win32':
        # 设置WindowsProactorEventLoopPolicy以支持子进程
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        
        # 确保当前事件循环也使用正确的策略
        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

# 自动执行修复
fix_windows_event_loop()
