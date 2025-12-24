"""
Windows Playwright修复 - 彻底解决 NotImplementedError 子进程问题
"""
import sys
import asyncio

def fix_windows_asyncio():
    """修复Windows下的asyncio子进程问题"""
    if sys.platform != 'win32':
        return
        
    # 设置 ProactorEventLoopPolicy (支持子进程)
    policy = asyncio.WindowsProactorEventLoopPolicy()
    asyncio.set_event_loop_policy(policy)
    
    # 确保当前循环也使用正确的策略
    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        # 没有运行的循环，创建一个新的
        loop = policy.new_event_loop()
        asyncio.set_event_loop(loop)
    
    print("✅ Windows asyncio修复完成 - Playwright子进程支持已启用")

# 立即执行修复
fix_windows_asyncio()
