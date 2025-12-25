# Windows Playwright修复 - 必须在任何其他导入之前执行
import sys
if sys.platform == 'win32':
    import asyncio
    # 立即设置ProactorEventLoopPolicy
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

# FastAPI Application Package
