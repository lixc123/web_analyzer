"""异步辅助工具模块"""
import asyncio
from functools import wraps
from typing import Any, Callable, Coroutine, Optional, TypeVar

T = TypeVar("T")


def run_sync(coro: Coroutine[Any, Any, T]) -> T:
    """在同步上下文中运行协程。
    
    如果当前已有事件循环在运行，使用 nest_asyncio 或在新线程中运行；
    否则用 asyncio.run()。
    
    Args:
        coro: 要运行的协程
        
    Returns:
        协程的返回值
        
    Warning:
        如果在已有事件循环的上下文中调用，会在新线程中运行，
        可能导致性能损失。建议优先使用 async/await。
    """
    import concurrent.futures
    
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # 没有运行中的事件循环，直接运行
        return asyncio.run(coro)
    
    # 有运行中的循环，不能用 run_until_complete（会死锁）
    # 在新线程中创建新的事件循环来运行
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(asyncio.run, coro)
        return future.result()


def fire_and_forget(coro: Coroutine[Any, Any, Any]) -> Optional[asyncio.Task]:
    """启动协程但不等待结果（fire-and-forget 模式）。
    
    Args:
        coro: 要启动的协程
        
    Returns:
        创建的 Task，如果没有事件循环则返回 None
    """
    try:
        loop = asyncio.get_running_loop()
        return loop.create_task(coro)
    except RuntimeError:
        # 没有事件循环，同步运行
        asyncio.run(coro)
        return None


async def gather_with_limit(
    coros: list,
    limit: int = 5,
    return_exceptions: bool = True,
) -> list:
    """带并发限制的 gather。
    
    Args:
        coros: 协程列表
        limit: 最大并发数
        return_exceptions: 是否将异常作为结果返回
        
    Returns:
        结果列表
    """
    semaphore = asyncio.Semaphore(limit)
    
    async def limited_coro(coro):
        async with semaphore:
            return await coro
    
    return await asyncio.gather(
        *[limited_coro(c) for c in coros],
        return_exceptions=return_exceptions,
    )


async def retry_async(
    coro_func: Callable[[], Coroutine[Any, Any, T]],
    max_retries: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
) -> T:
    """带重试的异步调用。
    
    Args:
        coro_func: 返回协程的可调用对象（每次重试会调用它创建新协程）
        max_retries: 最大重试次数
        delay: 初始延迟秒数
        backoff: 延迟增长倍数
        
    Returns:
        协程的返回值
        
    Raises:
        最后一次尝试的异常
    """
    last_exception = None
    current_delay = delay
    
    for attempt in range(max_retries + 1):
        try:
            return await coro_func()
        except Exception as e:
            last_exception = e
            if attempt < max_retries:
                await asyncio.sleep(current_delay)
                current_delay *= backoff
    
    raise last_exception  # type: ignore


async def timeout_wrapper(
    coro: Coroutine[Any, Any, T],
    timeout_seconds: float,
    default: Optional[T] = None,
) -> Optional[T]:
    """为协程添加超时，超时返回默认值。
    
    Args:
        coro: 要执行的协程
        timeout_seconds: 超时秒数
        default: 超时时返回的默认值
        
    Returns:
        协程结果或默认值
    """
    try:
        return await asyncio.wait_for(coro, timeout=timeout_seconds)
    except asyncio.TimeoutError:
        return default


class AsyncTaskQueue:
    """简单的异步任务队列，用于管理后台任务。"""
    
    def __init__(self, max_workers: int = 3) -> None:
        self._queue: asyncio.Queue = asyncio.Queue()
        self._workers: list[asyncio.Task] = []
        self._max_workers = max_workers
        self._running = False
    
    async def start(self) -> None:
        """启动工作线程。"""
        if self._running:
            return
        self._running = True
        for _ in range(self._max_workers):
            task = asyncio.create_task(self._worker())
            self._workers.append(task)
    
    async def stop(self) -> None:
        """停止队列并等待所有任务完成。"""
        self._running = False
        # 发送停止信号
        for _ in self._workers:
            await self._queue.put(None)
        # 等待所有 worker 结束
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()
    
    async def put(self, coro: Coroutine) -> None:
        """添加任务到队列。"""
        await self._queue.put(coro)
    
    async def _worker(self) -> None:
        """工作协程。"""
        while self._running:
            coro = await self._queue.get()
            if coro is None:
                break
            try:
                await coro
            except Exception:
                pass  # 静默处理异常，可按需添加日志
            finally:
                self._queue.task_done()
