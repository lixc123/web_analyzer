"""
代理服务器主类
"""

from typing import Optional, Callable
import threading
import asyncio
import logging
import socket
import time
from mitmproxy.tools.dump import DumpMaster
from mitmproxy import options

logger = logging.getLogger(__name__)


class ProxyServer:
    """代理服务器核心类"""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8888,
        on_request: Optional[Callable] = None,
        on_response: Optional[Callable] = None,
        on_websocket: Optional[Callable] = None,
    ):
        """
        初始化代理服务器

        Args:
            host: 监听地址
            port: 监听端口
            on_request: 请求回调函数
            on_response: 响应回调函数
        """
        self.host = host
        self.port = port
        self.on_request = on_request
        self.on_response = on_response
        self.on_websocket = on_websocket
        self._running = False
        self._master = None
        self._thread = None
        self._loop = None
        self._startup_event = threading.Event()
        self._startup_error: Optional[BaseException] = None

    def start(self):
        """启动代理服务器"""
        if self._running:
            raise RuntimeError("代理服务器已在运行")

        max_retries = 3
        current_port = self.port

        for attempt in range(max_retries):
            # 检查端口范围
            if current_port > 65535:
                raise RuntimeError(f"端口号超出有效范围: {current_port}")

            # mitmproxy 10+ 需要 running event loop；DumpMaster 必须在 loop 所在线程内创建
            self._startup_event.clear()
            self._startup_error = None

            self._running = True
            self._thread = threading.Thread(target=self._run, args=(current_port,), daemon=True)
            self._thread.start()

            started = self._startup_event.wait(timeout=3)
            if not started:
                self._running = False
                raise RuntimeError("启动代理服务超时")

            if self._startup_error:
                err_text = str(self._startup_error).lower()
                if "address already in use" in err_text or "被占用" in err_text:
                    logger.warning(f"端口 {current_port} 被占用，尝试下一个端口...")
                    current_port += 1
                    self._running = False
                    if attempt < max_retries - 1:
                        continue
                    raise RuntimeError(f"启动代理服务失败，尝试了 {max_retries} 次: {self._startup_error}")

                self._running = False
                raise RuntimeError(f"启动代理服务失败: {self._startup_error}")

            # 等待端口真正进入监听状态（mitmproxy 可能在启动阶段提前退出且不抛异常）
            if not self._wait_for_listening(current_port, timeout=3.0):
                err = self._startup_error or RuntimeError("proxy_not_listening")
                self.stop()
                raise RuntimeError(f"启动代理服务失败: {err}")

            # 更新端口（如果重试后端口改变）
            self.port = current_port
            logger.info(f"代理服务成功启动在端口 {current_port}")
            return current_port

    def _wait_for_listening(self, port: int, timeout: float = 3.0) -> bool:
        """等待代理端口进入监听状态。"""
        probe_host = self.host
        if not probe_host or probe_host in {"0.0.0.0", "::"}:
            probe_host = "127.0.0.1"

        deadline = time.time() + float(timeout)
        while time.time() < deadline:
            if self._startup_error:
                return False
            if self._thread and not self._thread.is_alive():
                return False

            try:
                with socket.create_connection((probe_host, int(port)), timeout=0.2):
                    return True
            except OSError:
                time.sleep(0.05)

        return False

    def _run(self, listen_port: int):
        """在独立线程中运行事件循环"""
        loop = None
        try:
            # 创建新的事件循环
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop

            # 创建 mitmproxy 配置
            from backend.app.config import settings

            opts = options.Options(
                confdir=settings.mitmproxy_confdir,
                listen_host=self.host,
                listen_port=listen_port,
                ssl_insecure=True,
            )

            # 创建 DumpMaster 实例（绑定 loop）
            self._master = DumpMaster(opts, loop=loop, with_termlog=False, with_dumper=False)

            # 添加请求拦截器插件
            from .request_handler import RequestInterceptor
            interceptor = RequestInterceptor(self.on_request, self.on_response, self.on_websocket)
            self._master.addons.add(interceptor)

            # 通知启动完成（master 初始化完成）
            self._startup_event.set()

            # 运行代理服务
            # mitmproxy 10+ 的 Master.run 是 coroutine
            loop.run_until_complete(self._master.run())
        except Exception as e:
            logger.error(f"代理服务运行错误: {e}", exc_info=True)
            self._running = False
            self._startup_error = e
            self._startup_event.set()
        finally:
            self._running = False
            if loop:
                try:
                    loop.close()
                except Exception:
                    pass
            self._loop = None
            self._master = None

    def stop(self):
        """停止代理服务器"""
        if not self._running:
            return

        self._running = False

        if self._master:
            try:
                if self._loop and self._loop.is_running():
                    self._loop.call_soon_threadsafe(self._master.shutdown)
                else:
                    self._master.shutdown()
            except Exception as e:
                logger.error(f"关闭代理服务时出错: {e}")

        # 等待线程结束
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
            if self._thread.is_alive():
                logger.warning("代理线程未能在5秒内结束")

        # 清理资源引用
        self._thread = None
        self._loop = None

    @property
    def is_running(self) -> bool:
        """返回代理服务器运行状态"""
        return self._running
