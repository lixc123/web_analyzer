"""
代理服务器主类
"""

from typing import Optional, Callable
import threading
import asyncio
from mitmproxy.tools.dump import DumpMaster
from mitmproxy import options


class ProxyServer:
    """代理服务器核心类"""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8888,
        on_request: Optional[Callable] = None,
        on_response: Optional[Callable] = None
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
        self._running = False
        self._master = None
        self._thread = None

    def start(self):
        """启动代理服务器"""
        if self._running:
            raise RuntimeError("代理服务器已在运行")

        max_retries = 3
        current_port = self.port

        for attempt in range(max_retries):
            try:
                # 创建 mitmproxy 配置
                opts = options.Options(
                    listen_host=self.host,
                    listen_port=current_port,
                    ssl_insecure=True
                )

                # 创建 DumpMaster 实例
                self._master = DumpMaster(opts)

                # 添加请求拦截器插件
                from .request_handler import RequestInterceptor
                interceptor = RequestInterceptor(self.on_request, self.on_response)
                self._master.addons.add(interceptor)

                # 在独立线程中启动代理服务
                self._running = True
                self._thread = threading.Thread(target=self._run, daemon=True)
                self._thread.start()

                # 更新端口（如果重试后端口改变）
                self.port = current_port
                print(f"代理服务成功启动在端口 {current_port}")
                return

            except OSError as e:
                if "address already in use" in str(e).lower() or "被占用" in str(e):
                    print(f"端口 {current_port} 被占用，尝试下一个端口...")
                    current_port += 1
                    if attempt < max_retries - 1:
                        continue
                raise RuntimeError(f"启动代理服务失败，尝试了 {max_retries} 次: {str(e)}")
            except Exception as e:
                print(f"启动代理服务时出错 (尝试 {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    continue
                raise

    def _run(self):
        """在独立线程中运行事件循环"""
        try:
            # 创建新的事件循环
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            # 运行代理服务
            self._master.run()
        except Exception as e:
            print(f"代理服务运行错误: {e}")
            self._running = False

    def stop(self):
        """停止代理服务器"""
        if not self._running:
            return

        if self._master:
            self._master.shutdown()

        self._running = False

    @property
    def is_running(self) -> bool:
        """返回代理服务器运行状态"""
        return self._running
