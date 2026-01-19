"""
全局代理服务管理器
"""

from typing import Optional
from .proxy_server import ProxyServer
from .statistics import RequestStatistics


class ProxyServiceManager:
    """代理服务管理器 - 单例模式"""

    _instance = None
    _proxy_server: Optional[ProxyServer] = None
    _statistics: RequestStatistics = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._statistics = RequestStatistics()
        return cls._instance

    @classmethod
    def get_instance(cls) -> 'ProxyServiceManager':
        """获取管理器实例"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def is_running(self) -> bool:
        """检查代理服务是否运行"""
        return self._proxy_server is not None and self._proxy_server.is_running

    def get_server(self) -> Optional[ProxyServer]:
        """获取当前代理服务器实例"""
        return self._proxy_server

    def get_statistics(self) -> RequestStatistics:
        """获取统计实例"""
        return self._statistics

    def start_service(self, host: str, port: int, on_request=None, on_response=None) -> ProxyServer:
        """启动代理服务"""
        if self.is_running():
            self.stop_service()

        self._proxy_server = ProxyServer(
            host=host,
            port=port,
            on_request=on_request,
            on_response=on_response
        )

        self._proxy_server.start()
        return self._proxy_server

    def stop_service(self):
        """停止代理服务"""
        if self._proxy_server:
            self._proxy_server.stop()
            self._proxy_server = None
