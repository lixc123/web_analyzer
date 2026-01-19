"""
全局代理服务管理器
"""

from typing import Optional, Dict, List
from datetime import datetime
import threading
import logging
from .proxy_server import ProxyServer
from .statistics import RequestStatistics
from .filters import RequestFilter

logger = logging.getLogger(__name__)


class ProxyServiceManager:
    """代理服务管理器 - 单例模式"""

    _instance = None
    _lock = threading.Lock()
    _proxy_server: Optional[ProxyServer] = None
    _statistics: Optional[RequestStatistics] = None
    _firewall_rule_name: Optional[str] = None
    _devices: Optional[Dict[str, dict]] = None
    _filter: Optional[RequestFilter] = None
    _storage = None
    _system_proxy_enabled: bool = False
    _main_event_loop = None
    _system_proxy_instance = None  # 保存系统代理实例

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                # 双重检查锁定
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._statistics = RequestStatistics()
                    cls._instance._devices = {}
                    cls._instance._filter = RequestFilter()
                    cls._instance._devices_lock = threading.Lock()

                    # 初始化存储
                    from backend.app.services.request_storage import RequestStorage
                    cls._instance._storage = RequestStorage()
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

    def track_device(self, device_info: dict):
        """跟踪设备"""
        import hashlib
        import copy

        # 深拷贝设备信息，避免外部修改影响
        device_info = copy.deepcopy(device_info)

        # 使用User-Agent哈希生成唯一键，避免冲突
        user_agent = device_info.get('user_agent', '')
        platform = device_info.get('platform', 'unknown')
        device = device_info.get('device', 'unknown')

        # 生成唯一设备键：使用User-Agent的完整MD5哈希值
        if user_agent:
            ua_hash = hashlib.md5(user_agent.encode()).hexdigest()
            device_key = f"{platform}_{device}_{ua_hash}"
        else:
            device_key = f"{platform}_{device}_unknown"

        with self._devices_lock:
            if device_key not in self._devices:
                self._devices[device_key] = {
                    **device_info,
                    'first_seen': datetime.now().isoformat(),
                    'request_count': 0
                }
            self._devices[device_key]['request_count'] += 1
            self._devices[device_key]['last_seen'] = datetime.now().isoformat()

    def get_devices(self) -> List[dict]:
        """获取设备列表"""
        with self._devices_lock:
            return list(self._devices.values())

    def get_filter(self) -> RequestFilter:
        """获取过滤器实例"""
        return self._filter

    def get_storage(self):
        """获取存储实例"""
        return self._storage

    def set_main_event_loop(self, loop):
        """设置主事件循环"""
        self._main_event_loop = loop

    def get_main_event_loop(self):
        """获取主事件循环"""
        return self._main_event_loop

    def start_service(self, host: str, port: int, enable_system_proxy: bool = False, on_request=None, on_response=None) -> ProxyServer:
        """启动代理服务"""
        with self._lock:
            if self.is_running():
                self.stop_service()

            # 记录是否启用系统代理
            self._system_proxy_enabled = enable_system_proxy

            # 配置防火墙
            try:
                from .windows_firewall import WindowsFirewall
                firewall = WindowsFirewall()
                rule_name = f"WebAnalyzer Proxy {port}"
                if firewall.add_rule(port, rule_name):
                    self._firewall_rule_name = rule_name
            except Exception as e:
                logger.warning(f"配置防火墙失败（非致命错误）: {e}")

            self._proxy_server = ProxyServer(
                host=host,
                port=port,
                on_request=on_request,
                on_response=on_response
            )

            # 启动代理服务，返回实际使用的端口
            actual_port = self._proxy_server.start()

            # 如果端口发生变化，更新防火墙规则
            if actual_port != port:
                logger.info(f"端口从 {port} 变更为 {actual_port}")
                if self._firewall_rule_name:
                    try:
                        from .windows_firewall import WindowsFirewall
                        firewall = WindowsFirewall()
                        # 先添加新规则
                        new_rule_name = f"WebAnalyzer Proxy {actual_port}"
                        if firewall.add_rule(actual_port, new_rule_name):
                            # 新规则添加成功后，再删除旧规则
                            firewall.remove_rule(self._firewall_rule_name)
                            self._firewall_rule_name = new_rule_name
                        else:
                            logger.warning(f"添加新防火墙规则失败，保留旧规则")
                    except Exception as e:
                        logger.warning(f"更新防火墙规则失败: {e}")

            return self._proxy_server

    def stop_service(self):
        """停止代理服务"""
        if self._proxy_server:
            self._proxy_server.stop()
            self._proxy_server = None

        # 清理防火墙规则
        if self._firewall_rule_name:
            try:
                from .windows_firewall import WindowsFirewall
                firewall = WindowsFirewall()
                firewall.remove_rule(self._firewall_rule_name)
                self._firewall_rule_name = None
            except Exception as e:
                logger.warning(f"清理防火墙规则失败: {e}")

    def is_system_proxy_enabled(self) -> bool:
        """检查是否启用了系统代理"""
        return self._system_proxy_enabled

    def get_system_proxy_instance(self):
        """获取系统代理实例"""
        return self._system_proxy_instance

    def set_system_proxy_instance(self, instance):
        """设置系统代理实例"""
        self._system_proxy_instance = instance
