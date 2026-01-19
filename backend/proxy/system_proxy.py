"""
Windows系统代理设置
"""

import winreg
import ctypes
import logging

logger = logging.getLogger(__name__)


class WindowsSystemProxy:
    """Windows系统代理管理器"""

    INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

    def __init__(self):
        """初始化系统代理管理器"""
        self._original_settings = None

    def get_current_settings(self) -> dict:
        """读取当前系统代理设置"""
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.INTERNET_SETTINGS, 0, winreg.KEY_READ)

            try:
                proxy_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
            except (FileNotFoundError, OSError):
                proxy_enable = 0

            try:
                proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
            except (FileNotFoundError, OSError):
                proxy_server = ""

            winreg.CloseKey(key)

            # 解析 host:port
            host, port = "", 0
            if proxy_server and ":" in proxy_server:
                parts = proxy_server.split(":", 1)
                host = parts[0]
                try:
                    port = int(parts[1]) if len(parts) > 1 and parts[1] else 0
                except (ValueError, IndexError):
                    port = 0

            return {
                "enabled": bool(proxy_enable),
                "host": host,
                "port": port
            }
        except Exception as e:
            logger.error(f"读取系统代理设置失败: {e}")
            return {"enabled": False, "host": "", "port": 0}

    def enable_proxy(self, host: str = "127.0.0.1", port: int = 8888):
        """启用系统代理"""
        try:
            # 保存原始设置
            if self._original_settings is None:
                self._original_settings = self.get_current_settings()

            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.INTERNET_SETTINGS, 0, winreg.KEY_WRITE)

            # 设置代理
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"{host}:{port}")
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "localhost;127.*;192.168.*;<local>")

            winreg.CloseKey(key)

            # 刷新设置
            self._refresh_settings()

            logger.info(f"系统代理已启用: {host}:{port}")
        except Exception as e:
            logger.error(f"启用系统代理失败: {e}")
            raise

    def disable_proxy(self):
        """禁用系统代理"""
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.INTERNET_SETTINGS, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)

            self._refresh_settings()
            logger.info("系统代理已禁用")
        except Exception as e:
            logger.error(f"禁用系统代理失败: {e}")

    def restore_original(self):
        """恢复原始代理设置"""
        if self._original_settings is None:
            return

        try:
            if self._original_settings["enabled"] and self._original_settings["host"] and self._original_settings["port"]:
                # 只有在原始设置有效时才恢复
                self.enable_proxy(
                    host=self._original_settings["host"],
                    port=self._original_settings["port"]
                )
            else:
                # 否则直接禁用代理
                self.disable_proxy()

            logger.info("系统代理已恢复到原始状态")
        except Exception as e:
            logger.error(f"恢复系统代理失败: {e}")

    def _refresh_settings(self):
        """刷新系统网络设置"""
        try:
            INTERNET_OPTION_SETTINGS_CHANGED = 39
            INTERNET_OPTION_REFRESH = 37

            internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
            internet_set_option(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            internet_set_option(0, INTERNET_OPTION_REFRESH, 0, 0)
        except Exception as e:
            logger.warning(f"刷新系统设置失败: {e}")
