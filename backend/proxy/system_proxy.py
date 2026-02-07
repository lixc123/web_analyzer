"""Windows WinINet(系统/IE) 代理设置。

注意：WinINet 与 WinHTTP 是两套不同的代理栈。
这里管理的是 WinINet（通常等同于“系统代理/IE 设置”）。

为了避免误伤非 Windows 环境，本模块尽量在运行时导入 winreg。
"""

from __future__ import annotations

import ctypes
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class WindowsSystemProxy:
    """Windows系统代理管理器"""

    INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

    def __init__(self):
        """初始化系统代理管理器"""
        self._original_settings: Optional[Dict[str, Any]] = None

    @staticmethod
    def _is_windows() -> bool:
        return os.name == "nt"

    @staticmethod
    def _parse_proxy_server(proxy_server: str) -> Dict[str, str]:
        """解析 ProxyServer 字符串。

        支持形态：
        - "127.0.0.1:8888"
        - "http=127.0.0.1:8888;https=127.0.0.1:8888"
        - "socks=127.0.0.1:1080;http=..."
        """
        raw = (proxy_server or "").strip()
        if not raw:
            return {}

        out: Dict[str, str] = {}
        parts = [p.strip() for p in raw.split(";") if p.strip()]
        for p in parts:
            if "=" in p:
                k, v = p.split("=", 1)
                k = k.strip().lower()
                v = v.strip()
                if k and v:
                    out[k] = v
            else:
                out["all"] = p
        return out

    def get_current_raw_settings(self) -> Dict[str, Any]:
        """读取当前 WinINet 代理原始设置（注册表字段）。"""
        if not self._is_windows():
            return {"supported": False, "error": "not_windows"}

        try:
            import winreg

            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.INTERNET_SETTINGS, 0, winreg.KEY_READ)
            try:
                def _read(name: str):
                    try:
                        value, _ = winreg.QueryValueEx(key, name)
                        return value
                    except (FileNotFoundError, OSError):
                        return None

                return {
                    "supported": True,
                    "ProxyEnable": int(_read("ProxyEnable") or 0),
                    "ProxyServer": str(_read("ProxyServer") or ""),
                    "ProxyOverride": str(_read("ProxyOverride") or ""),
                    "AutoConfigURL": str(_read("AutoConfigURL") or ""),
                    "AutoDetect": int(_read("AutoDetect") or 0),
                }
            finally:
                try:
                    winreg.CloseKey(key)
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"读取系统代理设置失败: {e}")
            return {"supported": True, "error": str(e)}

    def get_current_settings(self) -> Dict[str, Any]:
        """读取当前系统代理设置（结构化）。"""
        raw = self.get_current_raw_settings()
        if not raw.get("supported"):
            return {"supported": False, "enabled": False, "host": "", "port": 0, "raw": raw}

        if raw.get("error"):
            return {"supported": True, "enabled": False, "host": "", "port": 0, "raw": raw}

        proxy_enable = bool(int(raw.get("ProxyEnable", 0) or 0))
        proxy_server = str(raw.get("ProxyServer") or "")
        proxies = self._parse_proxy_server(proxy_server)

        # 推断主代理地址（优先 https/http，其次 all）
        candidate = proxies.get("https") or proxies.get("http") or proxies.get("all") or ""
        host, port = "", 0
        if candidate and ":" in candidate:
            h, p = candidate.rsplit(":", 1)
            host = h.strip()
            try:
                port = int(p.strip())
            except Exception:
                port = 0

        return {
            "supported": True,
            "proxy_enabled": proxy_enable,
            "proxy_server": proxy_server,
            "proxy_override": str(raw.get("ProxyOverride") or ""),
            "auto_config_url": str(raw.get("AutoConfigURL") or ""),
            "auto_detect": bool(int(raw.get("AutoDetect", 0) or 0)),
            "proxies": proxies,
            "enabled": proxy_enable,  # 兼容旧字段
            "host": host,
            "port": port,
        }

    def enable_proxy(
        self,
        host: str = "127.0.0.1",
        port: int = 8888,
        proxy_override: str = "localhost;127.*;192.168.*;<local>",
        per_protocol: bool = True,
    ):
        """启用 WinINet 系统代理。

        Args:
            host/port: 代理地址
            proxy_override: 绕过列表
            per_protocol: True 时写入 "http=...;https=..."，避免部分应用仅读取单协议字段
        """
        if not self._is_windows():
            raise RuntimeError("系统代理设置仅支持 Windows")

        try:
            import winreg

            # 保存原始设置（完整字段）
            if self._original_settings is None:
                self._original_settings = self.get_current_raw_settings()

            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE)
            try:
                proxy_value = f"{host}:{int(port)}"
                if per_protocol:
                    proxy_value = f"http={proxy_value};https={proxy_value}"

                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_value)
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, str(proxy_override or ""))
            finally:
                winreg.CloseKey(key)

            self._refresh_settings()
            logger.info(f"系统代理(WinINet)已启用: {host}:{port} (per_protocol={per_protocol})")
        except Exception as e:
            logger.error(f"启用系统代理失败: {e}")
            raise

    def disable_proxy(self):
        """禁用系统代理"""
        if not self._is_windows():
            return

        try:
            import winreg

            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE)
            try:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            finally:
                winreg.CloseKey(key)

            self._refresh_settings()
            logger.info("系统代理(WinINet)已禁用")
        except Exception as e:
            logger.error(f"禁用系统代理失败: {e}")

    def restore_original(self):
        """恢复原始代理设置"""
        if not self._is_windows():
            return

        if self._original_settings is None:
            # 没有快照时，尽力关闭
            self.disable_proxy()
            return

        try:
            import winreg

            original = dict(self._original_settings)
            if original.get("supported") is False:
                self.disable_proxy()
                return

            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE)
            try:
                # 按字段恢复；空字符串也要恢复（用于清理之前写入的值）
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, int(original.get("ProxyEnable", 0) or 0))
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, str(original.get("ProxyServer") or ""))
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, str(original.get("ProxyOverride") or ""))

                # AutoConfigURL/AutoDetect 可能不存在，存在时恢复；否则尽量删除/置空
                winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, str(original.get("AutoConfigURL") or ""))
                winreg.SetValueEx(key, "AutoDetect", 0, winreg.REG_DWORD, int(original.get("AutoDetect", 0) or 0))
            finally:
                winreg.CloseKey(key)

            self._refresh_settings()
            logger.info("系统代理(WinINet)已恢复到原始状态")
        except Exception as e:
            logger.error(f"恢复系统代理失败: {e}")

    def _refresh_settings(self):
        """刷新系统网络设置"""
        if not self._is_windows():
            return

        try:
            INTERNET_OPTION_SETTINGS_CHANGED = 39
            INTERNET_OPTION_REFRESH = 37

            internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
            internet_set_option(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            internet_set_option(0, INTERNET_OPTION_REFRESH, 0, 0)
        except Exception as e:
            logger.warning(f"刷新系统设置失败: {e}")
