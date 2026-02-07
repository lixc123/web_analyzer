"""Windows WinHTTP 代理设置。

WinHTTP 与 WinINet(IE/Internet Settings) 是两套不同的代理栈：
- WinINet：多数浏览器/基于 IE 设置的应用使用
- WinHTTP：不少桌面应用/服务组件使用（不一定跟随 WinINet）

本模块通过 `netsh winhttp` 管理 WinHTTP 代理，并支持回滚到原始状态。
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9 .,:;=/_\\-]+$")


def _is_windows() -> bool:
    return os.name == "nt"


def _run_netsh(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["netsh", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
    )


@dataclass(frozen=True)
class WinHttpProxySettings:
    mode: str  # direct|proxy|unknown
    proxy_server: str = ""
    bypass_list: str = ""
    raw_output: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "supported": _is_windows(),
            "mode": self.mode,
            "proxy_server": self.proxy_server,
            "bypass_list": self.bypass_list,
            "raw_output": self.raw_output,
        }


class WindowsWinHttpProxy:
    """WinHTTP 代理管理器（通过 netsh winhttp）。"""

    def __init__(self):
        self._original_settings: Optional[WinHttpProxySettings] = None

    def get_current_settings(self) -> WinHttpProxySettings:
        if not _is_windows():
            return WinHttpProxySettings(mode="unknown", raw_output="not_windows")

        proc = _run_netsh(["winhttp", "show", "proxy"])
        output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        if proc.returncode != 0:
            # 权限不足/系统缺失时也返回结构化信息，便于前端诊断展示
            return WinHttpProxySettings(mode="unknown", raw_output=output.strip() or f"netsh_error_{proc.returncode}")

        text = proc.stdout or ""
        # 常见输出：
        # "Direct access (no proxy server)."
        if "Direct access" in text:
            return WinHttpProxySettings(mode="direct", raw_output=text.strip())

        proxy_server = ""
        bypass_list = ""

        # 兼容不同语言/格式：抓取 “Proxy Server(s)” 与 “Bypass List”
        for line in text.splitlines():
            line_stripped = line.strip()
            if not line_stripped:
                continue
            if "Proxy Server" in line_stripped:
                # e.g. Proxy Server(s) :  127.0.0.1:8888
                parts = line_stripped.split(":", 1)
                if len(parts) == 2:
                    proxy_server = parts[1].strip()
            if "Bypass List" in line_stripped:
                parts = line_stripped.split(":", 1)
                if len(parts) == 2:
                    bypass_list = parts[1].strip()

        if proxy_server:
            return WinHttpProxySettings(mode="proxy", proxy_server=proxy_server, bypass_list=bypass_list, raw_output=text.strip())

        return WinHttpProxySettings(mode="unknown", raw_output=text.strip())

    def enable_proxy(self, host: str = "127.0.0.1", port: int = 8888, bypass_list: str = "localhost;127.*;192.168.*;<local>") -> None:
        if not _is_windows():
            raise RuntimeError("WinHTTP 代理仅支持 Windows")

        if self._original_settings is None:
            self._original_settings = self.get_current_settings()

        proxy_server = f"{host}:{int(port)}"
        if not _SAFE_TOKEN_RE.match(proxy_server) or not _SAFE_TOKEN_RE.match(bypass_list):
            raise ValueError("参数包含不安全字符")

        proc = _run_netsh(["winhttp", "set", "proxy", proxy_server, bypass_list])
        if proc.returncode != 0:
            msg = (proc.stderr or proc.stdout or "").strip()
            raise RuntimeError(f"设置 WinHTTP 代理失败: {msg or proc.returncode}")

        logger.info("WinHTTP 代理已启用: %s (bypass=%s)", proxy_server, bypass_list)

    def reset_proxy(self) -> None:
        if not _is_windows():
            raise RuntimeError("WinHTTP 代理仅支持 Windows")

        proc = _run_netsh(["winhttp", "reset", "proxy"])
        if proc.returncode != 0:
            msg = (proc.stderr or proc.stdout or "").strip()
            raise RuntimeError(f"重置 WinHTTP 代理失败: {msg or proc.returncode}")

        logger.info("WinHTTP 代理已重置为 Direct")

    def import_from_ie(self) -> None:
        """将 WinINet(IE) 代理导入到 WinHTTP。

        注意：此操作并不一定能反映 PAC/自动代理的全部行为，但对多数场景有帮助。
        """
        if not _is_windows():
            raise RuntimeError("WinHTTP 代理仅支持 Windows")

        if self._original_settings is None:
            self._original_settings = self.get_current_settings()

        proc = _run_netsh(["winhttp", "import", "proxy", "source=ie"])
        if proc.returncode != 0:
            msg = (proc.stderr or proc.stdout or "").strip()
            raise RuntimeError(f"导入 IE 代理到 WinHTTP 失败: {msg or proc.returncode}")

        logger.info("WinHTTP 代理已从 IE 导入")

    def restore_original(self) -> None:
        if self._original_settings is None:
            return

        settings = self._original_settings
        try:
            if settings.mode == "direct":
                self.reset_proxy()
                return
            if settings.mode == "proxy" and settings.proxy_server:
                bypass_list = settings.bypass_list or "localhost;127.*;192.168.*;<local>"
                proc = _run_netsh(["winhttp", "set", "proxy", settings.proxy_server, bypass_list])
                if proc.returncode != 0:
                    msg = (proc.stderr or proc.stdout or "").strip()
                    raise RuntimeError(f"恢复 WinHTTP 代理失败: {msg or proc.returncode}")
                logger.info("WinHTTP 代理已恢复: %s", settings.proxy_server)
                return
        except Exception as exc:
            logger.error("恢复 WinHTTP 代理失败: %s", exc)
            raise
