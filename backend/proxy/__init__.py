"""
代理服务核心模块
"""

import sys

from .proxy_server import ProxyServer
from .request_handler import RequestInterceptor
from .cert_manager import CertManager

__all__ = ['ProxyServer', 'RequestInterceptor', 'CertManager']

# Windows-only helpers (e.g. registry-based system proxy).
if sys.platform == "win32":
    from .system_proxy import WindowsSystemProxy  # noqa: F401
    from .winhttp_proxy import WindowsWinHttpProxy  # noqa: F401

    __all__.append('WindowsSystemProxy')
    __all__.append('WindowsWinHttpProxy')
