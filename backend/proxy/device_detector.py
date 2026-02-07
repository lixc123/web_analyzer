"""设备信息检测模块"""
import re
from typing import Optional, Dict


class DeviceDetector:
    """设备信息检测器"""

    @staticmethod
    def detect(user_agent: str) -> Dict[str, Optional[str]]:
        """从 User-Agent 中提取设备信息"""
        if not user_agent:
            return {"platform": "unknown", "device": None, "os_version": None, "browser": None, "app": None}

        ua = user_agent

        # 简单浏览器识别（桌面优先）
        browser = None
        try:
            if "Edg/" in ua or "EdgA/" in ua or "EdgiOS/" in ua:
                browser = "Edge"
            elif "Chrome/" in ua and "Chromium" not in ua and "Edg/" not in ua:
                browser = "Chrome"
            elif "Firefox/" in ua:
                browser = "Firefox"
            elif "Safari/" in ua and "Chrome/" not in ua and "Chromium" not in ua:
                browser = "Safari"
        except Exception:
            browser = None

        # iOS 设备检测
        if "iPhone" in user_agent or "iPad" in user_agent or "iPod" in user_agent:
            device = "iPhone" if "iPhone" in user_agent else ("iPad" if "iPad" in user_agent else "iPod")
            os_match = re.search(r"OS (\d+)[_.](\d+)", user_agent)
            os_version = f"{os_match.group(1)}.{os_match.group(2)}" if os_match else None
            return {"platform": "iOS", "device": device, "os_version": os_version, "browser": browser, "app": None}

        # Android 设备检测
        if "Android" in user_agent:
            os_match = re.search(r"Android (\d+\.?\d*)", user_agent)
            os_version = os_match.group(1) if os_match else None
            device_match = re.search(r";\s*([^;)]+)\s+Build", user_agent)
            device = device_match.group(1).strip() if device_match else "Android"
            return {"platform": "Android", "device": device, "os_version": os_version, "browser": browser, "app": None}

        # 桌面浏览器
        if "Windows" in user_agent:
            win_match = re.search(r"Windows NT (\d+)\.(\d+)", user_agent)
            os_version = f"{win_match.group(1)}.{win_match.group(2)}" if win_match else None
            return {"platform": "Windows", "device": "PC", "os_version": os_version, "browser": browser, "app": None}
        if "Macintosh" in user_agent or "Mac OS X" in user_agent:
            mac_match = re.search(r"Mac OS X (\d+)[_.](\d+)", user_agent)
            os_version = f"{mac_match.group(1)}.{mac_match.group(2)}" if mac_match else None
            return {"platform": "macOS", "device": "Mac", "os_version": os_version, "browser": browser, "app": None}
        if "Linux" in user_agent:
            return {"platform": "Linux", "device": "PC", "os_version": None, "browser": browser, "app": None}

        return {"platform": "unknown", "device": None, "os_version": None, "browser": browser, "app": None}
