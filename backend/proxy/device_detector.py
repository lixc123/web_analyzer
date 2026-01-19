"""设备信息检测模块"""
import re
from typing import Optional, Dict


class DeviceDetector:
    """设备信息检测器"""

    @staticmethod
    def detect(user_agent: str) -> Dict[str, Optional[str]]:
        """从 User-Agent 中提取设备信息"""
        if not user_agent:
            return {"platform": "unknown", "device": None, "os_version": None, "app": None}

        # iOS 设备检测
        if "iPhone" in user_agent or "iPad" in user_agent or "iPod" in user_agent:
            device = "iPhone" if "iPhone" in user_agent else ("iPad" if "iPad" in user_agent else "iPod")
            os_match = re.search(r"OS (\d+)[_.](\d+)", user_agent)
            os_version = f"{os_match.group(1)}.{os_match.group(2)}" if os_match else None
            return {"platform": "iOS", "device": device, "os_version": os_version, "app": None}

        # Android 设备检测
        if "Android" in user_agent:
            os_match = re.search(r"Android (\d+\.?\d*)", user_agent)
            os_version = os_match.group(1) if os_match else None
            device_match = re.search(r";\s*([^;)]+)\s+Build", user_agent)
            device = device_match.group(1).strip() if device_match else "Android"
            return {"platform": "Android", "device": device, "os_version": os_version, "app": None}

        # 桌面浏览器
        if "Windows" in user_agent:
            return {"platform": "Windows", "device": "PC", "os_version": None, "app": None}
        if "Macintosh" in user_agent or "Mac OS X" in user_agent:
            return {"platform": "macOS", "device": "Mac", "os_version": None, "app": None}
        if "Linux" in user_agent:
            return {"platform": "Linux", "device": "PC", "os_version": None, "app": None}

        return {"platform": "unknown", "device": None, "os_version": None, "app": None}
