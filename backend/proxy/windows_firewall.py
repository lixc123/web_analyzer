"""
Windows防火墙管理
"""

import subprocess
import logging

logger = logging.getLogger(__name__)


class WindowsFirewall:
    """Windows防火墙管理器"""

    def __init__(self):
        """初始化防火墙管理器"""
        pass

    def check_rule_exists(self, rule_name: str) -> bool:
        """检查防火墙规则是否存在"""
        try:
            result = subprocess.run(
                f'netsh advfirewall firewall show rule name="{rule_name}"',
                shell=True,
                capture_output=True,
                text=True
            )
            return "No rules match" not in result.stdout and result.returncode == 0
        except Exception as e:
            logger.error(f"检查防火墙规则失败: {e}")
            return False

    def add_rule(self, port: int, rule_name: str = "WebAnalyzer Proxy") -> bool:
        """添加防火墙规则"""
        try:
            # 检查规则是否已存在
            if self.check_rule_exists(rule_name):
                logger.info(f"防火墙规则 '{rule_name}' 已存在")
                return True

            # 添加规则
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=allow protocol=TCP localport={port}'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if result.returncode == 0:
                logger.info(f"防火墙规则 '{rule_name}' 添加成功")
                return True
            else:
                logger.error(f"添加防火墙规则失败: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"添加防火墙规则时出错: {e}")
            return False

    def remove_rule(self, rule_name: str = "WebAnalyzer Proxy") -> bool:
        """删除防火墙规则"""
        try:
            if not self.check_rule_exists(rule_name):
                logger.info(f"防火墙规则 '{rule_name}' 不存在")
                return True

            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if result.returncode == 0:
                logger.info(f"防火墙规则 '{rule_name}' 删除成功")
                return True
            else:
                logger.error(f"删除防火墙规则失败: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"删除防火墙规则时出错: {e}")
            return False
