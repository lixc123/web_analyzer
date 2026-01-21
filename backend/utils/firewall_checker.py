"""Windows防火墙状态检查工具"""
import subprocess
import logging
import platform

logger = logging.getLogger(__name__)


class FirewallChecker:
    """Windows防火墙状态检查器"""

    @staticmethod
    def check_firewall_status() -> dict:
        """检查Windows防火墙状态
        
        Returns:
            dict: 包含防火墙状态信息的字典
        """
        if platform.system() != 'Windows':
            return {
                "supported": False,
                "message": "仅支持Windows系统",
                "enabled": None,
                "profiles": {}
            }

        try:
            # 使用netsh命令检查防火墙状态
            result = subprocess.run(
                ['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode != 0:
                logger.error(f"检查防火墙状态失败: {result.stderr}")
                return {
                    "supported": True,
                    "enabled": None,
                    "message": "无法获取防火墙状态",
                    "error": result.stderr,
                    "profiles": {}
                }

            # 解析输出
            output = result.stdout
            profiles = {}
            current_profile = None

            for line in output.split('\n'):
                line = line.strip()
                if '配置文件设置' in line or 'Profile Settings' in line:
                    # 提取配置文件名称
                    if '域' in line or 'Domain' in line:
                        current_profile = 'domain'
                    elif '专用' in line or 'Private' in line:
                        current_profile = 'private'
                    elif '公用' in line or 'Public' in line:
                        current_profile = 'public'
                elif '状态' in line or 'State' in line:
                    if current_profile:
                        # 提取状态
                        if '启用' in line or 'ON' in line.upper():
                            profiles[current_profile] = True
                        elif '禁用' in line or 'OFF' in line.upper():
                            profiles[current_profile] = False

            # 判断整体状态（任一配置文件启用即认为防火墙启用）
            enabled = any(profiles.values()) if profiles else None

            return {
                "supported": True,
                "enabled": enabled,
                "message": "防火墙已启用" if enabled else "防火墙已禁用" if enabled is False else "状态未知",
                "profiles": profiles
            }

        except subprocess.TimeoutExpired:
            logger.error("检查防火墙状态超时")
            return {
                "supported": True,
                "enabled": None,
                "message": "检查超时",
                "profiles": {}
            }
        except Exception as e:
            logger.error(f"检查防火墙状态异常: {e}")
            return {
                "supported": True,
                "enabled": None,
                "message": f"检查失败: {str(e)}",
                "profiles": {}
            }

    @staticmethod
    def check_port_rule(port: int) -> dict:
        """检查指定端口的防火墙规则
        
        Args:
            port: 端口号
            
        Returns:
            dict: 端口规则信息
        """
        if platform.system() != 'Windows':
            return {
                "supported": False,
                "message": "仅支持Windows系统",
                "has_rule": None
            }

        try:
            # 检查入站规则
            result = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name=all'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                return {
                    "supported": True,
                    "has_rule": None,
                    "message": "无法获取防火墙规则"
                }

            # 检查输出中是否包含该端口
            output = result.stdout
            has_rule = str(port) in output

            return {
                "supported": True,
                "has_rule": has_rule,
                "message": f"端口 {port} {'已' if has_rule else '未'}配置防火墙规则",
                "port": port
            }

        except Exception as e:
            logger.error(f"检查端口规则异常: {e}")
            return {
                "supported": True,
                "has_rule": None,
                "message": f"检查失败: {str(e)}",
                "port": port
            }

    @staticmethod
    def get_firewall_recommendations(port: int) -> list:
        """获取防火墙配置建议
        
        Args:
            port: 代理服务端口
            
        Returns:
            list: 建议列表
        """
        recommendations = []
        
        status = FirewallChecker.check_firewall_status()
        
        if not status.get("supported"):
            return ["当前系统不支持自动检查防火墙状态"]
        
        if status.get("enabled"):
            recommendations.append(f"防火墙已启用，请确保端口 {port} 已添加到允许列表")
            
            port_rule = FirewallChecker.check_port_rule(port)
            if not port_rule.get("has_rule"):
                recommendations.append(
                    f"建议添加防火墙规则：\n"
                    f"netsh advfirewall firewall add rule name=\"Proxy Server\" "
                    f"dir=in action=allow protocol=TCP localport={port}"
                )
        else:
            recommendations.append("防火墙已禁用，无需额外配置")
        
        return recommendations
