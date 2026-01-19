"""
CA证书管理
"""

from typing import Optional


class CertManager:
    """证书管理器"""

    def __init__(self, cert_dir: Optional[str] = None):
        """
        初始化证书管理器

        Args:
            cert_dir: 证书目录路径，默认为 ~/.mitmproxy
        """
        self.cert_dir = cert_dir

    def ensure_ca_exists(self) -> bool:
        """确保CA证书存在"""
        pass

    def get_cert_path(self) -> str:
        """获取CA证书文件路径"""
        pass

    def get_cert_for_mobile(self) -> dict:
        """获取移动端安装所需的证书信息"""
        pass

    def generate_qr_code(self, download_url: str) -> str:
        """生成证书下载页面的二维码"""
        pass

    def install_cert_windows(self) -> bool:
        """在Windows系统中安装CA证书"""
        pass

    def uninstall_cert_windows(self) -> bool:
        """从Windows系统中移除CA证书"""
        pass

    def get_mobile_install_instructions(self, server_ip: str, port: int) -> dict:
        """获取移动端证书安装说明"""
        pass
