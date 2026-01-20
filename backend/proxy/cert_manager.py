"""
CA证书管理
"""

import os
import base64
import subprocess
from pathlib import Path
from typing import Optional
from io import BytesIO


class CertManager:
    """证书管理器"""

    def __init__(self, cert_dir: Optional[str] = None):
        """
        初始化证书管理器

        Args:
            cert_dir: 证书目录路径，默认为 ~/.mitmproxy
        """
        if cert_dir is None:
            cert_dir = os.path.expanduser("~/.mitmproxy")

        self.cert_dir = cert_dir
        self.ca_cert_path = os.path.join(cert_dir, "mitmproxy-ca-cert.pem")
        self.ca_cert_cer_path = os.path.join(cert_dir, "mitmproxy-ca-cert.cer")

    def ensure_ca_exists(self) -> bool:
        """确保CA证书存在"""
        try:
            os.makedirs(self.cert_dir, exist_ok=True)
            return os.path.exists(self.ca_cert_path)
        except Exception as e:
            print(f"创建证书目录失败: {e}")
            return False

    def get_cert_path(self) -> str:
        """获取CA证书文件路径"""
        return self.ca_cert_path

    def get_cert_for_mobile(self) -> dict:
        """获取移动端安装所需的证书信息"""
        try:
            if not os.path.exists(self.ca_cert_path):
                return {"error": "证书文件不存在"}

            with open(self.ca_cert_path, 'rb') as f:
                cert_content = f.read()

            return {
                "path": self.ca_cert_path,
                "content_base64": base64.b64encode(cert_content).decode('utf-8'),
                "filename": "mitmproxy-ca-cert.pem"
            }
        except Exception as e:
            return {"error": f"读取证书失败: {e}"}

    def generate_qr_code(self, download_url: str) -> str:
        """生成证书下载页面的二维码"""
        try:
            import qrcode

            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(download_url)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")

            buffer = BytesIO()
            img.save(buffer, format='PNG')
            buffer.seek(0)

            return base64.b64encode(buffer.getvalue()).decode('utf-8')
        except Exception as e:
            print(f"生成二维码失败: {e}")
            return ""

    def install_cert_windows(self) -> bool:
        """在Windows系统中安装CA证书"""
        try:
            if not os.path.exists(self.ca_cert_path):
                print("证书文件不存在")
                return False

            cmd = f'certutil -addstore -user Root "{self.ca_cert_path}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if result.returncode == 0:
                print("证书安装成功")
                return True
            else:
                print(f"证书安装失败: {result.stderr}")
                return False
        except Exception as e:
            print(f"安装证书时出错: {e}")
            return False

    def uninstall_cert_windows(self) -> bool:
        """从Windows系统中移除CA证书"""
        try:
            cmd = 'certutil -delstore -user Root mitmproxy'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if result.returncode == 0:
                print("证书卸载成功")
                return True
            else:
                print(f"证书卸载失败: {result.stderr}")
                return False
        except Exception as e:
            print(f"卸载证书时出错: {e}")
            return False

    def get_mobile_install_instructions(self, server_ip: str, port: int) -> dict:
        """获取移动端证书安装说明"""
        return {
            "ios": [
                f"1. 在iOS设备上连接到与电脑相同的WiFi网络",
                f"2. 打开Safari浏览器，访问 http://{server_ip}:{port}/cert/download",
                f"3. 点击下载证书，系统会提示"此网站正尝试下载一个配置描述文件"",
                f"4. 点击"允许"，然后前往"设置" > "已下载描述文件"",
                f"5. 点击安装描述文件，输入密码完成安装",
                f"6. 前往"设置" > "通用" > "关于本机" > "证书信任设置"，启用对mitmproxy证书的完全信任"
            ],
            "android": [
                f"1. 在Android设备上连接到与电脑相同的WiFi网络",
                f"2. 打开浏览器，访问 http://{server_ip}:{port}/cert/download",
                f"3. 下载证书文件到设备",
                f"4. 前往"设置" > "安全" > "加密与凭据" > "从存储设备安装"",
                f"5. 选择下载的证书文件，输入证书名称（如mitmproxy）",
                f"6. 注意：Android 7.0+默认不信任用户证书，部分应用可能无法抓包"
            ]
        }

    def check_cert_installed_windows(self) -> bool:
        """检查证书是否已在Windows系统中安装"""
        try:
            cmd = 'certutil -store -user Root'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if result.returncode == 0:
                # 检查输出中是否包含mitmproxy证书
                return 'mitmproxy' in result.stdout.lower()
            return False
        except Exception as e:
            print(f"检查证书状态时出错: {e}")
            return False

    def get_cert_status(self) -> dict:
        """获取证书状态信息"""
        return {
            "exists": os.path.exists(self.ca_cert_path),
            "path": self.ca_cert_path,
            "installed_windows": self.check_cert_installed_windows() if os.name == 'nt' else None
        }

