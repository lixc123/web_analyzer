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
                f"3. 点击下载证书，系统会提示\"此网站正尝试下载一个配置描述文件\"",
                f"4. 点击\"允许\"，然后前往\"设置\" > \"已下载描述文件\"",
                f"5. 点击安装描述文件，输入密码完成安装",
                f"6. 前往\"设置\" > \"通用\" > \"关于本机\" > \"证书信任设置\"，启用对mitmproxy证书的完全信任"
            ],
            "android": [
                f"1. 在Android设备上连接到与电脑相同的WiFi网络",
                f"2. 打开浏览器，访问 http://{server_ip}:{port}/cert/download",
                f"3. 下载证书文件到设备",
                f"4. 前往\"设置\" > \"安全\" > \"加密与凭据\" > \"从存储设备安装\"",
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
        cert_info = self.get_cert_info()
        
        return {
            "exists": os.path.exists(self.ca_cert_path),
            "path": self.ca_cert_path,
            "installed_windows": self.check_cert_installed_windows() if os.name == 'nt' else None,
            "expiry_date": cert_info.get("expiry_date"),
            "days_until_expiry": cert_info.get("days_until_expiry"),
            "is_expired": cert_info.get("is_expired"),
            "is_expiring_soon": cert_info.get("is_expiring_soon")
        }

    def get_cert_info(self) -> dict:
        """获取证书详细信息，包括过期时间"""
        try:
            if not os.path.exists(self.ca_cert_path):
                return {"error": "证书文件不存在"}

            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            from datetime import datetime, timezone

            with open(self.ca_cert_path, 'rb') as f:
                cert_data = f.read()

            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            # 获取过期时间
            expiry_date = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
            
            # 计算剩余天数
            now = datetime.now(timezone.utc)
            days_until_expiry = (expiry_date - now).days
            
            # 判断是否过期或即将过期（30天内）
            is_expired = days_until_expiry < 0
            is_expiring_soon = 0 <= days_until_expiry <= 30

            return {
                "expiry_date": expiry_date.isoformat(),
                "days_until_expiry": days_until_expiry,
                "is_expired": is_expired,
                "is_expiring_soon": is_expiring_soon,
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string()
            }
        except ImportError:
            return {"error": "需要安装 cryptography 库: pip install cryptography"}
        except Exception as e:
            return {"error": f"读取证书信息失败: {e}"}

    def regenerate_cert(self) -> bool:
        """重新生成证书（删除旧证书，让mitmproxy自动生成新的）"""
        try:
            import shutil
            
            # 备份旧证书
            if os.path.exists(self.cert_dir):
                backup_dir = f"{self.cert_dir}.backup.{int(os.path.getmtime(self.cert_dir))}"
                shutil.copytree(self.cert_dir, backup_dir, dirs_exist_ok=True)
                print(f"旧证书已备份到: {backup_dir}")
            
            # 删除证书目录
            if os.path.exists(self.cert_dir):
                shutil.rmtree(self.cert_dir)
            
            # 重新创建目录
            os.makedirs(self.cert_dir, exist_ok=True)
            
            print("证书目录已清空，mitmproxy将在下次启动时自动生成新证书")
            return True
        except Exception as e:
            print(f"重新生成证书失败: {e}")
            return False

    def check_and_notify_expiry(self) -> dict:
        """检查证书过期状态并返回提醒信息"""
        cert_info = self.get_cert_info()
        
        if "error" in cert_info:
            return {
                "status": "error",
                "message": cert_info["error"]
            }
        
        if cert_info.get("is_expired"):
            return {
                "status": "expired",
                "message": f"证书已过期！过期时间: {cert_info['expiry_date']}",
                "action": "需要立即重新生成证书"
            }
        elif cert_info.get("is_expiring_soon"):
            days = cert_info.get("days_until_expiry", 0)
            return {
                "status": "expiring_soon",
                "message": f"证书将在 {days} 天后过期",
                "action": "建议尽快重新生成证书"
            }
        else:
            days = cert_info.get("days_until_expiry", 0)
            return {
                "status": "valid",
                "message": f"证书有效，还有 {days} 天过期",
                "action": None
            }

