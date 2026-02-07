"""
Frida Hook脚本模板管理系统
"""

import os
from typing import Dict, List, Optional
from pathlib import Path


class HookTemplate:
    """Hook脚本模板"""

    def __init__(
        self,
        name: str,
        description: str,
        script_path: str,
        category: str = "general",
        default_params: Optional[Dict] = None,
    ):
        self.name = name
        self.description = description
        self.script_path = script_path
        self.category = category
        self.default_params = default_params or {}

    def load_script(self) -> str:
        """加载脚本内容"""
        try:
            with open(self.script_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            raise Exception(f"加载脚本失败: {e}")

    def render(self, **kwargs) -> str:
        """渲染脚本模板（支持参数替换）"""
        script = self.load_script()

        # 合并默认参数与传入参数
        params = dict(self.default_params or {})
        params.update(kwargs)

        # 简单的参数替换
        for key, value in params.items():
            placeholder = f"{{{{{key}}}}}"
            if isinstance(value, bool):
                rendered = "true" if value else "false"
            elif value is None:
                rendered = "null"
            else:
                rendered = str(value)
            script = script.replace(placeholder, rendered)

        return script

    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "script_path": self.script_path,
            "default_params": self.default_params,
        }


class TemplateManager:
    """模板管理器"""

    def __init__(self, scripts_dir: Optional[str] = None):
        if scripts_dir is None:
            # 默认脚本目录
            current_dir = os.path.dirname(os.path.abspath(__file__))
            scripts_dir = os.path.join(current_dir, "scripts")

        self.scripts_dir = scripts_dir
        self.templates: Dict[str, HookTemplate] = {}
        self._load_builtin_templates()

    def _load_builtin_templates(self):
        """加载内置模板"""
        # Windows API Hook模板
        windows_api_script = os.path.join(self.scripts_dir, "windows_api_hooks.js")
        if os.path.exists(windows_api_script):
            self.register_template(HookTemplate(
                name="windows_api_hooks",
                description="Windows API Hook (网络+加密)",
                script_path=windows_api_script,
                category="network",
                default_params={
                    "enable_winhttp": True,
                    "enable_wininet": True,
                    "enable_winsock": True,
                    "enable_crypto": True,
                    "enable_file": False,
                    "enable_registry": False,
                    "max_preview": 4096,
                    "hexdump": False,
                    "sample_rate": 1,
                    "capture_stack_trace": False,
                    "max_stack_depth": 16,
                    "dump_raw_buffers": False,
                    "raw_max_bytes": 4096,
                    "raw_total_budget_bytes": 0,
                    "winsock_reassemble": False,
                    "winsock_reassemble_max_bytes": 16384,
                },
            ))

        # Windows SSL Unpinning 模板
        ssl_unpin_script = os.path.join(self.scripts_dir, "windows_ssl_unpinning.js")
        if os.path.exists(ssl_unpin_script):
            self.register_template(HookTemplate(
                name="windows_ssl_unpinning",
                description="Windows SSL Unpinning（绕过常见证书校验）",
                script_path=ssl_unpin_script,
                category="security"
            ))

        openssl_unpin_script = os.path.join(self.scripts_dir, "openssl_ssl_unpinning.js")
        if os.path.exists(openssl_unpin_script):
            self.register_template(HookTemplate(
                name="openssl_ssl_unpinning",
                description="OpenSSL/BoringSSL Unpinning（绕过证书校验）",
                script_path=openssl_unpin_script,
                category="security"
            ))

        mbedtls_unpin_script = os.path.join(self.scripts_dir, "mbedtls_ssl_unpinning.js")
        if os.path.exists(mbedtls_unpin_script):
            self.register_template(HookTemplate(
                name="mbedtls_ssl_unpinning",
                description="mbedTLS Unpinning（绕过证书校验）",
                script_path=mbedtls_unpin_script,
                category="security"
            ))

        # 网络监控模板
        self.register_template(HookTemplate(
            name="network_monitor",
            description="网络请求监控",
            script_path=windows_api_script,  # 复用同一脚本
            category="network",
            default_params={
                "enable_winhttp": True,
                "enable_wininet": True,
                "enable_winsock": True,
                "enable_crypto": False,
                "enable_file": False,
                "enable_registry": False,
                "max_preview": 4096,
                "hexdump": False,
                "sample_rate": 1,
                "capture_stack_trace": False,
                "max_stack_depth": 16,
                "dump_raw_buffers": False,
                "raw_max_bytes": 4096,
                "raw_total_budget_bytes": 0,
                "winsock_reassemble": False,
                "winsock_reassemble_max_bytes": 16384,
            },
        ))

        # 加密监控模板
        self.register_template(HookTemplate(
            name="crypto_monitor",
            description="加密操作监控",
            script_path=windows_api_script,  # 复用同一脚本
            category="crypto",
            default_params={
                "enable_winhttp": False,
                "enable_wininet": False,
                "enable_winsock": False,
                "enable_crypto": True,
                "enable_file": False,
                "enable_registry": False,
                "max_preview": 4096,
                "hexdump": False,
                "sample_rate": 1,
                "capture_stack_trace": False,
                "max_stack_depth": 16,
                "dump_raw_buffers": False,
                "raw_max_bytes": 4096,
                "raw_total_budget_bytes": 0,
                "winsock_reassemble": False,
                "winsock_reassemble_max_bytes": 16384,
            },
        ))

        # 应用层加密定位模板（采样 + 调用栈，默认关闭，需要用户显式选择）
        self.register_template(HookTemplate(
            name="encryption_locator",
            description="应用层加密定位（含调用栈/采样）",
            script_path=windows_api_script,
            category="crypto",
            default_params={
                "enable_winhttp": False,
                "enable_wininet": False,
                "enable_winsock": False,
                "enable_crypto": True,
                "enable_file": False,
                "enable_registry": False,
                "max_preview": 2048,
                "hexdump": False,
                "sample_rate": 0.2,
                "capture_stack_trace": True,
                "max_stack_depth": 24,
                "dump_raw_buffers": False,
                "raw_max_bytes": 4096,
                "raw_total_budget_bytes": 0,
                "winsock_reassemble": False,
                "winsock_reassemble_max_bytes": 16384,
            },
        ))

        # 压缩/解压定位模板（用于定位应用层压缩/序列化点，默认关闭）
        compression_script = os.path.join(self.scripts_dir, "compression_monitor.js")
        if os.path.exists(compression_script):
            self.register_template(HookTemplate(
                name="compression_monitor",
                description="压缩/解压定位（RtlCompressBuffer/zlib，含调用栈/采样）",
                script_path=compression_script,
                category="crypto",
                default_params={
                    "sample_rate": 0.2,
                    "capture_stack_trace": True,
                    "max_stack_depth": 24,
                    "max_preview": 2048,
                    "hexdump": False,
                },
            ))

    def register_template(self, template: HookTemplate):
        """注册模板"""
        self.templates[template.name] = template

    def get_template(self, name: str) -> Optional[HookTemplate]:
        """获取模板"""
        return self.templates.get(name)

    def list_templates(self, category: Optional[str] = None) -> List[Dict]:
        """列出所有模板"""
        templates = self.templates.values()

        if category:
            templates = [t for t in templates if t.category == category]

        return [t.to_dict() for t in templates]

    def get_categories(self) -> List[str]:
        """获取所有分类"""
        categories = set(t.category for t in self.templates.values())
        return sorted(list(categories))

    def create_custom_template(self, name: str, description: str, script_content: str, category: str = "custom") -> HookTemplate:
        """创建自定义模板"""
        # 保存到自定义脚本目录
        custom_dir = os.path.join(self.scripts_dir, "custom")
        os.makedirs(custom_dir, exist_ok=True)

        script_path = os.path.join(custom_dir, f"{name}.js")

        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(script_content)

        template = HookTemplate(
            name=name,
            description=description,
            script_path=script_path,
            category=category
        )

        self.register_template(template)
        return template

    def delete_template(self, name: str) -> bool:
        """删除自定义模板"""
        template = self.get_template(name)
        if not template:
            return False

        # 只能删除自定义模板
        if template.category != "custom":
            raise Exception("不能删除内置模板")

        # 删除文件
        try:
            if os.path.exists(template.script_path):
                os.remove(template.script_path)
        except Exception as e:
            print(f"删除脚本文件失败: {e}")

        # 从注册表中移除
        del self.templates[name]
        return True


# 全局模板管理器实例
_template_manager = None


def get_template_manager() -> TemplateManager:
    """获取全局模板管理器实例"""
    global _template_manager
    if _template_manager is None:
        _template_manager = TemplateManager()
    return _template_manager
