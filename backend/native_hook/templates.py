"""
Frida Hook脚本模板管理系统
"""

import os
from typing import Dict, List, Optional
from pathlib import Path


class HookTemplate:
    """Hook脚本模板"""

    def __init__(self, name: str, description: str, script_path: str, category: str = "general"):
        self.name = name
        self.description = description
        self.script_path = script_path
        self.category = category

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

        # 简单的参数替换
        for key, value in kwargs.items():
            placeholder = f"{{{{{key}}}}}"
            script = script.replace(placeholder, str(value))

        return script

    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "script_path": self.script_path
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
                category="network"
            ))

        # 网络监控模板
        self.register_template(HookTemplate(
            name="network_monitor",
            description="网络请求监控",
            script_path=windows_api_script,  # 复用同一脚本
            category="network"
        ))

        # 加密监控模板
        self.register_template(HookTemplate(
            name="crypto_monitor",
            description="加密操作监控",
            script_path=windows_api_script,  # 复用同一脚本
            category="crypto"
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
