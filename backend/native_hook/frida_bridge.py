"""
Frida Bridge - Frida核心封装
提供进程附加、脚本注入等功能
"""

import frida
import sys
import logging
from typing import Optional, Callable, List, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class FridaHook:
    """Frida Hook核心类"""

    def __init__(self):
        self.session: Optional[frida.core.Session] = None
        self.script: Optional[frida.core.Script] = None
        self.device: Optional[frida.core.Device] = None
        self.process_name: Optional[str] = None
        self.pid: Optional[int] = None
        self.message_handler: Optional[Callable] = None

    def list_processes(self) -> List[Dict[str, Any]]:
        """列出所有运行中的进程"""
        try:
            if not self.device:
                self.device = frida.get_local_device()

            processes = self.device.enumerate_processes()
            return [
                {
                    'pid': p.pid,
                    'name': p.name,
                    'parameters': p.parameters if hasattr(p, 'parameters') else {}
                }
                for p in processes
            ]
        except Exception as e:
            logger.error(f"列出进程失败: {e}")
            raise

    def attach_process(self, process_name: str) -> bool:
        """附加到进程（通过进程名）"""
        try:
            if not self.device:
                self.device = frida.get_local_device()

            # 查找进程
            processes = self.device.enumerate_processes()
            target_process = None
            for p in processes:
                if process_name.lower() in p.name.lower():
                    target_process = p
                    break

            if not target_process:
                raise ValueError(f"未找到进程: {process_name}")

            # 附加到进程
            self.session = self.device.attach(target_process.pid)
            self.process_name = target_process.name
            self.pid = target_process.pid

            logger.info(f"成功附加到进程: {self.process_name} (PID: {self.pid})")
            return True

        except Exception as e:
            logger.error(f"附加进程失败: {e}")
            raise

    def attach_pid(self, pid: int) -> bool:
        """附加到进程（通过PID）"""
        try:
            if not self.device:
                self.device = frida.get_local_device()

            self.session = self.device.attach(pid)
            self.pid = pid

            # 获取进程名
            processes = self.device.enumerate_processes()
            for p in processes:
                if p.pid == pid:
                    self.process_name = p.name
                    break

            logger.info(f"成功附加到进程: {self.process_name} (PID: {self.pid})")
            return True

        except Exception as e:
            logger.error(f"附加进程失败: {e}")
            raise

    def detach(self) -> bool:
        """分离进程"""
        try:
            if self.script:
                self.script.unload()
                self.script = None

            if self.session:
                self.session.detach()
                self.session = None

            logger.info(f"已分离进程: {self.process_name}")
            self.process_name = None
            self.pid = None
            return True

        except Exception as e:
            logger.error(f"分离进程失败: {e}")
            raise

    def inject_script(self, script_code: str, message_handler: Optional[Callable] = None) -> bool:
        """注入Frida脚本"""
        try:
            if not self.session:
                raise ValueError("未附加到任何进程")

            # 卸载旧脚本
            if self.script:
                self.script.unload()

            # 创建新脚本
            self.script = self.session.create_script(script_code)

            # 设置消息处理器
            if message_handler:
                self.message_handler = message_handler
                self.script.on('message', self._on_message)

            # 加载脚本
            self.script.load()

            logger.info("脚本注入成功")
            return True

        except Exception as e:
            logger.error(f"注入脚本失败: {e}")
            raise

    def inject_script_file(self, script_path: str, message_handler: Optional[Callable] = None) -> bool:
        """注入Frida脚本文件"""
        try:
            script_file = Path(script_path)
            if not script_file.exists():
                raise FileNotFoundError(f"脚本文件不存在: {script_path}")

            script_code = script_file.read_text(encoding='utf-8')
            return self.inject_script(script_code, message_handler)

        except Exception as e:
            logger.error(f"注入脚本文件失败: {e}")
            raise

    def _on_message(self, message: Dict[str, Any], data: Optional[bytes]):
        """处理Frida消息"""
        try:
            if message['type'] == 'send':
                payload = message.get('payload', {})
                if self.message_handler:
                    self.message_handler(payload, data)
                else:
                    logger.info(f"收到消息: {payload}")
            elif message['type'] == 'error':
                logger.error(f"脚本错误: {message.get('description', 'Unknown error')}")
                if 'stack' in message:
                    logger.error(f"堆栈: {message['stack']}")
        except Exception as e:
            logger.error(f"处理消息失败: {e}")

    def call_function(self, function_name: str, *args) -> Any:
        """调用脚本中的函数"""
        try:
            if not self.script:
                raise ValueError("未注入任何脚本")

            # 导出的函数可以通过exports调用
            exports = self.script.exports
            if hasattr(exports, function_name):
                func = getattr(exports, function_name)
                return func(*args)
            else:
                raise ValueError(f"函数不存在: {function_name}")

        except Exception as e:
            logger.error(f"调用函数失败: {e}")
            raise

    def is_attached(self) -> bool:
        """检查是否已附加到进程"""
        return self.session is not None

    def get_process_info(self) -> Optional[Dict[str, Any]]:
        """获取当前附加的进程信息"""
        if not self.is_attached():
            return None

        return {
            'process_name': self.process_name,
            'pid': self.pid,
            'has_script': self.script is not None
        }


def check_frida_installed() -> bool:
    """检查Frida是否已安装"""
    try:
        import frida
        version = frida.__version__
        logger.info(f"Frida已安装，版本: {version}")
        return True
    except ImportError:
        logger.error("Frida未安装")
        return False


def get_frida_version() -> Optional[str]:
    """获取Frida版本"""
    try:
        import frida
        return frida.__version__
    except ImportError:
        return None
