"""
代理服务API路由
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import socket

router = APIRouter()


class ProxyConfig(BaseModel):
    """代理服务配置模型"""
    host: str = "0.0.0.0"
    port: int = 8888
    enable_system_proxy: bool = False
    filter_hosts: List[str] = []


class ProxyStatus(BaseModel):
    """代理服务状态模型"""
    running: bool
    host: str
    port: int
    system_proxy_enabled: bool
    connected_clients: int
    total_requests: int


@router.post("/start")
async def start_proxy(config: ProxyConfig):
    """启动代理服务器"""
    try:
        from backend.proxy.service_manager import ProxyServiceManager

        # 获取管理器实例
        manager = ProxyServiceManager.get_instance()

        # 启动代理服务
        manager.start_service(
            host=config.host,
            port=config.port,
            on_request=_handle_request,
            on_response=_handle_response
        )

        # 如果需要启用系统代理
        if config.enable_system_proxy:
            from backend.proxy import WindowsSystemProxy
            system_proxy = WindowsSystemProxy()
            system_proxy.enable_proxy(host="127.0.0.1", port=config.port)

        return {
            "status": "success",
            "message": "代理服务启动成功",
            "host": config.host,
            "port": config.port
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"启动代理服务失败: {str(e)}")


@router.post("/stop")
async def stop_proxy():
    """停止代理服务器"""
    try:
        from backend.proxy.service_manager import ProxyServiceManager

        # 获取管理器实例
        manager = ProxyServiceManager.get_instance()

        if not manager.is_running():
            raise HTTPException(status_code=400, detail="代理服务未运行")

        # 停止代理服务
        manager.stop_service()

        # 恢复系统代理设置
        from backend.proxy import WindowsSystemProxy
        system_proxy = WindowsSystemProxy()
        system_proxy.restore_original()

        return {
            "status": "success",
            "message": "代理服务已停止"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"停止代理服务失败: {str(e)}")


@router.get("/status")
async def get_proxy_status():
    """获取代理服务器状态"""
    from backend.proxy.service_manager import ProxyServiceManager

    manager = ProxyServiceManager.get_instance()
    server = manager.get_server()

    if not server:
        return ProxyStatus(
            running=False,
            host="",
            port=0,
            system_proxy_enabled=False,
            connected_clients=0,
            total_requests=0
        )

    return ProxyStatus(
        running=manager.is_running(),
        host=server.host,
        port=server.port,
        system_proxy_enabled=False,
        connected_clients=0,
        total_requests=0
    )


@router.get("/local-ip")
async def get_local_ip():
    """获取本机局域网IP地址"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        return {"ip": local_ip}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取本机IP失败: {str(e)}")


@router.get("/statistics")
async def get_statistics():
    """获取请求统计数据"""
    from backend.proxy.service_manager import ProxyServiceManager

    manager = ProxyServiceManager.get_instance()
    stats = manager.get_statistics()

    return stats.get_summary()


def _handle_request(request_data: dict):
    """处理捕获的请求"""
    from backend.proxy.service_manager import ProxyServiceManager

    # 记录统计
    manager = ProxyServiceManager.get_instance()
    manager.get_statistics().record_request(request_data)

    print(f"捕获请求: {request_data['method']} {request_data['url']}")


def _handle_response(response_data: dict):
    """处理捕获的响应"""
    from backend.proxy.service_manager import ProxyServiceManager

    # 记录统计
    manager = ProxyServiceManager.get_instance()
    manager.get_statistics().record_response(response_data)

    print(f"捕获响应: {response_data['status_code']} {response_data['url']}")
