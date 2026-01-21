"""
代理服务API路由
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import socket
import base64

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
        from backend.app.websocket.proxy_events import broadcaster
        import asyncio

        # 获取管理器实例
        manager = ProxyServiceManager.get_instance()

        # 启动代理服务并获取服务器实例
        server = manager.start_service(
            host=config.host,
            port=config.port,
            enable_system_proxy=config.enable_system_proxy,
            on_request=_handle_request,
            on_response=_handle_response
        )

        # 获取实际使用的端口（可能因端口占用而改变）
        actual_port = server.port

        # 如果需要启用系统代理
        if config.enable_system_proxy:
            try:
                from backend.proxy import WindowsSystemProxy
                system_proxy = WindowsSystemProxy()
                system_proxy.enable_proxy(host="127.0.0.1", port=actual_port)
                # 保存系统代理实例到管理器
                manager.set_system_proxy_instance(system_proxy)
            except Exception as e:
                # 回滚：停止已启动的代理服务
                manager.stop_service()
                raise HTTPException(status_code=500, detail=f"启用系统代理失败: {str(e)}")

        # 广播代理启动状态
        status_data = {
            "running": True,
            "host": config.host,
            "port": actual_port,
            "system_proxy_enabled": config.enable_system_proxy
        }
        main_loop = manager.get_main_event_loop()
        if main_loop:
            asyncio.run_coroutine_threadsafe(broadcaster.broadcast_status(status_data), main_loop)

        return {
            "status": "success",
            "message": "代理服务启动成功",
            "host": config.host,
            "port": actual_port
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"启动代理服务失败: {str(e)}")


@router.post("/stop")
async def stop_proxy():
    """停止代理服务器"""
    try:
        from backend.proxy.service_manager import ProxyServiceManager
        from backend.app.websocket.proxy_events import broadcaster
        import asyncio

        # 获取管理器实例
        manager = ProxyServiceManager.get_instance()

        if not manager.is_running():
            raise HTTPException(status_code=400, detail="代理服务未运行")

        # 检查是否启用了系统代理
        if manager.is_system_proxy_enabled():
            # 恢复系统代理设置 - 使用保存的实例
            system_proxy = manager.get_system_proxy_instance()
            if system_proxy:
                system_proxy.restore_original()
                manager.set_system_proxy_instance(None)

        # 停止代理服务
        manager.stop_service()

        # 广播代理停止状态
        status_data = {
            "running": False,
            "host": "",
            "port": 0,
            "system_proxy_enabled": False
        }
        main_loop = manager.get_main_event_loop()
        if main_loop:
            asyncio.run_coroutine_threadsafe(broadcaster.broadcast_status(status_data), main_loop)

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
    stats = manager.get_statistics().get_summary()

    if not server:
        return {
            "running": False,
            "host": "",
            "port": 0,
            "system_proxy_enabled": False,
            "connected_clients": 0,
            "clients_count": 0,  # 别名字段，兼容前端
            "total_requests": 0,
            "statistics": {
                "devices_count": 0,
                "total_requests": 0
            }
        }

    clients_count = len(manager.get_devices())
    return {
        "running": manager.is_running(),
        "host": server.host,
        "port": server.port,
        "system_proxy_enabled": manager.is_system_proxy_enabled(),
        "connected_clients": clients_count,
        "clients_count": clients_count,  # 别名字段，兼容前端
        "total_requests": stats.get('total_requests', 0),
        "statistics": {
            "devices_count": clients_count,
            "total_requests": stats.get('total_requests', 0)
        }
    }


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


@router.get("/cert/download")
async def download_cert():
    """下载CA证书文件"""
    from backend.proxy.cert_manager import CertManager
    from fastapi.responses import Response

    cert_manager = CertManager()
    cert_info = cert_manager.get_cert_for_mobile()

    if "error" in cert_info:
        raise HTTPException(status_code=404, detail=cert_info["error"])

    cert_content = base64.b64decode(cert_info["content_base64"])

    return Response(
        content=cert_content,
        media_type="application/x-x509-ca-cert",
        headers={
            "Content-Disposition": f'attachment; filename="{cert_info["filename"]}"'
        }
    )


@router.get("/cert/instructions")
async def get_cert_instructions():
    """获取证书安装说明"""
    from backend.proxy.cert_manager import CertManager
    from backend.proxy.service_manager import ProxyServiceManager

    manager = ProxyServiceManager.get_instance()
    server = manager.get_server()

    if not server:
        raise HTTPException(status_code=400, detail="代理服务未运行")

    # 获取本机IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "127.0.0.1"

    cert_manager = CertManager()
    instructions = cert_manager.get_mobile_install_instructions(local_ip, server.port)

    return instructions


@router.get("/cert/qrcode")
async def get_cert_qrcode():
    """生成证书下载二维码"""
    from backend.proxy.cert_manager import CertManager
    from backend.proxy.service_manager import ProxyServiceManager

    manager = ProxyServiceManager.get_instance()
    server = manager.get_server()

    if not server:
        raise HTTPException(status_code=400, detail="代理服务未运行")

    # 获取本机IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "127.0.0.1"

    download_url = f"http://{local_ip}:{server.port}/api/v1/proxy/cert/download"

    cert_manager = CertManager()
    qr_code_base64 = cert_manager.generate_qr_code(download_url)

    if not qr_code_base64:
        raise HTTPException(status_code=500, detail="生成二维码失败")

    return {"qrcode": qr_code_base64, "url": download_url}


@router.post("/cert/install-windows")
async def install_cert_windows():
    """在Windows系统中安装CA证书"""
    from backend.proxy.cert_manager import CertManager

    cert_manager = CertManager()
    success = cert_manager.install_cert_windows()

    if success:
        return {"status": "success", "message": "证书安装成功"}
    else:
        raise HTTPException(status_code=500, detail="证书安装失败")


@router.post("/cert/uninstall-windows")
async def uninstall_cert_windows():
    """从Windows系统中卸载CA证书"""
    from backend.proxy.cert_manager import CertManager

    cert_manager = CertManager()
    success = cert_manager.uninstall_cert_windows()

    if success:
        return {"status": "success", "message": "证书卸载成功"}
    else:
        raise HTTPException(status_code=500, detail="证书卸载失败")


@router.get("/cert/status")
async def get_cert_status():
    """获取证书状态"""
    from backend.proxy.cert_manager import CertManager

    cert_manager = CertManager()
    status = cert_manager.get_cert_status()

    return status


@router.get("/cert/info")
async def get_cert_info():
    """获取证书详细信息"""
    from backend.proxy.cert_manager import CertManager

    cert_manager = CertManager()
    info = cert_manager.get_cert_info()

    return info


@router.get("/cert/expiry-check")
async def check_cert_expiry():
    """检查证书过期状态"""
    from backend.proxy.cert_manager import CertManager

    cert_manager = CertManager()
    result = cert_manager.check_and_notify_expiry()

    return result


@router.post("/cert/regenerate")
async def regenerate_cert():
    """重新生成证书"""
    from backend.proxy.cert_manager import CertManager

    cert_manager = CertManager()
    success = cert_manager.regenerate_cert()

    if success:
        return {
            "status": "success",
            "message": "证书已重新生成，请重启代理服务并重新安装证书"
        }
    else:
        raise HTTPException(status_code=500, detail="重新生成证书失败")


@router.get("/devices")
async def get_devices():
    """获取连接的设备列表"""
    from backend.proxy.service_manager import ProxyServiceManager

    manager = ProxyServiceManager.get_instance()
    devices = manager.get_devices()

    return {"devices": devices, "total": len(devices)}


@router.get("/mobile-setup")
async def get_mobile_setup():
    """获取移动端配置页面"""
    from fastapi.responses import HTMLResponse
    from backend.proxy.service_manager import ProxyServiceManager
    import os

    manager = ProxyServiceManager.get_instance()
    server = manager.get_server()

    if not server:
        raise HTTPException(status_code=400, detail="代理服务未运行")

    # 获取本机IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "127.0.0.1"

    # 读取HTML模板
    template_path = os.path.join(os.path.dirname(__file__), "../../../static/mobile-setup.html")
    with open(template_path, "r", encoding="utf-8") as f:
        html_content = f.read()

    # 替换变量
    html_content = html_content.replace("{{SERVER_IP}}", local_ip)
    html_content = html_content.replace("{{SERVER_PORT}}", str(server.port))

    return HTMLResponse(content=html_content)


@router.get("/firewall/status")
async def get_firewall_status():
    """获取防火墙状态"""
    from backend.utils.firewall_checker import FirewallChecker

    status = FirewallChecker.check_firewall_status()
    return status


@router.get("/firewall/check-port")
async def check_firewall_port(port: int = 8888):
    """检查指定端口的防火墙规则"""
    from backend.utils.firewall_checker import FirewallChecker

    result = FirewallChecker.check_port_rule(port)
    return result


@router.get("/firewall/recommendations")
async def get_firewall_recommendations():
    """获取防火墙配置建议"""
    from backend.utils.firewall_checker import FirewallChecker
    from backend.proxy.service_manager import ProxyServiceManager

    manager = ProxyServiceManager.get_instance()
    server = manager.get_server()
    
    port = server.port if server else 8888
    recommendations = FirewallChecker.get_firewall_recommendations(port)
    
    return {
        "port": port,
        "recommendations": recommendations
    }


def _handle_request(request_data: dict):
    """处理捕获的请求"""
    from backend.proxy.service_manager import ProxyServiceManager
    from backend.models.unified_request import UnifiedRequest
    from backend.app.websocket.proxy_events import broadcaster
    import asyncio
    import logging

    logger = logging.getLogger(__name__)

    # 记录统计
    manager = ProxyServiceManager.get_instance()
    manager.get_statistics().record_request(request_data)

    # 跟踪设备
    if 'device' in request_data:
        manager.track_device(request_data['device'])

    # 保存到存储
    try:
        unified_request = UnifiedRequest.from_proxy_request(request_data)
        storage = manager.get_storage()
        storage.save_request(unified_request)
        # request_id 已经在 request_data 中，无需重新赋值

        # 广播到 WebSocket 客户端 - 使用主事件循环
        main_loop = manager.get_main_event_loop()
        if main_loop:
            try:
                asyncio.run_coroutine_threadsafe(broadcaster.broadcast_request(request_data), main_loop)
            except Exception as e:
                logger.error(f"WebSocket广播失败: {e}")
        else:
            logger.debug("主事件循环未设置，跳过WebSocket广播")
    except Exception as e:
        logger.error(f"保存请求失败: {e}")

    logger.info(f"捕获请求: {request_data['method']} {request_data['url']}")


def _handle_response(response_data: dict):
    """处理捕获的响应"""
    from backend.proxy.service_manager import ProxyServiceManager
    from backend.app.websocket.proxy_events import broadcaster
    import asyncio
    import logging

    logger = logging.getLogger(__name__)

    # 记录统计
    manager = ProxyServiceManager.get_instance()
    manager.get_statistics().record_response(response_data)

    # 更新请求的响应信息 - 使用请求ID而不是URL
    storage = manager.get_storage()
    request_id = response_data.get('request_id')
    if request_id:
        storage.update_response(request_id, response_data)

        # 广播响应更新到 WebSocket 客户端
        main_loop = manager.get_main_event_loop()
        if main_loop:
            try:
                asyncio.run_coroutine_threadsafe(broadcaster.broadcast_response(response_data), main_loop)
            except Exception as e:
                logger.error(f"WebSocket广播响应失败: {e}")

    logger.info(f"捕获响应: {response_data['status_code']} {response_data['url']}")


@router.get("/requests")
async def get_proxy_requests(
    source: Optional[str] = None,
    platform: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    """获取代理捕获的请求列表

    Args:
        source: 请求来源过滤 (web_browser/desktop_app/mobile_ios/mobile_android)
        platform: 平台过滤 (Windows/macOS/Linux/iOS/Android)
        limit: 返回数量限制，默认100
        offset: 偏移量，默认0

    Returns:
        请求列表和总数
    """
    from backend.proxy.service_manager import ProxyServiceManager
    from backend.models.unified_request import RequestSource

    manager = ProxyServiceManager.get_instance()
    storage = manager.get_storage()

    # 转换source参数
    source_enum = None
    if source:
        try:
            source_enum = RequestSource(source)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"无效的source参数: {source}")

    # 获取请求列表
    requests = storage.get_requests(
        source=source_enum,
        platform=platform,
        limit=limit,
        offset=offset
    )

    # 获取统计信息
    stats = storage.get_statistics()

    return {
        "requests": requests,
        "total": stats['total'],
        "limit": limit,
        "offset": offset
    }


@router.get("/request/{request_id}")
async def get_proxy_request_detail(request_id: str):
    """获取单个请求的详细信息

    Args:
        request_id: 请求ID

    Returns:
        请求详细信息
    """
    from backend.proxy.service_manager import ProxyServiceManager

    manager = ProxyServiceManager.get_instance()
    storage = manager.get_storage()

    request = storage.get_request_by_id(request_id)

    if not request:
        raise HTTPException(status_code=404, detail=f"请求不存在: {request_id}")

    return request


@router.get("/requests/export")
async def export_requests(
    format: str = "har",
    source: Optional[str] = None,
    platform: Optional[str] = None,
    limit: int = 1000
):
    """导出请求数据

    Args:
        format: 导出格式 (har/csv)，默认har
        source: 请求来源过滤 (web_browser/desktop_app/mobile_ios/mobile_android)
        platform: 平台过滤 (Windows/macOS/Linux/iOS/Android)
        limit: 导出数量限制，默认1000

    Returns:
        导出的文件内容
    """
    from backend.proxy.service_manager import ProxyServiceManager
    from backend.models.unified_request import RequestSource
    from fastapi.responses import Response
    import json
    from datetime import datetime

    if format not in ["har", "csv"]:
        raise HTTPException(status_code=400, detail=f"不支持的导出格式: {format}")

    manager = ProxyServiceManager.get_instance()
    storage = manager.get_storage()

    # 转换source参数
    source_enum = None
    if source:
        try:
            source_enum = RequestSource(source)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"无效的source参数: {source}")

    # 获取请求列表
    requests = storage.get_requests(
        source=source_enum,
        platform=platform,
        limit=limit,
        offset=0
    )

    if format == "har":
        # 生成HAR格式
        har_content = _convert_to_har(requests)
        return Response(
            content=json.dumps(har_content, indent=2, ensure_ascii=False),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="requests_{datetime.now().strftime("%Y%m%d_%H%M%S")}.har"'
            }
        )
    else:  # csv
        # 生成CSV格式
        csv_content = _convert_to_csv(requests)
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="requests_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'
            }
        )


def _convert_to_har(requests: list) -> dict:
    """将请求列表转换为HAR格式

    HAR (HTTP Archive) 是一个用于记录HTTP请求和响应的标准格式
    """
    from datetime import datetime

    entries = []
    for req in requests:
        # 构建请求头数组
        request_headers = [
            {"name": k, "value": v}
            for k, v in req.get("headers", {}).items()
        ]

        # 构建响应头数组
        response_headers = [
            {"name": k, "value": v}
            for k, v in req.get("response_headers", {}).items()
        ] if req.get("response_headers") else []

        # 计算请求体大小
        request_body_size = len(req.get("body", "")) if req.get("body") else 0

        # 计算响应体大小
        response_body_size = req.get("response_size", 0) or 0

        # 构建HAR entry
        entry = {
            "startedDateTime": datetime.fromtimestamp(req.get("timestamp", 0)).isoformat() + "Z",
            "time": (req.get("response_time", 0) or 0) * 1000,  # 转换为毫秒
            "request": {
                "method": req.get("method", "GET"),
                "url": req.get("url", ""),
                "httpVersion": "HTTP/1.1",
                "headers": request_headers,
                "queryString": [],
                "cookies": [],
                "headersSize": -1,
                "bodySize": request_body_size,
            },
            "response": {
                "status": req.get("status_code", 0) or 0,
                "statusText": "",
                "httpVersion": "HTTP/1.1",
                "headers": response_headers,
                "cookies": [],
                "content": {
                    "size": response_body_size,
                    "mimeType": req.get("content_type", ""),
                    "text": req.get("response_body", "") if req.get("response_body") else ""
                },
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": response_body_size,
            },
            "cache": {},
            "timings": {
                "send": 0,
                "wait": (req.get("response_time", 0) or 0) * 1000,
                "receive": 0
            }
        }
        entries.append(entry)

    # 构建完整的HAR对象
    har = {
        "log": {
            "version": "1.2",
            "creator": {
                "name": "Proxy Capture Tool",
                "version": "2.0.0"
            },
            "entries": entries
        }
    }

    return har


def _convert_to_csv(requests: list) -> str:
    """将请求列表转换为CSV格式"""
    import csv
    from io import StringIO
    from datetime import datetime

    output = StringIO()
    writer = csv.writer(output)

    # 写入表头
    writer.writerow([
        "ID",
        "Timestamp",
        "Method",
        "URL",
        "Status Code",
        "Response Time (s)",
        "Response Size (bytes)",
        "Source",
        "Platform",
        "Content Type"
    ])

    # 写入数据行
    for req in requests:
        timestamp = datetime.fromtimestamp(req.get("timestamp", 0)).strftime("%Y-%m-%d %H:%M:%S")
        device_info = req.get("device_info", {})

        writer.writerow([
            req.get("id", ""),
            timestamp,
            req.get("method", ""),
            req.get("url", ""),
            req.get("status_code", ""),
            req.get("response_time", ""),
            req.get("response_size", ""),
            req.get("source", ""),
            device_info.get("platform", "") if device_info else "",
            req.get("content_type", "")
        ])

    return output.getvalue()
