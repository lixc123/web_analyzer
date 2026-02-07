"""
代理服务API路由
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional
import socket
import base64
import re

router = APIRouter()


_SAFE_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class ProxyConfig(BaseModel):
    """代理服务配置模型"""
    host: str = "0.0.0.0"
    port: int = 8888
    enable_system_proxy: bool = False
    enable_winhttp_proxy: bool = False
    winhttp_import_from_ie: bool = False
    filter_hosts: List[str] = []


class ProxyStatus(BaseModel):
    """代理服务状态模型"""
    running: bool
    host: str
    port: int
    system_proxy_enabled: bool
    connected_clients: int
    total_requests: int
    winhttp_proxy_enabled: bool = False


class SystemProxyRequest(BaseModel):
    """手动启用/禁用系统代理（WinINet/IE）请求"""

    host: str = "127.0.0.1"
    port: int = 8888


class WinHttpProxyRequest(BaseModel):
    """手动启用/禁用 WinHTTP 代理请求"""

    host: str = "127.0.0.1"
    port: int = 8888
    import_from_ie: bool = False
    bypass_list: str = "localhost;127.*;192.168.*;<local>"


class ProxySessionUpdateRequest(BaseModel):
    notes: str = ""


class ProxyStorageCleanupRequest(BaseModel):
    artifacts_max_total_mb: int = 0
    artifacts_max_age_days: int = 0
    sessions_max_age_days: int = 0
    dry_run: bool = True


class ArtifactBundleRequest(BaseModel):
    artifact_ids: List[str] = []


@router.post("/start")
async def start_proxy(config: ProxyConfig):
    """启动代理服务器"""
    try:
        from backend.proxy.service_manager import ProxyServiceManager
        from backend.app.websocket.proxy_events import broadcaster
        import asyncio

        # 获取管理器实例
        manager = ProxyServiceManager.get_instance()

        # 若已在运行，先完整回滚系统代理/WinHTTP，再停止服务，避免污染系统环境
        if manager.is_running():
            try:
                _restore_system_proxies(manager)
                manager.stop_proxy_session(status="stopped")
            finally:
                manager.stop_service()

        # 启动代理服务并获取服务器实例
        server = manager.start_service(
            host=config.host,
            port=config.port,
            enable_system_proxy=config.enable_system_proxy,
            on_request=_handle_request,
            on_response=_handle_response,
            on_websocket=_handle_websocket_event,
        )

        # 获取实际使用的端口（可能因端口占用而改变）
        actual_port = server.port

        # 如果需要启用系统代理（WinINet/IE）
        if config.enable_system_proxy:
            try:
                from backend.proxy import WindowsSystemProxy
                system_proxy = WindowsSystemProxy()
                system_proxy.enable_proxy(host="127.0.0.1", port=actual_port)
                # 保存系统代理实例到管理器
                manager.set_system_proxy_instance(system_proxy)
                manager.set_system_proxy_enabled(True)
            except Exception as e:
                # 回滚：停止已启动的代理服务
                manager.stop_service()
                raise HTTPException(status_code=500, detail=f"启用系统代理失败: {str(e)}")

        # 如果需要启用 WinHTTP 代理（部分桌面应用使用）
        if config.enable_winhttp_proxy:
            try:
                from backend.proxy import WindowsWinHttpProxy

                winhttp_proxy = WindowsWinHttpProxy()
                if config.winhttp_import_from_ie:
                    winhttp_proxy.import_from_ie()
                else:
                    winhttp_proxy.enable_proxy(host="127.0.0.1", port=actual_port)

                manager.set_winhttp_proxy_instance(winhttp_proxy)
                manager.set_winhttp_proxy_enabled(True)
            except Exception as e:
                # 回滚：恢复 WinINet 并停止代理
                if manager.is_system_proxy_enabled():
                    system_proxy = manager.get_system_proxy_instance()
                    if system_proxy:
                        try:
                            system_proxy.restore_original()
                        except Exception:
                            pass
                        manager.set_system_proxy_instance(None)
                        manager.set_system_proxy_enabled(False)
                manager.stop_service()
                raise HTTPException(status_code=500, detail=f"启用 WinHTTP 代理失败: {str(e)}")

        # 启动 proxy capture session（落盘）
        proxy_session_id = manager.start_proxy_session(config.host, actual_port) or ""

        # 广播代理启动状态
        status_data = {
            "running": True,
            "host": config.host,
            "port": actual_port,
            "system_proxy_enabled": config.enable_system_proxy,
            "winhttp_proxy_enabled": config.enable_winhttp_proxy,
            "proxy_session_id": proxy_session_id,
        }
        main_loop = manager.get_main_event_loop()
        if main_loop:
            asyncio.run_coroutine_threadsafe(broadcaster.broadcast_status(status_data), main_loop)

        from backend.proxy.diagnostics import run_proxy_diagnostics

        diagnostics = run_proxy_diagnostics(manager)
        try:
            recorder = manager.get_proxy_session_recorder()
            if recorder:
                recorder.record_diagnostics(diagnostics)
        except Exception:
            pass

        return {
            "status": "success",
            "message": "代理服务启动成功",
            "host": config.host,
            "port": actual_port,
            "proxy_session_id": proxy_session_id,
            "diagnostics": diagnostics
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

        _restore_system_proxies(manager)
        manager.stop_proxy_session(status="stopped")

        # 停止代理服务
        manager.stop_service()

        # 广播代理停止状态
        status_data = {
            "running": False,
            "host": "",
            "port": 0,
            "system_proxy_enabled": False,
            "winhttp_proxy_enabled": False,
            "proxy_session_id": "",
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
            "winhttp_proxy_enabled": False,
            "proxy_session_id": "",
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
        "winhttp_proxy_enabled": manager.is_winhttp_proxy_enabled(),
        "proxy_session_id": manager.get_proxy_session_id() or "",
        "connected_clients": clients_count,
        "clients_count": clients_count,  # 别名字段，兼容前端
        "total_requests": stats.get('total_requests', 0),
        "statistics": {
            "devices_count": clients_count,
            "total_requests": stats.get('total_requests', 0)
        }
    }


@router.get("/diagnostics")
async def get_proxy_diagnostics():
    """抓包环境诊断（Windows 优先）。"""
    from backend.proxy.service_manager import ProxyServiceManager
    from backend.proxy.diagnostics import run_proxy_diagnostics

    manager = ProxyServiceManager.get_instance()
    return run_proxy_diagnostics(manager)


# --------------------------
# Proxy capture sessions (disk)
# --------------------------


@router.get("/sessions")
async def list_proxy_sessions(limit: int = 200, offset: int = 0):
    """列出 proxy capture 会话（落盘）。"""
    from backend.proxy.proxy_session import list_proxy_sessions as _list

    return _list(limit=limit, offset=offset)


@router.get("/sessions/{session_id}")
async def get_proxy_session(session_id: str):
    """获取单个 proxy capture 会话元信息。"""
    if not session_id or not _SAFE_SESSION_ID_RE.match(session_id):
        raise HTTPException(status_code=400, detail="无效的session_id")

    from backend.proxy.proxy_session import load_proxy_session_meta

    meta = load_proxy_session_meta(session_id)
    if not meta:
        raise HTTPException(status_code=404, detail="会话不存在")
    return meta


@router.patch("/sessions/{session_id}")
async def update_proxy_session(session_id: str, request: ProxySessionUpdateRequest):
    """更新会话备注（notes）。"""
    if not session_id or not _SAFE_SESSION_ID_RE.match(session_id):
        raise HTTPException(status_code=400, detail="无效的session_id")

    from backend.proxy.service_manager import ProxyServiceManager
    from backend.proxy.proxy_session import load_proxy_session_meta, find_session_dir

    manager = ProxyServiceManager.get_instance()
    current = manager.get_proxy_session_id()
    if current and current == session_id:
        recorder = manager.get_proxy_session_recorder()
        if recorder:
            recorder.update_notes(request.notes or "")
            return {"status": "success"}

    meta = load_proxy_session_meta(session_id)
    if not meta:
        raise HTTPException(status_code=404, detail="会话不存在")

    # update on disk
    meta["notes"] = request.notes or ""
    try:
        meta_path = find_session_dir(session_id) / "proxy_meta.json"
        meta_path.write_text(__import__("json").dumps(meta, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"写入失败: {e}")

    # best-effort update db
    try:
        from backend.app.database import SessionLocal
        from backend.models.proxy_capture_db import ProxySessionModel

        with SessionLocal() as db:
            row = db.get(ProxySessionModel, session_id)
            if row:
                row.notes = request.notes or ""
                db.commit()
    except Exception:
        pass

    return {"status": "success"}


@router.delete("/sessions/{session_id}")
async def delete_proxy_session(session_id: str):
    """删除 proxy capture 会话（目录 + DB 索引 + 关联 artifacts）。"""
    if not session_id or not _SAFE_SESSION_ID_RE.match(session_id):
        raise HTTPException(status_code=400, detail="无效的session_id")

    from backend.proxy.proxy_session import find_session_dir, delete_proxy_session as _delete

    session_dir = find_session_dir(session_id)
    if not session_dir.exists() or not session_dir.is_dir():
        raise HTTPException(status_code=404, detail="会话不存在")

    try:
        result = _delete(session_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="会话不存在")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"删除失败: {e}")

    return {"status": "success", **(result or {})}


@router.get("/sessions/{session_id}/requests")
async def get_proxy_session_requests(session_id: str, limit: int = 200, offset: int = 0):
    """获取某个会话的请求列表（合并后）。"""
    if not session_id or not _SAFE_SESSION_ID_RE.match(session_id):
        raise HTTPException(status_code=400, detail="无效的session_id")

    from backend.proxy.proxy_session import load_proxy_session_requests, load_proxy_session_meta

    meta = load_proxy_session_meta(session_id)
    if not meta:
        raise HTTPException(status_code=404, detail="会话不存在")

    records = load_proxy_session_requests(session_id)
    total = len(records)
    sliced = records[int(offset) : int(offset) + int(limit)]
    return {"requests": sliced, "total": total, "limit": limit, "offset": offset, "session": meta}


@router.get("/sessions/{session_id}/websockets")
async def get_proxy_session_websockets(session_id: str, limit: int = 200, offset: int = 0):
    """获取某个会话的 WebSocket 连接列表。"""
    if not session_id or not _SAFE_SESSION_ID_RE.match(session_id):
        raise HTTPException(status_code=400, detail="无效的session_id")

    from backend.proxy.proxy_session import load_proxy_session_ws_connections, load_proxy_session_meta

    meta = load_proxy_session_meta(session_id)
    if not meta:
        raise HTTPException(status_code=404, detail="会话不存在")

    connections = load_proxy_session_ws_connections(session_id)
    total = len(connections)
    sliced = connections[int(offset) : int(offset) + int(limit)]
    return {"connections": sliced, "total": total, "limit": limit, "offset": offset, "session": meta}


@router.get("/sessions/{session_id}/websockets/{connection_id}/messages")
async def get_proxy_session_websocket_messages(session_id: str, connection_id: str, limit: int = 500, offset: int = 0):
    """获取某个会话的指定 WebSocket 连接消息。"""
    if not session_id or not _SAFE_SESSION_ID_RE.match(session_id):
        raise HTTPException(status_code=400, detail="无效的session_id")
    if not connection_id:
        raise HTTPException(status_code=400, detail="无效的connection_id")

    from backend.proxy.proxy_session import load_proxy_session_ws_messages, load_proxy_session_meta

    meta = load_proxy_session_meta(session_id)
    if not meta:
        raise HTTPException(status_code=404, detail="会话不存在")

    messages = [m for m in load_proxy_session_ws_messages(session_id) if str(m.get("connection_id") or "") == str(connection_id)]
    total = len(messages)
    sliced = messages[int(offset) : int(offset) + int(limit)]
    return {"messages": sliced, "total": total, "limit": limit, "offset": offset, "session": meta, "connection_id": connection_id}


@router.get("/sessions/{session_id}/js-events")
async def get_proxy_session_js_events(session_id: str, limit: int = 500, offset: int = 0, correlated_request_id: Optional[str] = None):
    """获取某个会话的 JS 注入事件（fetch/xhr/ws 调用栈等）。"""
    if not session_id or not _SAFE_SESSION_ID_RE.match(session_id):
        raise HTTPException(status_code=400, detail="无效的session_id")

    from backend.proxy.proxy_session import load_proxy_session_js_events, load_proxy_session_meta

    meta = load_proxy_session_meta(session_id)
    if not meta:
        raise HTTPException(status_code=404, detail="会话不存在")

    events = load_proxy_session_js_events(session_id)
    if correlated_request_id:
        events = [e for e in events if str(e.get("correlated_request_id") or "") == str(correlated_request_id)]
    total = len(events)
    sliced = events[int(offset) : int(offset) + int(limit)]
    return {"events": sliced, "total": total, "limit": limit, "offset": offset, "session": meta}


@router.get("/storage/status")
async def get_proxy_storage_status():
    """获取 ProxyCapture 存储占用统计（artifacts + proxy sessions）。"""
    from backend.proxy.storage_maintenance import get_storage_status

    return get_storage_status()


@router.post("/storage/cleanup")
async def cleanup_proxy_storage(request: ProxyStorageCleanupRequest):
    """清理 ProxyCapture 存储（支持 dry-run）。"""
    from backend.proxy.storage_maintenance import plan_artifacts_cleanup, apply_artifacts_cleanup, plan_sessions_cleanup
    from backend.proxy.proxy_session import delete_proxy_session as _delete_session
    from backend.app.config import settings
    from backend.proxy.service_manager import ProxyServiceManager

    artifacts_max_total_mb = int(request.artifacts_max_total_mb) if int(request.artifacts_max_total_mb) > 0 else int(settings.proxy_artifacts_max_total_mb)
    artifacts_max_age_days = int(request.artifacts_max_age_days) if int(request.artifacts_max_age_days) > 0 else int(settings.proxy_artifacts_max_age_days)
    sessions_max_age_days = int(request.sessions_max_age_days) if int(request.sessions_max_age_days) > 0 else int(settings.proxy_sessions_max_age_days)

    artifacts_plan = plan_artifacts_cleanup(max_total_mb=artifacts_max_total_mb, max_age_days=artifacts_max_age_days)
    artifacts_result = apply_artifacts_cleanup(artifacts_plan, dry_run=bool(request.dry_run))

    sessions_plan = plan_sessions_cleanup(max_age_days=sessions_max_age_days)
    sessions_deleted = []
    sessions_failed = []
    if not request.dry_run:
        manager = ProxyServiceManager.get_instance()
        current_session = manager.get_proxy_session_id()
        for item in sessions_plan.get("items", []) or []:
            sid = str(item.get("session_id") or "")
            if not sid:
                continue
            if current_session and sid == current_session:
                continue
            try:
                sessions_deleted.append({"session_id": sid, **(_delete_session(sid) or {})})
            except Exception as exc:
                sessions_failed.append({"session_id": sid, "error": str(exc)})

    return {
        "dry_run": bool(request.dry_run),
        "resolved_policy": {
            "artifacts_max_total_mb": artifacts_max_total_mb,
            "artifacts_max_age_days": artifacts_max_age_days,
            "sessions_max_age_days": sessions_max_age_days,
        },
        "artifacts": {"plan": artifacts_plan, "result": artifacts_result},
        "sessions": {
            "plan": sessions_plan,
            "deleted": sessions_deleted,
            "failed": sessions_failed,
        },
    }


@router.post("/system-proxy/enable")
async def enable_system_proxy(request: SystemProxyRequest):
    """启用系统代理（WinINet/IE）。

    用于向导/排障时手动切换，避免必须重启代理服务。
    """
    from backend.proxy.service_manager import ProxyServiceManager

    manager = ProxyServiceManager.get_instance()
    if not manager.is_running():
        raise HTTPException(status_code=400, detail="代理服务未运行，无法启用系统代理")

    try:
        from backend.proxy import WindowsSystemProxy

        system_proxy = manager.get_system_proxy_instance() or WindowsSystemProxy()
        system_proxy.enable_proxy(host=request.host, port=request.port)
        manager.set_system_proxy_instance(system_proxy)
        manager.set_system_proxy_enabled(True)
        return {"status": "success", "message": "系统代理已启用"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"启用系统代理失败: {str(e)}")


@router.post("/system-proxy/disable")
async def disable_system_proxy():
    """恢复系统代理（WinINet/IE）到原始状态。"""
    from backend.proxy.service_manager import ProxyServiceManager

    manager = ProxyServiceManager.get_instance()
    try:
        system_proxy = manager.get_system_proxy_instance()
        if system_proxy:
            system_proxy.restore_original()
        manager.set_system_proxy_instance(None)
        manager.set_system_proxy_enabled(False)
        return {"status": "success", "message": "系统代理已恢复"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"恢复系统代理失败: {str(e)}")


@router.post("/winhttp-proxy/enable")
async def enable_winhttp_proxy(request: WinHttpProxyRequest):
    """启用 WinHTTP 代理。"""
    from backend.proxy.service_manager import ProxyServiceManager

    manager = ProxyServiceManager.get_instance()
    if not manager.is_running():
        raise HTTPException(status_code=400, detail="代理服务未运行，无法启用 WinHTTP 代理")

    try:
        from backend.proxy import WindowsWinHttpProxy

        winhttp_proxy = manager.get_winhttp_proxy_instance() or WindowsWinHttpProxy()
        if request.import_from_ie:
            winhttp_proxy.import_from_ie()
        else:
            winhttp_proxy.enable_proxy(host=request.host, port=request.port, bypass_list=request.bypass_list)
        manager.set_winhttp_proxy_instance(winhttp_proxy)
        manager.set_winhttp_proxy_enabled(True)
        return {"status": "success", "message": "WinHTTP 代理已启用"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"启用 WinHTTP 代理失败: {str(e)}")


@router.post("/winhttp-proxy/disable")
async def disable_winhttp_proxy():
    """恢复 WinHTTP 代理到原始状态。"""
    from backend.proxy.service_manager import ProxyServiceManager

    manager = ProxyServiceManager.get_instance()
    try:
        winhttp_proxy = manager.get_winhttp_proxy_instance()
        if winhttp_proxy:
            winhttp_proxy.restore_original()
        manager.set_winhttp_proxy_instance(None)
        manager.set_winhttp_proxy_enabled(False)
        return {"status": "success", "message": "WinHTTP 代理已恢复"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"恢复 WinHTTP 代理失败: {str(e)}")


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


@router.get("/artifacts/{artifact_id}")
async def download_proxy_artifact(artifact_id: str):
    """下载代理抓包落盘产物（请求/响应体、WS 二进制等）。"""
    from fastapi.responses import FileResponse
    from backend.proxy.artifacts import ProxyArtifactStore

    store = ProxyArtifactStore()
    try:
        path = store.resolve_artifact_path(artifact_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="无效的artifact_id")

    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail="文件不存在")

    return FileResponse(
        path=str(path),
        filename=path.name,
        media_type="application/octet-stream",
    )


@router.post("/artifacts/bundle")
async def bundle_proxy_artifacts(request: ArtifactBundleRequest, background_tasks: BackgroundTasks):
    """批量打包下载 artifacts（zip）。"""
    from fastapi.responses import FileResponse
    from backend.proxy.artifacts import ProxyArtifactStore
    import tempfile
    import zipfile
    from pathlib import Path
    import os

    store = ProxyArtifactStore()
    artifact_ids = [str(a) for a in (request.artifact_ids or []) if a]
    if not artifact_ids:
        raise HTTPException(status_code=400, detail="artifact_ids 不能为空")
    if len(artifact_ids) > 5000:
        raise HTTPException(status_code=400, detail="artifact_ids 过多（最多 5000）")

    tmp = tempfile.NamedTemporaryFile(prefix="proxy_artifacts_", suffix=".zip", delete=False)
    tmp_path = Path(tmp.name)
    tmp.close()

    added = 0
    with zipfile.ZipFile(str(tmp_path), "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for aid in artifact_ids:
            try:
                path = store.resolve_artifact_path(aid)
            except ValueError:
                continue
            if not path.exists() or not path.is_file():
                continue
            try:
                zf.write(str(path), arcname=path.name)
                added += 1
            except Exception:
                continue

    if added == 0:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
        raise HTTPException(status_code=404, detail="未找到任何可打包的artifact")

    def _cleanup(p: str):
        try:
            os.remove(p)
        except Exception:
            pass

    background_tasks.add_task(_cleanup, str(tmp_path))
    return FileResponse(path=str(tmp_path), filename="proxy_artifacts.zip", media_type="application/zip")


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

    manager = ProxyServiceManager.get_instance()

    # 补充抓包环境快照（用于前端过滤/排障；不代表单条请求必然来自该代理栈）
    try:
        request_data["proxy_state"] = {
            "wininet_enabled": manager.is_system_proxy_enabled(),
            "winhttp_enabled": manager.is_winhttp_proxy_enabled(),
        }
    except Exception:
        request_data["proxy_state"] = None

    # 会话ID（用于前端/落盘关联）
    try:
        request_data["proxy_session_id"] = manager.get_proxy_session_id() or ""
    except Exception:
        request_data["proxy_session_id"] = ""

    # 跟踪设备（增强：补充 IP/端口/稳定标识，便于移动端筛选来源）
    if 'device' in request_data and isinstance(request_data.get('device'), dict):
        try:
            ca = request_data.get("client_address") or {}
            if isinstance(ca, dict):
                if ca.get("host") and not request_data["device"].get("ip"):
                    request_data["device"]["ip"] = ca.get("host")
                if ca.get("port") and not request_data["device"].get("client_port"):
                    request_data["device"]["client_port"] = ca.get("port")
        except Exception:
            pass
        manager.track_device(request_data['device'])

    # 保存到存储
    try:
        unified_request = UnifiedRequest.from_proxy_request(request_data)
        record = unified_request.to_dict()

        # 记录统计（尽量使用统一结构，包含 source 等字段）
        manager.get_statistics().record_request(record)

        storage = manager.get_storage()
        storage.save_request(unified_request)
        # request_id 已经在 request_data 中，无需重新赋值

        # session 落盘（best-effort）
        try:
            recorder = manager.get_proxy_session_recorder()
            if recorder:
                recorder.record_request(record)
                if record.get("body_artifact"):
                    recorder.record_artifact(record.get("body_artifact"))
        except Exception:
            pass

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

    manager = ProxyServiceManager.get_instance()
    # 记录统计（响应）
    try:
        manager.get_statistics().record_response(response_data)
    except Exception:
        pass

    # 更新请求的响应信息 - 使用请求ID而不是URL
    storage = manager.get_storage()
    request_id = response_data.get('request_id')
    if request_id:
        # 会话ID（用于前端联动）
        try:
            response_data["proxy_session_id"] = manager.get_proxy_session_id() or ""
        except Exception:
            response_data["proxy_session_id"] = ""

        storage.update_response(request_id, response_data)

        # session 落盘（best-effort，存储为统一字段名）
        try:
            recorder = manager.get_proxy_session_recorder()
            if recorder:
                resp_record = {
                    "status_code": response_data.get("status_code"),
                    "response_headers": response_data.get("headers", {}),
                    "response_body": response_data.get("body"),
                    "response_body_artifact": response_data.get("body_artifact"),
                    "response_body_preview_hex": response_data.get("body_preview_hex"),
                    "response_size": response_data.get("content_length"),
                    "response_time": response_data.get("response_time"),
                    "timestamp": response_data.get("timestamp"),
                    "streaming": response_data.get("streaming"),
                    "grpc": response_data.get("grpc"),
                    "protobuf": response_data.get("protobuf"),
                }
                # content_type 优先来自响应头
                try:
                    ct = (response_data.get("headers", {}) or {}).get("Content-Type") or ""
                    resp_record["content_type"] = str(ct).split(";", 1)[0].strip()
                except Exception:
                    resp_record["content_type"] = None
                recorder.record_response(str(request_id), resp_record)
                if resp_record.get("response_body_artifact"):
                    recorder.record_artifact(resp_record.get("response_body_artifact"))
        except Exception:
            pass

        # 广播响应更新到 WebSocket 客户端
        main_loop = manager.get_main_event_loop()
        if main_loop:
            try:
                asyncio.run_coroutine_threadsafe(broadcaster.broadcast_response(response_data), main_loop)
            except Exception as e:
                logger.error(f"WebSocket广播响应失败: {e}")

    logger.info(f"捕获响应: {response_data['status_code']} {response_data['url']}")


def _handle_websocket_event(ws_event: dict):
    """处理捕获的 WebSocket 事件（握手/消息/关闭）。"""
    from backend.proxy.service_manager import ProxyServiceManager
    from backend.app.websocket.proxy_events import broadcaster
    import asyncio
    import logging
    import uuid

    logger = logging.getLogger(__name__)

    manager = ProxyServiceManager.get_instance()
    storage = manager.get_storage()

    try:
        event_type = ws_event.get("event")
        request_id = ws_event.get("request_id") or ""
        connection_id = str(request_id) if request_id else ""

        proxy_session_id = ""
        try:
            proxy_session_id = manager.get_proxy_session_id() or ""
        except Exception:
            proxy_session_id = ""
        try:
            ws_event["proxy_session_id"] = proxy_session_id
        except Exception:
            pass

        if event_type in {"ws_start", "ws_end"} and connection_id:
            storage.upsert_ws_connection(connection_id, ws_event.get("url", ""), event_type, ws_event.get("timestamp"))

        if event_type == "ws_message" and connection_id:
            message_id = f"wsmsg_{uuid.uuid4().hex}"
            message_record = {
                "id": message_id,
                "connection_id": connection_id,
                "url": ws_event.get("url", ""),
                "timestamp": ws_event.get("timestamp"),
                "proxy_session_id": proxy_session_id,
                "direction": ws_event.get("direction"),
                "is_text": ws_event.get("is_text"),
                "size": ws_event.get("size"),
                "data": ws_event.get("data", ""),
                "data_artifact": ws_event.get("data_artifact"),
            }
            storage.upsert_ws_connection(connection_id, ws_event.get("url", ""), event_type, ws_event.get("timestamp"))
            storage.add_ws_message(connection_id, message_record)
            ws_event = message_record
        elif connection_id:
            # 标准化事件结构
            ws_event = {
                "id": f"wsevt_{uuid.uuid4().hex}",
                "connection_id": connection_id,
                "url": ws_event.get("url", ""),
                "timestamp": ws_event.get("timestamp"),
                "event": event_type,
                "proxy_session_id": proxy_session_id,
            }

        # session 落盘（best-effort）
        try:
            recorder = manager.get_proxy_session_recorder()
            if recorder:
                if ws_event.get("direction"):
                    recorder.record_ws_message(ws_event)
                    if ws_event.get("data_artifact"):
                        recorder.record_artifact(ws_event.get("data_artifact"))
                else:
                    recorder.record_ws_connection_event(ws_event)
        except Exception:
            pass

        # 广播到 WebSocket 客户端（实时）
        main_loop = manager.get_main_event_loop()
        if main_loop:
            try:
                asyncio.run_coroutine_threadsafe(broadcaster.broadcast_websocket_event(ws_event), main_loop)
            except Exception as e:
                logger.error(f"WebSocket广播WS事件失败: {e}")
    except Exception as e:
        logger.error(f"处理WebSocket事件失败: {e}", exc_info=True)


@router.get("/requests")
async def get_proxy_requests(
    source: Optional[str] = None,
    platform: Optional[str] = None,
    include_sensitive: Optional[bool] = None,
    q: Optional[str] = None,
    protocol: Optional[str] = None,
    status_group: Optional[str] = None,
    content_type_group: Optional[str] = None,
    proxy_stack: Optional[str] = None,
    process_name: Optional[str] = None,
    tag: Optional[str] = None,
    proxy_session_id: Optional[str] = None,
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

    page = storage.get_requests_page(
        source=source_enum,
        platform=platform,
        q=q,
        protocol=protocol,
        status_group=status_group,
        content_type_group=content_type_group,
        proxy_stack=proxy_stack,
        process_name=process_name,
        tag=tag,
        proxy_session_id=proxy_session_id,
        limit=limit,
        offset=offset,
    )
    requests = page.get("requests") or []

    from backend.app.config import settings

    resolved_include_sensitive = include_sensitive if include_sensitive is not None else (not settings.proxy_mask_sensitive_default)

    if not resolved_include_sensitive:
        from backend.proxy.privacy import sanitize_request_record

        requests = [sanitize_request_record(r) for r in requests]

    return {
        "requests": requests,
        "total": int(page.get("total") or 0),
        "overall_total": int(page.get("overall_total") or 0),
        "limit": limit,
        "offset": offset
    }


@router.delete("/requests")
async def clear_proxy_requests():
    """清空代理请求缓存（仅影响内存，不影响已落盘会话）。"""
    from backend.proxy.service_manager import ProxyServiceManager

    manager = ProxyServiceManager.get_instance()
    storage = manager.get_storage()
    try:
        storage.clear_requests()
    except Exception:
        pass
    try:
        manager.get_statistics().reset()
    except Exception:
        pass
    return {"status": "success", "message": "已清空请求缓存"}


@router.get("/request/{request_id}")
async def get_proxy_request_detail(request_id: str, include_sensitive: Optional[bool] = None):
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
        # fallback: 查找落盘会话
        try:
            from backend.app.database import SessionLocal
            from backend.models.proxy_capture_db import ProxyRequestIndexModel
            from backend.proxy.proxy_session import load_proxy_session_requests

            with SessionLocal() as db:
                idx = db.get(ProxyRequestIndexModel, request_id)
            if idx and idx.session_id:
                for r in load_proxy_session_requests(idx.session_id):
                    if str(r.get("id") or "") == str(request_id):
                        request = r
                        break
        except Exception:
            request = None

    if not request:
        raise HTTPException(status_code=404, detail=f"请求不存在: {request_id}")

    from backend.app.config import settings

    resolved_include_sensitive = include_sensitive if include_sensitive is not None else (not settings.proxy_mask_sensitive_default)

    if resolved_include_sensitive:
        return request

    from backend.proxy.privacy import sanitize_request_record
    return sanitize_request_record(request)


@router.get("/requests/export")
async def export_requests(
    format: str = "har",
    source: Optional[str] = None,
    platform: Optional[str] = None,
    limit: int = 1000,
    include_sensitive: Optional[bool] = None,
    session_id: Optional[str] = None,
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

    if format not in ["har", "csv", "json"]:
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

    # 获取请求列表（可从 session 落盘读取）
    if session_id:
        from backend.proxy.proxy_session import load_proxy_session_requests

        if not _SAFE_SESSION_ID_RE.match(session_id):
            raise HTTPException(status_code=400, detail="无效的session_id")
        requests = load_proxy_session_requests(session_id)
        if source_enum:
            requests = [r for r in requests if r.get("source") == source_enum]
        if platform:
            requests = [r for r in requests if (r.get("device_info") or {}).get("platform") == platform]
        requests = requests[: int(limit)]
    else:
        requests = storage.get_requests(
            source=source_enum,
            platform=platform,
            limit=limit,
            offset=0
        )

    from backend.app.config import settings

    resolved_include_sensitive = include_sensitive if include_sensitive is not None else (not settings.proxy_mask_sensitive_default)

    if not resolved_include_sensitive:
        from backend.proxy.privacy import sanitize_request_record

        requests = [sanitize_request_record(r) for r in requests]

    if format == "json":
        return Response(
            content=json.dumps({"session_id": session_id or manager.get_proxy_session_id() or "", "requests": requests}, ensure_ascii=False, indent=2),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="requests_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json"'
            },
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

        http_version = req.get("http_version") or "HTTP/1.1"
        resp_http_version = http_version

        # 构建HAR entry
        entry = {
            "startedDateTime": datetime.fromtimestamp(req.get("timestamp", 0)).isoformat() + "Z",
            "time": (req.get("response_time", 0) or 0) * 1000,  # 转换为毫秒
            "request": {
                "method": req.get("method", "GET"),
                "url": req.get("url", ""),
                "httpVersion": http_version,
                "headers": request_headers,
                "queryString": [],
                "cookies": [],
                "headersSize": -1,
                "bodySize": request_body_size,
            },
            "response": {
                "status": req.get("status_code", 0) or 0,
                "statusText": "",
                "httpVersion": resp_http_version,
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

        # best-effort: request body
        if req.get("body"):
            entry["request"]["postData"] = {
                "mimeType": req.get("content_type", "") or "",
                "text": req.get("body", "") or "",
            }

        # 自定义元数据（非 HAR 标准字段）
        entry["_web_analyzer"] = {
            "id": req.get("id"),
            "proxy_session_id": req.get("proxy_session_id") or req.get("proxy_session_id") or "",
            "source": req.get("source"),
            "device_info": req.get("device_info"),
            "client_process": req.get("client_process"),
            "server_address": req.get("server_address"),
            "client_address": req.get("client_address"),
            "tls": req.get("tls"),
            "tags": req.get("tags"),
            "proxy_state": req.get("proxy_state"),
            "is_websocket_handshake": req.get("is_websocket_handshake"),
            "error": req.get("error"),
        }
        # 记录落盘引用（非标准字段，但对排障很有用）
        if req.get("body_artifact"):
            entry["request"]["_artifact"] = req.get("body_artifact")
        if req.get("response_body_artifact"):
            entry["response"]["content"]["_artifact"] = req.get("response_body_artifact")
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
        "Proxy Session ID",
        "Timestamp",
        "Method",
        "URL",
        "Status Code",
        "Response Time (s)",
        "Response Size (bytes)",
        "Source",
        "Platform",
        "Content Type",
        "HTTP Version",
        "Server Host",
        "Server Port",
        "Client Process",
        "Client PID",
        "Client EXE",
        "TLS SNI",
        "TLS ALPN",
        "Request Artifact ID",
        "Response Artifact ID",
        "Tags",
        "Is WebSocket Handshake",
        "Error",
    ])

    # 写入数据行
    for req in requests:
        timestamp = datetime.fromtimestamp(req.get("timestamp", 0)).strftime("%Y-%m-%d %H:%M:%S")
        device_info = req.get("device_info", {})
        server_address = req.get("server_address") or {}
        tls = req.get("tls") or {}
        proc = req.get("client_process") or {}
        req_art = (req.get("body_artifact") or {}).get("artifact_id") if isinstance(req.get("body_artifact"), dict) else ""
        resp_art = (req.get("response_body_artifact") or {}).get("artifact_id") if isinstance(req.get("response_body_artifact"), dict) else ""
        tags = req.get("tags") or []
        if isinstance(tags, list):
            tags_str = ",".join(str(t) for t in tags)
        else:
            tags_str = str(tags)
        err = req.get("error")
        err_str = ""
        if isinstance(err, dict):
            err_str = str(err.get("message") or err.get("error") or "")
        elif err is not None:
            err_str = str(err)

        writer.writerow([
            req.get("id", ""),
            req.get("proxy_session_id", "") or "",
            timestamp,
            req.get("method", ""),
            req.get("url", ""),
            req.get("status_code", ""),
            req.get("response_time", ""),
            req.get("response_size", ""),
            req.get("source", ""),
            device_info.get("platform", "") if device_info else "",
            req.get("content_type", ""),
            req.get("http_version", ""),
            server_address.get("host", ""),
            server_address.get("port", ""),
            proc.get("name", ""),
            proc.get("pid", ""),
            proc.get("exe", ""),
            tls.get("sni", ""),
            tls.get("alpn", ""),
            req_art or "",
            resp_art or "",
            tags_str,
            "true" if req.get("is_websocket_handshake") else "false",
            err_str,
        ])

    return output.getvalue()


@router.get("/websockets")
async def list_websocket_connections(limit: int = 100, offset: int = 0):
    """列出 WebSocket 连接（按最近活动排序）。"""
    from backend.proxy.service_manager import ProxyServiceManager

    manager = ProxyServiceManager.get_instance()
    storage = manager.get_storage()
    connections = storage.get_ws_connections(limit=limit, offset=offset)
    total = storage.count_ws_connections()
    return {"connections": connections, "total": total, "limit": limit, "offset": offset, "count": len(connections)}


@router.get("/websockets/export")
async def export_websockets(
    format: str = "json",
    session_id: Optional[str] = None,
    connection_id: Optional[str] = None,
    limit: int = 5000,
):
    """导出 WebSocket 连接与消息（json/csv）。

    - session_id 为空：导出当前内存缓存
    - session_id 非空：导出落盘会话
    """
    from fastapi.responses import Response
    import json
    import csv
    from io import StringIO
    from datetime import datetime

    if format not in {"json", "csv"}:
        raise HTTPException(status_code=400, detail=f"不支持的导出格式: {format}")

    connections = []
    messages = []

    if session_id:
        if not _SAFE_SESSION_ID_RE.match(session_id):
            raise HTTPException(status_code=400, detail="无效的session_id")
        from backend.proxy.proxy_session import load_proxy_session_ws_connections, load_proxy_session_ws_messages

        connections = load_proxy_session_ws_connections(session_id)
        messages = load_proxy_session_ws_messages(session_id)
    else:
        from backend.proxy.service_manager import ProxyServiceManager

        manager = ProxyServiceManager.get_instance()
        storage = manager.get_storage()
        connections = storage.get_all_ws_connections()
        messages = storage.get_all_ws_messages()

    if connection_id:
        messages = [m for m in messages if str(m.get("connection_id") or "") == str(connection_id)]

    messages = messages[: int(limit)]

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    if format == "json":
        return Response(
            content=json.dumps({"session_id": session_id or "", "connections": connections, "messages": messages}, ensure_ascii=False, indent=2, default=str),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="websockets_{ts}.json"'},
        )

    # csv (messages)
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["message_id", "connection_id", "url", "timestamp", "direction", "is_text", "size", "data_preview", "artifact_id"])
    for m in messages:
        art_id = ""
        if isinstance(m.get("data_artifact"), dict):
            art_id = str(m.get("data_artifact", {}).get("artifact_id") or "")
        writer.writerow(
            [
                m.get("id", ""),
                m.get("connection_id", ""),
                m.get("url", ""),
                m.get("timestamp", ""),
                m.get("direction", ""),
                m.get("is_text", ""),
                m.get("size", ""),
                m.get("data", ""),
                art_id,
            ]
        )
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="websockets_{ts}.csv"'},
    )


@router.get("/websockets/{connection_id}")
async def get_websocket_connection(connection_id: str):
    """获取单个 WebSocket 连接信息。"""
    from backend.proxy.service_manager import ProxyServiceManager

    manager = ProxyServiceManager.get_instance()
    storage = manager.get_storage()
    conn = storage.get_ws_connection(connection_id)
    if not conn:
        raise HTTPException(status_code=404, detail="WebSocket连接不存在")
    return conn


@router.get("/websockets/{connection_id}/messages")
async def list_websocket_messages(connection_id: str, limit: int = 200, offset: int = 0, direction: Optional[str] = None, min_size: Optional[int] = None):
    """列出指定 WebSocket 连接的消息。"""
    from backend.proxy.service_manager import ProxyServiceManager

    manager = ProxyServiceManager.get_instance()
    storage = manager.get_storage()
    page = storage.get_ws_messages_page(connection_id, limit=limit, offset=offset, direction=direction, min_size=min_size)
    messages = page.get("messages") or []
    total = int(page.get("total") or 0)
    return {"messages": messages, "connection_id": connection_id, "total": total, "limit": limit, "offset": offset, "count": len(messages)}


@router.delete("/websockets")
async def clear_websockets():
    """清空 WebSocket 连接与消息（仅影响内存缓存）。"""
    from backend.proxy.service_manager import ProxyServiceManager

    manager = ProxyServiceManager.get_instance()
    storage = manager.get_storage()
    storage.clear_ws()
    return {"status": "success", "message": "WebSocket数据已清空"}


def _restore_system_proxies(manager):
    """恢复系统代理设置（WinINet/IE + WinHTTP）。

    该函数必须“尽力而为”，即使回滚失败也要保证不阻塞 stop/start 流程。
    """
    import logging

    logger = logging.getLogger(__name__)

    # WinINet/IE
    if manager.is_system_proxy_enabled():
        system_proxy = manager.get_system_proxy_instance()
        if system_proxy:
            try:
                system_proxy.restore_original()
            except Exception as exc:
                logger.warning("恢复系统代理(WinINet)失败: %s", exc)
        manager.set_system_proxy_instance(None)
        manager.set_system_proxy_enabled(False)

    # WinHTTP
    if manager.is_winhttp_proxy_enabled():
        winhttp_proxy = manager.get_winhttp_proxy_instance()
        if winhttp_proxy:
            try:
                winhttp_proxy.restore_original()
            except Exception as exc:
                logger.warning("恢复 WinHTTP 代理失败: %s", exc)
        manager.set_winhttp_proxy_instance(None)
        manager.set_winhttp_proxy_enabled(False)
