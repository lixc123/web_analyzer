"""
Native Hook API接口
提供Frida Hook相关的REST API
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
import uuid
from datetime import datetime
from pathlib import Path
import logging

from models.hook_record import HookRecord, ProcessInfo, HookSession, HookScriptTemplate
from native_hook.frida_bridge import FridaHook, check_frida_installed, get_frida_version

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/native-hook", tags=["Native Hook"])

# 全局Hook实例管理
hook_instances: Dict[str, FridaHook] = {}
active_sessions: Dict[str, HookSession] = {}

# 持久化存储
from backend.app.services.hook_storage import HookStorage

hook_storage = HookStorage()

# Hook 原始 buffer 落盘预算（避免误配置导致磁盘爆炸）
_RAW_BYTES_BUDGET_PER_SESSION = 50 * 1024 * 1024  # 50MB
_RAW_BYTES_MAX_PER_RECORD = 256 * 1024  # 256KB
_raw_bytes_used_by_session: Dict[str, int] = {}


class AttachRequest(BaseModel):
    """附加请求"""
    process_name: Optional[str] = None
    pid: Optional[int] = None


class InjectScriptRequest(BaseModel):
    """注入脚本请求"""
    script_code: Optional[str] = None
    template_name: Optional[str] = None
    template_params: Optional[Dict[str, Any]] = None


@router.get("/status")
async def get_hook_status():
    """获取Hook状态"""
    try:
        frida_installed = check_frida_installed()
        frida_version = get_frida_version()

        return {
            "frida_installed": frida_installed,
            "frida_version": frida_version,
            "active_sessions": len([s for s in active_sessions.values() if s.status == "active"]),
            "total_records": hook_storage.total_records()
        }
    except Exception as e:
        logger.error(f"获取Hook状态失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/processes")
async def list_processes():
    """列出所有运行中的进程"""
    try:
        # 检查Frida是否安装
        if not check_frida_installed():
            raise HTTPException(status_code=400, detail="Frida未安装")

        # 创建临时Hook实例
        hook = FridaHook()
        processes = hook.list_processes()

        return {
            "processes": processes,
            "count": len(processes)
        }
    except Exception as e:
        logger.error(f"列出进程失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/attach")
async def attach_process(request: AttachRequest):
    """附加到进程"""
    try:
        # 检查Frida是否安装
        if not check_frida_installed():
            raise HTTPException(status_code=400, detail="Frida未安装")

        # 验证参数
        if not request.process_name and not request.pid:
            raise HTTPException(status_code=400, detail="必须提供process_name或pid")

        # 创建Hook实例
        session_id = str(uuid.uuid4())
        hook = FridaHook()

        # 附加到进程
        if request.process_name:
            hook.attach_process(request.process_name)
        else:
            hook.attach_pid(request.pid)

        # 保存Hook实例
        hook_instances[session_id] = hook

        # 创建会话记录
        process_info = hook.get_process_info()
        session = HookSession(
            session_id=session_id,
            process_name=process_info['process_name'],
            pid=process_info['pid'],
            script_name="",
            started_at=datetime.now(),
            status="active"
        )
        active_sessions[session_id] = session
        # 持久化会话
        try:
            hook_storage.create_session(session_id, session.process_name, session.pid)
        except Exception as e:
            logger.warning(f"持久化会话失败（不影响附加）: {e}")

        return {
            "session_id": session_id,
            "process_name": process_info['process_name'],
            "pid": process_info['pid'],
            "message": "成功附加到进程"
        }

    except Exception as e:
        logger.error(f"附加进程失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/detach/{session_id}")
async def detach_process(session_id: str):
    """分离进程"""
    try:
        if session_id not in hook_instances:
            raise HTTPException(status_code=404, detail="会话不存在")

        hook = hook_instances[session_id]
        hook.detach()

        # 更新会话状态
        if session_id in active_sessions:
            active_sessions[session_id].status = "stopped"
            active_sessions[session_id].ended_at = datetime.now()
        try:
            hook_storage.update_session(session_id, status="stopped", ended_at=datetime.utcnow())
        except Exception as e:
            logger.warning(f"更新会话状态失败: {e}")

        # 删除Hook实例
        del hook_instances[session_id]
        active_sessions.pop(session_id, None)
        _raw_bytes_used_by_session.pop(session_id, None)

        return {"message": "成功分离进程"}

    except Exception as e:
        logger.error(f"分离进程失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/inject-script/{session_id}")
async def inject_script(session_id: str, request: InjectScriptRequest):
    """注入Frida脚本"""
    try:
        if session_id not in hook_instances:
            raise HTTPException(status_code=404, detail="会话不存在")

        hook = hook_instances[session_id]

        # 获取脚本代码
        script_code = None
        if request.script_code:
            script_code = request.script_code
        elif request.template_name:
            # 从模板管理器加载脚本
            from native_hook.templates import get_template_manager

            manager = get_template_manager()
            template = manager.get_template(request.template_name)

            if not template:
                raise HTTPException(status_code=404, detail=f"脚本模板不存在: {request.template_name}")

            # 支持模板参数渲染
            params = request.template_params or {}
            try:
                script_code = template.render(**params)
            except Exception:
                script_code = template.load_script()
        else:
            raise HTTPException(status_code=400, detail="必须提供script_code或template_name")

        # 定义消息处理器
        def message_handler(payload: Dict[str, Any], data: Optional[bytes]):
            try:
                # 创建Hook记录
                hook_type = payload.get('type', 'unknown')
                api_name = payload.get('api', 'unknown')
                hook_id = str(uuid.uuid4())

                # 优先使用内存中的会话信息；若不存在则回退到 payload
                sess = active_sessions.get(session_id)
                process_name = sess.process_name if sess else payload.get("process_name", "unknown")
                pid = sess.pid if sess else int(payload.get("pid", 0) or 0)

                # 弱关联：若 Hook 捕获到了 url/method，尝试与代理抓包的 request_id 关联，方便前端联动
                try:
                    url = payload.get("url")
                    method = payload.get("method")
                    if url and method:
                        import time
                        from backend.proxy.service_manager import ProxyServiceManager

                        proxy_manager = ProxyServiceManager.get_instance()
                        req_storage = proxy_manager.get_storage()
                        target_host = None
                        target_port = None
                        try:
                            peer = payload.get("peer") or {}
                            if isinstance(peer, dict):
                                target_host = peer.get("host") or peer.get("ip")
                                target_port = peer.get("port")
                        except Exception:
                            target_host = None
                            target_port = None

                        try:
                            from urllib.parse import urlparse

                            parsed = urlparse(str(url))
                            if not target_host and parsed.netloc:
                                # parsed.netloc may contain port
                                host = parsed.hostname
                                if host:
                                    target_host = host
                            if target_port is None and parsed.port:
                                target_port = parsed.port
                        except Exception:
                            pass

                        corr = None
                        try:
                            corr = req_storage.find_recent_request_id_multi_factor(
                                url=str(url),
                                method=str(method),
                                target_host=str(target_host) if target_host else None,
                                target_port=int(target_port) if target_port is not None else None,
                                window_seconds=8.0,
                                base_timestamp=time.time(),
                            )
                        except Exception:
                            corr = None

                        if corr and corr.get("request_id"):
                            payload["_correlated_request_id"] = corr.get("request_id")
                            payload["_correlation"] = corr
                        else:
                            correlated_id = req_storage.find_recent_request_id(
                                url=str(url),
                                method=str(method),
                                window_seconds=8.0,
                                base_timestamp=time.time(),
                            )
                            if correlated_id:
                                payload["_correlated_request_id"] = correlated_id
                except Exception:
                    pass

                # 可选：保存 Frida data 通道的原始 buffer（用于 AI 对比字节特征）
                if data:
                    try:
                        used = int(_raw_bytes_used_by_session.get(session_id, 0) or 0)
                        remaining = max(0, _RAW_BYTES_BUDGET_PER_SESSION - used)
                        if remaining <= 0:
                            payload["_raw_buffer_artifact"] = {"skipped": True, "reason": "session_budget_exhausted"}
                        else:
                            cap = min(len(data), _RAW_BYTES_MAX_PER_RECORD, remaining)
                            blob = bytes(data[:cap])
                            from backend.app.services.hook_artifacts import HookArtifactStore

                            store = HookArtifactStore()
                            art = store.store_bytes(blob, content_type="application/octet-stream", prefix="hookraw")
                            payload["_raw_buffer_artifact"] = {
                                **art.to_dict(),
                                "captured_bytes": int(cap),
                                "original_bytes": int(len(data)),
                                "truncated": bool(cap < len(data)),
                            }
                            _raw_bytes_used_by_session[session_id] = used + int(cap)
                    except Exception as e:
                        payload["_raw_buffer_artifact"] = {"error": str(e)}

                hook_storage.add_record(
                    hook_id=hook_id,
                    session_id=session_id,
                    process_name=process_name,
                    pid=pid,
                    hook_type=hook_type,
                    api_name=api_name,
                    args=payload,
                    timestamp=datetime.utcnow(),
                    return_value=None,
                    stack_trace=payload.get("stack_trace"),
                    thread_id=payload.get("thread_id"),
                )

                if sess:
                    sess.record_count += 1

                logger.info(f"收到Hook记录: {api_name}")
            except Exception as e:
                logger.error(f"处理Hook消息失败: {e}")

        # 注入脚本
        hook.inject_script(script_code, message_handler)

        # 更新会话
        script_name = request.template_name or "custom"
        if session_id in active_sessions:
            active_sessions[session_id].script_name = script_name
        try:
            hook_storage.update_session(session_id, script_name=script_name)
        except Exception as e:
            logger.warning(f"更新会话脚本名失败: {e}")

        return {"message": "脚本注入成功"}

    except Exception as e:
        logger.error(f"注入脚本失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/templates")
async def list_templates(category: Optional[str] = None):
    """列出所有Hook脚本模板"""
    try:
        from native_hook.templates import get_template_manager

        manager = get_template_manager()
        templates = manager.list_templates(category=category)
        categories = manager.get_categories()

        return {
            "templates": templates,
            "categories": categories,
            "count": len(templates)
        }

    except Exception as e:
        logger.error(f"列出模板失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/templates/{template_name}")
async def get_template(template_name: str):
    """获取模板详情"""
    try:
        from native_hook.templates import get_template_manager

        manager = get_template_manager()
        template = manager.get_template(template_name)

        if not template:
            raise HTTPException(status_code=404, detail="模板不存在")

        return {
            "name": template.name,
            "description": template.description,
            "category": template.category,
            # 返回渲染后的脚本（使用 default_params），避免占位符影响直接复制使用
            "script_code": template.render()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取模板失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


class CreateTemplateRequest(BaseModel):
    """创建模板请求"""
    name: str
    description: str
    script_content: str
    category: str = "custom"


@router.post("/templates")
async def create_template(request: CreateTemplateRequest):
    """创建自定义模板"""
    try:
        from native_hook.templates import get_template_manager

        manager = get_template_manager()
        template = manager.create_custom_template(
            name=request.name,
            description=request.description,
            script_content=request.script_content,
            category=request.category
        )

        return {
            "status": "success",
            "message": "模板创建成功",
            "template": template.to_dict()
        }

    except Exception as e:
        logger.error(f"创建模板失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/templates/{template_name}")
async def delete_template(template_name: str):
    """删除自定义模板"""
    try:
        from native_hook.templates import get_template_manager

        manager = get_template_manager()
        success = manager.delete_template(template_name)

        if not success:
            raise HTTPException(status_code=404, detail="模板不存在")

        return {
            "status": "success",
            "message": "模板删除成功"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"删除模板失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/records")
async def get_hook_records(
    session_id: Optional[str] = None,
    hook_type: Optional[str] = None,
    api_name: Optional[str] = None,
    correlated_request_id: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    """获取Hook记录"""
    try:
        records, total = hook_storage.list_records(
            session_id=session_id,
            hook_type=hook_type,
            api_name=api_name,
            correlated_request_id=correlated_request_id,
            limit=limit,
            offset=offset,
        )
        return {"records": records, "total": total, "limit": limit, "offset": offset}

    except Exception as e:
        logger.error(f"获取Hook记录失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/records")
async def clear_hook_records(session_id: Optional[str] = None):
    """清空Hook记录"""
    try:
        count = hook_storage.clear_records(session_id=session_id)
        return {"message": f"已清空{count}条记录"}

    except Exception as e:
        logger.error(f"清空记录失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions")
async def list_sessions():
    """列出所有Hook会话"""
    try:
        sessions, total = hook_storage.list_sessions(limit=500, offset=0)
        return {"sessions": sessions, "count": total}

    except Exception as e:
        logger.error(f"列出会话失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions/{session_id}")
async def get_session(session_id: str):
    """获取会话详情"""
    try:
        session = hook_storage.get_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="会话不存在")
        return session

    except Exception as e:
        logger.error(f"获取会话失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions/{session_id}/modules")
async def list_session_modules(session_id: str, limit: int = 800):
    """列出会话进程加载模块（用于判断是否 OpenSSL/BoringSSL/mbedTLS）。"""
    try:
        hook = hook_instances.get(session_id)
        if not hook:
            raise HTTPException(status_code=404, detail="会话不存在")
        modules = hook.list_modules(limit=limit)
        return {"session_id": session_id, "modules": modules, "count": len(modules)}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"列出模块失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions/{session_id}/recommendations")
async def get_session_recommendations(session_id: str):
    """根据已加载模块给出推荐模板（best-effort）。"""
    try:
        hook = hook_instances.get(session_id)
        if not hook:
            raise HTTPException(status_code=404, detail="会话不存在")

        modules = hook.list_modules(limit=1200)
        names = [str(m.get("name") or "").lower() for m in modules if m.get("name")]

        detected = {
            "openssl": any(("libssl" in n) or ("ssleay32" in n) or ("boringssl" in n) for n in names),
            "mbedtls": any("mbedtls" in n for n in names),
            "schannel": any(("winhttp" in n) or ("wininet" in n) or ("crypt32" in n) or ("wintrust" in n) for n in names),
            "quic": any(("quic" in n) or ("msquic" in n) for n in names),
            "compression": any(("zlib" in n) or ("cabinet" in n) or ("compression" in n) for n in names),
        }

        recs = []
        # 通用：Windows 证书校验路径
        recs.append({"template_name": "windows_ssl_unpinning", "reason": "通用 Windows 证书校验路径（WinVerifyTrust/CertVerifyCertificateChainPolicy）"})
        # OpenSSL/BoringSSL
        if detected["openssl"]:
            recs.append({"template_name": "openssl_ssl_unpinning", "reason": "检测到 libssl/boringssl 相关模块"})
        # mbedTLS
        if detected["mbedtls"]:
            recs.append({"template_name": "mbedtls_ssl_unpinning", "reason": "检测到 mbedtls 相关模块"})

        # 应用层加密定位
        recs.append({"template_name": "encryption_locator", "reason": "定位应用层加密/签名（采样+调用栈）"})
        recs.append({"template_name": "compression_monitor", "reason": "定位压缩/解压（业务数据变换点，采样+调用栈）"})

        # 仅返回当前存在的模板
        try:
            from native_hook.templates import get_template_manager

            mgr = get_template_manager()
            recs = [r for r in recs if mgr.get_template(r.get("template_name"))]
        except Exception:
            pass

        return {"session_id": session_id, "detected": detected, "recommendations": recs}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取推荐失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/records/export")
async def export_hook_records(
    format: str = "json",
    session_id: Optional[str] = None,
    hook_type: Optional[str] = None,
    api_name: Optional[str] = None,
    limit: int = 5000,
):
    """导出 Hook 记录（json/csv）。"""
    from fastapi.responses import Response
    import csv
    import json
    from io import StringIO
    from datetime import datetime

    if format not in {"json", "csv"}:
        raise HTTPException(status_code=400, detail=f"不支持的导出格式: {format}")

    records, _total = hook_storage.list_records(
        session_id=session_id,
        hook_type=hook_type,
        api_name=api_name,
        limit=limit,
        offset=0,
    )

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    if format == "json":
        return Response(
            content=json.dumps({"records": records}, ensure_ascii=False, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="hook_records_{ts}.json"'},
        )

    # csv
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["hook_id", "session_id", "process_name", "pid", "hook_type", "api_name", "timestamp", "args"])
    for r in records:
        writer.writerow(
            [
                r.get("hook_id", ""),
                r.get("session_id", ""),
                r.get("process_name", ""),
                r.get("pid", ""),
                r.get("hook_type", ""),
                r.get("api_name", ""),
                r.get("timestamp", ""),
                json.dumps(r.get("args", {}), ensure_ascii=False),
            ]
        )
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="hook_records_{ts}.csv"'},
    )


@router.get("/artifacts/{artifact_id}")
async def download_hook_artifact(artifact_id: str):
    """下载 Hook 侧落盘的原始 buffer。"""
    from fastapi.responses import FileResponse
    from backend.app.services.hook_artifacts import HookArtifactStore

    store = HookArtifactStore()
    try:
        path = store.resolve_artifact_path(artifact_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="无效的artifact_id")

    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail="文件不存在")

    return FileResponse(path=str(path), filename=path.name, media_type="application/octet-stream")
