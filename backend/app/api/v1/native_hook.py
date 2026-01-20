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
hook_sessions: Dict[str, HookSession] = {}
hook_records: List[HookRecord] = []


class AttachRequest(BaseModel):
    """附加请求"""
    process_name: Optional[str] = None
    pid: Optional[int] = None


class InjectScriptRequest(BaseModel):
    """注入脚本请求"""
    script_code: Optional[str] = None
    template_name: Optional[str] = None


@router.get("/status")
async def get_hook_status():
    """获取Hook状态"""
    try:
        frida_installed = check_frida_installed()
        frida_version = get_frida_version()

        return {
            "frida_installed": frida_installed,
            "frida_version": frida_version,
            "active_sessions": len([s for s in hook_sessions.values() if s.status == "active"]),
            "total_records": len(hook_records)
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
        hook_sessions[session_id] = session

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
        if session_id in hook_sessions:
            hook_sessions[session_id].status = "stopped"
            hook_sessions[session_id].ended_at = datetime.now()

        # 删除Hook实例
        del hook_instances[session_id]

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

            script_code = template.load_script()
        else:
            raise HTTPException(status_code=400, detail="必须提供script_code或template_name")

        # 定义消息处理器
        def message_handler(payload: Dict[str, Any], data: Optional[bytes]):
            try:
                # 创建Hook记录
                record = HookRecord(
                    hook_id=str(uuid.uuid4()),
                    process_name=hook_sessions[session_id].process_name,
                    pid=hook_sessions[session_id].pid,
                    hook_type=payload.get('type', 'unknown'),
                    api_name=payload.get('api', 'unknown'),
                    args=payload,
                    timestamp=datetime.now()
                )
                hook_records.append(record)

                # 更新会话记录数
                hook_sessions[session_id].record_count += 1

                logger.info(f"收到Hook记录: {record.api_name}")
            except Exception as e:
                logger.error(f"处理Hook消息失败: {e}")

        # 注入脚本
        hook.inject_script(script_code, message_handler)

        # 更新会话
        hook_sessions[session_id].script_name = request.template_name or "custom"

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
            "script_code": template.load_script()
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
    limit: int = 100,
    offset: int = 0
):
    """获取Hook记录"""
    try:
        # 过滤记录
        filtered_records = hook_records

        if session_id:
            filtered_records = [r for r in filtered_records if r.process_name == hook_sessions.get(session_id, {}).process_name]

        if hook_type:
            filtered_records = [r for r in filtered_records if r.hook_type == hook_type]

        # 分页
        total = len(filtered_records)
        paginated_records = filtered_records[offset:offset + limit]

        return {
            "records": [r.model_dump() for r in paginated_records],
            "total": total,
            "limit": limit,
            "offset": offset
        }

    except Exception as e:
        logger.error(f"获取Hook记录失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/records")
async def clear_hook_records():
    """清空Hook记录"""
    try:
        global hook_records
        count = len(hook_records)
        hook_records = []

        return {"message": f"已清空{count}条记录"}

    except Exception as e:
        logger.error(f"清空记录失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions")
async def list_sessions():
    """列出所有Hook会话"""
    try:
        sessions = [s.model_dump() for s in hook_sessions.values()]
        return {"sessions": sessions, "count": len(sessions)}

    except Exception as e:
        logger.error(f"列出会话失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions/{session_id}")
async def get_session(session_id: str):
    """获取会话详情"""
    try:
        if session_id not in hook_sessions:
            raise HTTPException(status_code=404, detail="会话不存在")

        session = hook_sessions[session_id]
        return session.model_dump()

    except Exception as e:
        logger.error(f"获取会话失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))
