from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, WebSocket
from fastapi.responses import FileResponse
from pathlib import Path
import os
import tempfile
import zipfile
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
import asyncio
import logging

from ...database import get_db
from ...services.shared_recorder import get_recorder_service
from ...services.cache_service import CacheService
from ...config import settings

logger = logging.getLogger(__name__)
router = APIRouter()

# Pydantic models for request/response
class HookOptions(BaseModel):
    """JS Hook 功能选项"""
    network: bool = True           # 网络请求拦截 (fetch/XHR)
    storage: bool = False          # 存储拦截 (localStorage/sessionStorage/IndexedDB)
    userInteraction: bool = False  # 用户交互跟踪 (click/input等)
    form: bool = False             # 表单数据跟踪
    dom: bool = False              # DOM变化监控
    navigation: bool = False       # 导航历史跟踪
    console: bool = False          # Console日志拦截
    performance: bool = False      # 性能数据监控
    websocket: bool = False        # WebSocket 拦截
    crypto: bool = False           # Web Crypto API 拦截（定位加密/签名）
    storageExport: bool = False    # 存储数据完整导出（local/session/cookies/indexedDB）
    stateManagement: bool = False  # 状态管理（Redux/Vuex/Pinia）快照/变更

class CrawlerConfig(BaseModel):
    url: str
    max_depth: int = 3
    follow_redirects: bool = True
    capture_screenshots: bool = False
    headless: bool = False
    user_agent: Optional[str] = None
    timeout: int = 30
    manual_recording: bool = False  # 手动控制录制模式：先打开浏览器，用户手动开始/停止录制
    hook_options: HookOptions = HookOptions()  # JS Hook 功能选项，默认只开启网络请求
    use_system_chrome: bool = False  # 使用系统安装的 Chrome 而非 Playwright 内置 Chromium
    chrome_path: Optional[str] = None  # 自定义 Chrome 路径
    
class CrawlerStartRequest(BaseModel):
    config: CrawlerConfig
    session_name: Optional[str] = None

class CrawlerResponse(BaseModel):
    session_id: str
    status: str
    message: str
    config: CrawlerConfig

class CrawlerStatus(BaseModel):
    session_id: str
    status: str  # running, completed, failed, stopped
    progress: dict
    total_requests: int
    completed_requests: int
    errors: List[str]

@router.post("/start", response_model=CrawlerResponse)
async def start_crawler(
    request: CrawlerStartRequest,
    db: Session = Depends(get_db)
):
    """启动爬虫任务"""
    try:
        recorder_service = get_recorder_service()
        
        # 创建爬虫会话
        session_id = await recorder_service.create_session(
            url=request.config.url,
            session_name=request.session_name,
            config=request.config.dict()
        )
        
        # 检查是否为手动录制模式
        if request.config.manual_recording:
            # 手动模式：只打开浏览器，不自动开始录制
            async def _run_open_browser() -> None:
                try:
                    await recorder_service.open_browser_only(session_id)
                except Exception as e:
                    logger.error(f"后台打开浏览器失败 {session_id}: {e}")

            asyncio.create_task(_run_open_browser())
            
            return CrawlerResponse(
                session_id=session_id,
                status="browser_ready",
                message="浏览器已打开，请手动开始录制",
                config=request.config
            )
        else:
            # 自动模式：打开浏览器并立即开始录制
            async def _run_start_recording() -> None:
                try:
                    await recorder_service.start_recording(session_id)
                except Exception as e:
                    logger.error(f"后台启动录制失败 {session_id}: {e}")

            asyncio.create_task(_run_start_recording())
            
            return CrawlerResponse(
                session_id=session_id,
                status="starting",
                message="爬虫任务启动中",
                config=request.config
            )
        
    except Exception as e:
        logger.error(f"启动爬虫失败: {e}")
        raise HTTPException(status_code=500, detail=f"启动爬虫失败: {str(e)}")

@router.post("/stop/{session_id}")
async def stop_crawler(session_id: str, db: Session = Depends(get_db)):
    """停止爬虫任务"""
    try:
        recorder_service = get_recorder_service()
        await recorder_service.stop_recording_background(session_id)

        return {"session_id": session_id, "status": "stopping", "message": "停止请求已提交，正在收尾"}

    except Exception as e:
        logger.error(f"停止爬虫失败: {e}")
        raise HTTPException(status_code=500, detail=f"停止爬虫失败: {str(e)}")

@router.post("/stop-recording/{session_id}")
async def stop_recording_alias(session_id: str, db: Session = Depends(get_db)):
    """停止录制（别名路由，兼容前端）"""
    return await stop_crawler(session_id, db)


@router.post("/start-recording/{session_id}")
async def start_manual_recording(session_id: str, db: Session = Depends(get_db)):
    """手动开始录制（用于手动控制模式）"""
    try:
        recorder_service = get_recorder_service()
        await recorder_service.start_manual_recording(session_id)
        
        return {"session_id": session_id, "status": "running", "message": "录制已开始"}
        
    except Exception as e:
        logger.error(f"手动开始录制失败: {e}")
        raise HTTPException(status_code=500, detail=f"手动开始录制失败: {str(e)}")

@router.get("/status/{session_id}", response_model=CrawlerStatus)
async def get_crawler_status(session_id: str, db: Session = Depends(get_db)):
    """获取爬虫状态"""
    try:
        recorder_service = get_recorder_service()
        status = await recorder_service.get_session_status(session_id)
        
        return CrawlerStatus(
            session_id=session_id,
            status=status.get("status", "unknown"),
            progress=status.get("progress", {}),
            total_requests=status.get("total_requests", 0),
            completed_requests=status.get("completed_requests", 0),
            errors=status.get("errors", [])
        )
        
    except Exception as e:
        logger.error(f"获取爬虫状态失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取爬虫状态失败: {str(e)}")

@router.get("/sessions")
async def list_crawler_sessions(db: Session = Depends(get_db)):
    """列出所有爬虫会话"""
    try:
        recorder_service = get_recorder_service()
        sessions = await recorder_service.list_sessions()
        
        return {"sessions": sessions}
        
    except Exception as e:
        logger.error(f"获取会话列表失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取会话列表失败: {str(e)}")

@router.get("/requests/{session_id}")
async def get_session_requests(
    session_id: str,
    offset: int = 0,
    limit: int = 100,
    q: Optional[str] = None,
    resource_type: Optional[str] = None,
    method: Optional[str] = None,
    status: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """获取会话的请求记录"""
    try:
        recorder_service = get_recorder_service()
        page_data = await recorder_service.get_session_requests_page(
            session_id,
            offset=offset,
            limit=limit,
            q=q,
            resource_type=resource_type,
            method=method,
            status=status,
        )
        return page_data

    except Exception as e:
        logger.error(f"获取会话请求失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取会话请求失败: {str(e)}")

@router.get("/session/{session_id}/requests")
async def get_session_requests_alias(
    session_id: str,
    offset: int = 0,
    limit: int = 100,
    q: Optional[str] = None,
    resource_type: Optional[str] = None,
    method: Optional[str] = None,
    status: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """获取会话的请求记录（别名路由，兼容前端）"""
    return await get_session_requests(session_id, offset, limit, q, resource_type, method, status, db)


@router.delete("/requests/{session_id}")
async def clear_session_requests(session_id: str, db: Session = Depends(get_db)):
    """清空会话的请求记录"""
    try:
        recorder_service = get_recorder_service()
        return await recorder_service.clear_session_requests(session_id)
    except Exception as e:
        logger.error(f"清空会话请求失败: {e}")
        raise HTTPException(status_code=500, detail=f"清空会话请求失败: {str(e)}")

@router.delete("/session/{session_id}")
async def delete_crawler_session(session_id: str, db: Session = Depends(get_db)):
    """删除爬虫会话"""
    try:
        recorder_service = get_recorder_service()
        await recorder_service.delete_session(session_id)
        
        return {"session_id": session_id, "status": "deleted", "message": "会话已删除"}
        
    except Exception as e:
        logger.error(f"删除会话失败: {e}")
        raise HTTPException(status_code=500, detail=f"删除会话失败: {str(e)}")

@router.post("/export/{session_id}")
async def export_session_data(
    session_id: str,
    body: Optional[Dict[str, Any]] = None,
    format: str = "json",  # json, csv, har (query参数，兼容旧版)
    db: Session = Depends(get_db)
):
    """导出会话数据（支持body和query两种方式传递format）"""
    try:
        recorder_service = get_recorder_service()

        # 优先从body中获取format，如果没有则使用query参数
        if body and 'format' in body:
            format = body['format']

        if format not in ["json", "csv", "har"]:
            raise HTTPException(status_code=400, detail="支持的格式: json, csv, har")

        export_data = await recorder_service.export_session(session_id, format)

        return {
            "session_id": session_id,
            "format": format,
            "data": export_data,
            "message": "数据导出成功"
        }
        
    except Exception as e:
        logger.error(f"导出会话数据失败: {e}")
        raise HTTPException(status_code=500, detail=f"导出会话数据失败: {str(e)}")


@router.get("/download/{session_id}")
async def download_session_folder(
    session_id: str,
    background_tasks: BackgroundTasks,
):
    """下载整个会话目录（zip 打包）"""
    safe_session_id = Path(session_id).name
    if safe_session_id != session_id or any(sep in session_id for sep in ("/", "\\")):
        raise HTTPException(status_code=400, detail="非法的 session_id")

    # 先尝试直接匹配
    session_dir = Path(settings.data_dir) / "sessions" / safe_session_id
    actual_folder_name = safe_session_id
    
    # 如果直接匹配失败，尝试在sessions目录中查找对应的文件夹
    if not session_dir.exists() or not session_dir.is_dir():
        sessions_base_dir = Path(settings.data_dir) / "sessions"
        if not sessions_base_dir.exists():
            raise HTTPException(status_code=404, detail="sessions目录不存在")
            
        # 获取recorder_service来查找session映射
        try:
            recorder_service = get_recorder_service()
            sessions = await recorder_service.list_sessions()
            
            # 查找对应的session数据来获取真实的目录名
            target_session = None
            for s in sessions:
                if s.get("session_id") == session_id:
                    target_session = s
                    break
            
            if target_session:
                # 如果session是时间戳格式，使用该格式查找目录
                session_name = target_session.get("session_name", "")
                if session_name.startswith("session_") and len(session_name) > 8:
                    potential_dir = sessions_base_dir / session_name
                    if potential_dir.exists() and potential_dir.is_dir():
                        session_dir = potential_dir
                        actual_folder_name = session_name
                    else:
                        # 尝试直接在sessions目录中查找匹配的文件夹
                        for item in sessions_base_dir.iterdir():
                            if item.is_dir() and (item.name.startswith(f"session_") or session_id in item.name):
                                session_dir = item
                                actual_folder_name = item.name
                                break
            
        except Exception as e:
            logger.warning(f"查找session目录时出错: {e}")
            
        # 最后检查是否找到了有效目录
        if not session_dir.exists() or not session_dir.is_dir():
            raise HTTPException(status_code=404, detail=f"会话目录不存在: {session_id}")

    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=f"_{safe_session_id}.zip")
    tmp_file_path = Path(tmp_file.name)
    tmp_file.close()

    try:
        with zipfile.ZipFile(tmp_file_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(session_dir):
                root_path = Path(root)
                rel_root = root_path.relative_to(session_dir)

                if not files and not dirs:
                    zf.writestr(f"{actual_folder_name}/{rel_root.as_posix()}/", "")

                for file_name in files:
                    file_path = root_path / file_name
                    rel_file = file_path.relative_to(session_dir)
                    zf.write(file_path, arcname=f"{actual_folder_name}/{rel_file.as_posix()}")

        background_tasks.add_task(lambda p: os.path.exists(p) and os.remove(p), str(tmp_file_path))
        return FileResponse(
            path=str(tmp_file_path),
            media_type="application/zip",
            filename=f"{safe_session_id}.zip",
        )
    except HTTPException:
        raise
    except Exception as e:
        try:
            if tmp_file_path.exists():
                tmp_file_path.unlink()
        except Exception:
            pass
        logger.error(f"打包会话目录失败: {e}")
        raise HTTPException(status_code=500, detail=f"打包会话目录失败: {str(e)}")

@router.websocket("/progress/{session_id}")
async def crawler_progress_websocket(websocket: WebSocket, session_id: str):
    """WebSocket进度推送"""
    await websocket.accept()
    
    try:
        recorder_service = get_recorder_service()
        
        # 持续推送进度更新
        while True:
            status = await recorder_service.get_session_status(session_id)
            await websocket.send_json({
                "type": "progress_update",
                "session_id": session_id,
                "data": status
            })
            
            # 如果任务完成或失败，停止推送
            if status.get("status") in ["completed", "failed", "stopped"]:
                break
                
            await asyncio.sleep(1)  # 每秒更新一次
            
    except Exception as e:
        logger.error(f"WebSocket进度推送错误: {e}")
        await websocket.send_json({
            "type": "error",
            "message": str(e)
        })
    finally:
        await websocket.close()
