from fastapi import APIRouter, Depends, HTTPException, WebSocket
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
import asyncio
import logging

from ...database import get_db
from ...services.shared_recorder import get_recorder_service
from ...services.cache_service import CacheService

logger = logging.getLogger(__name__)
router = APIRouter()

# Pydantic models for request/response
class CrawlerConfig(BaseModel):
    url: str
    max_depth: int = 3
    follow_redirects: bool = True
    capture_screenshots: bool = False
    headless: bool = False
    user_agent: Optional[str] = None
    timeout: int = 30
    
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
        await recorder_service.stop_recording(session_id)
        
        return {"session_id": session_id, "status": "stopped", "message": "爬虫任务已停止"}
        
    except Exception as e:
        logger.error(f"停止爬虫失败: {e}")
        raise HTTPException(status_code=500, detail=f"停止爬虫失败: {str(e)}")

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
    format: str = "json",  # json, csv, har
    db: Session = Depends(get_db)
):
    """导出会话数据"""
    try:
        recorder_service = get_recorder_service()
        
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
