"""数据迁移API端点

提供将现有requests.json数据迁移到session级别存储的API接口
"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from ...database import HybridStorage
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/migrate-to-session-storage")
async def migrate_requests_to_session_storage():
    """
    将现有的requests.json数据迁移到各个session目录
    
    Returns:
        dict: 迁移结果报告
    """
    try:
        logger.info("开始执行数据迁移：从全局requests.json到session级别存储")
        
        # 执行迁移
        result = HybridStorage.migrate_requests_to_sessions()
        
        logger.info(f"数据迁移完成: {result}")
        
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "message": result,
                "migration_type": "requests_to_sessions"
            }
        )
        
    except Exception as e:
        logger.error(f"数据迁移失败: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"数据迁移失败: {str(e)}"
        )

@router.get("/migration-status")
async def get_migration_status():
    """
    获取数据迁移状态
    
    Returns:
        dict: 当前存储状态信息
    """
    try:
        # 检查全局requests.json
        global_requests_file = HybridStorage.get_requests_json_path()
        global_requests = HybridStorage.load_json_data(global_requests_file)
        global_count = len(global_requests) if global_requests else 0
        
        # 检查sessions.json
        sessions_file = HybridStorage.get_sessions_json_path()
        sessions = HybridStorage.load_json_data(sessions_file)
        sessions_list = sessions if isinstance(sessions, list) else []
        
        # 检查每个session的requests数量
        session_storage_info = []
        total_session_requests = 0
        
        for session in sessions_list:
            session_id = session.get('session_id')
            if session_id:
                session_requests = HybridStorage.load_session_requests(session_id)
                request_count = len(session_requests) if session_requests else 0
                total_session_requests += request_count
                
                session_storage_info.append({
                    "session_id": session_id,
                    "session_name": session.get('session_name', 'Unknown'),
                    "request_count": request_count,
                    "status": session.get('status', 'unknown'),
                    "created_at": session.get('created_at', 'unknown')
                })
        
        return {
            "global_storage": {
                "requests_file_exists": bool(global_requests),
                "total_requests": global_count
            },
            "session_storage": {
                "total_sessions": len(sessions_list),
                "total_requests_in_sessions": total_session_requests,
                "sessions": session_storage_info
            },
            "migration_needed": global_count > 0,
            "storage_type": "hybrid" if global_count > 0 and total_session_requests > 0 else 
                           "global_only" if global_count > 0 else 
                           "session_only" if total_session_requests > 0 else "empty"
        }
        
    except Exception as e:
        logger.error(f"获取迁移状态失败: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"获取迁移状态失败: {str(e)}"
        )
