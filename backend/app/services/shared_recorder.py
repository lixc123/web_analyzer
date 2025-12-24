"""
共享的RecorderService实例 - 确保所有API调用使用同一个服务实例
"""
import logging
from .recorder_service import RecorderService

logger = logging.getLogger(__name__)

# 全局共享的RecorderService实例
_shared_recorder_service = None

def get_recorder_service() -> RecorderService:
    """获取共享的RecorderService实例"""
    global _shared_recorder_service
    if _shared_recorder_service is None:
        logger.info("创建全局共享RecorderService实例")
        _shared_recorder_service = RecorderService()
        logger.info(f"共享RecorderService实例已创建: {id(_shared_recorder_service)}")
    else:
        logger.info(f"使用现有共享RecorderService实例: {id(_shared_recorder_service)}")
        logger.info(f"当前活动会话数: {len(_shared_recorder_service.active_sessions)}")
        logger.info(f"活动会话列表: {list(_shared_recorder_service.active_sessions.keys())}")
    
    return _shared_recorder_service
