"""
会话服务 - 处理会话管理和统计
"""

import uuid
import json
import time
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)

@dataclass
class SessionStats:
    session_id: str
    messages: int = 0
    tokens: int = 0
    requests: int = 0
    created_at: datetime = None
    last_activity: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.last_activity is None:
            self.last_activity = datetime.now()

class SessionService:
    def __init__(self):
        self._sessions: Dict[str, SessionStats] = {}
        self._session_history: Dict[str, List[Dict[str, Any]]] = {}
    
    def create_session(self, session_id: Optional[str] = None) -> str:
        """创建新会话"""
        if not session_id:
            session_id = str(uuid.uuid4())
        
        self._sessions[session_id] = SessionStats(session_id=session_id)
        self._session_history[session_id] = []
        
        logger.info(f"创建会话: {session_id}")
        return session_id
    
    def get_session_stats(self, session_id: str) -> Optional[SessionStats]:
        """获取会话统计"""
        return self._sessions.get(session_id)
    
    def update_session_activity(self, session_id: str, activity_type: str, data: Dict[str, Any] = None):
        """更新会话活动"""
        if session_id not in self._sessions:
            self.create_session(session_id)
        
        session_stats = self._sessions[session_id]
        session_stats.last_activity = datetime.now()
        
        # 更新统计
        if activity_type == "message":
            session_stats.messages += 1
        elif activity_type == "tokens":
            session_stats.tokens += data.get("count", 0) if data else 0
        elif activity_type == "request":
            session_stats.requests += 1
        
        # 记录历史
        history_entry = {
            "timestamp": datetime.now().isoformat(),
            "type": activity_type,
            "data": data or {}
        }
        self._session_history[session_id].append(history_entry)
    
    def get_session_history(self, session_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """获取会话历史"""
        history = self._session_history.get(session_id, [])
        return history[-limit:] if limit > 0 else history
    
    def clear_session_history(self, session_id: str) -> int:
        """清除会话历史"""
        if session_id in self._session_history:
            count = len(self._session_history[session_id])
            self._session_history[session_id] = []
            
            # 重置统计
            if session_id in self._sessions:
                self._sessions[session_id].messages = 0
                self._sessions[session_id].tokens = 0
                self._sessions[session_id].requests = 0
            
            logger.info(f"清除会话历史: {session_id}, 清除了 {count} 条记录")
            return count
        return 0
    
    async def compress_session_history(self, session_id: str, compression_ratio: float = 0.5) -> Dict[str, Any]:
        """压缩会话历史"""
        if session_id not in self._session_history:
            return {"success": False, "message": "会话不存在"}
        
        history = self._session_history[session_id]
        original_count = len(history)
        
        if original_count < 10:  # 少于10条记录不压缩
            return {
                "success": False, 
                "message": "历史记录太少，无需压缩",
                "original_count": original_count
            }
        
        # 简单的压缩策略：保留最新的记录
        keep_count = max(5, int(original_count * compression_ratio))
        compressed_history = history[-keep_count:]
        
        # 创建压缩摘要
        compressed_summary = {
            "compressed_at": datetime.now().isoformat(),
            "original_count": original_count,
            "compressed_count": len(compressed_history),
            "compression_ratio": len(compressed_history) / original_count,
            "period": {
                "start": history[0]["timestamp"] if history else None,
                "end": history[-keep_count-1]["timestamp"] if len(history) > keep_count else None
            }
        }
        
        # 更新历史记录
        self._session_history[session_id] = [
            {
                "timestamp": datetime.now().isoformat(),
                "type": "compression",
                "data": compressed_summary
            }
        ] + compressed_history
        
        # 更新token统计（估算压缩后的token数）
        if session_id in self._sessions:
            old_tokens = self._sessions[session_id].tokens
            new_tokens = int(old_tokens * compression_ratio)
            self._sessions[session_id].tokens = new_tokens
        
        logger.info(f"压缩会话历史: {session_id}, {original_count} -> {len(compressed_history)}")
        
        return {
            "success": True,
            "message": f"会话历史已压缩：{original_count} -> {len(compressed_history)} 条记录",
            **compressed_summary
        }
    
    def get_all_sessions(self) -> List[Dict[str, Any]]:
        """获取所有会话信息"""
        sessions = []
        for session_id, stats in self._sessions.items():
            sessions.append({
                "session_id": session_id,
                "stats": asdict(stats),
                "history_count": len(self._session_history.get(session_id, []))
            })
        return sessions
    
    def delete_session(self, session_id: str) -> bool:
        """删除会话"""
        deleted = False
        
        if session_id in self._sessions:
            del self._sessions[session_id]
            deleted = True
        
        if session_id in self._session_history:
            del self._session_history[session_id]
            deleted = True
        
        if deleted:
            logger.info(f"删除会话: {session_id}")
        
        return deleted
    
    def cleanup_expired_sessions(self, max_age_hours: int = 24):
        """清理过期会话"""
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        expired_sessions = []
        
        for session_id, stats in list(self._sessions.items()):
            if stats.last_activity < cutoff_time:
                expired_sessions.append(session_id)
                self.delete_session(session_id)
        
        if expired_sessions:
            logger.info(f"清理过期会话: {len(expired_sessions)} 个")
        
        return expired_sessions
    
    def get_session_summary(self, session_id: str) -> Optional[Dict[str, Any]]:
        """获取会话摘要"""
        if session_id not in self._sessions:
            return None
        
        stats = self._sessions[session_id]
        history = self._session_history.get(session_id, [])
        
        # 分析活动模式
        activity_types = {}
        for entry in history:
            activity_type = entry["type"]
            activity_types[activity_type] = activity_types.get(activity_type, 0) + 1
        
        return {
            "session_id": session_id,
            "stats": asdict(stats),
            "activity_summary": activity_types,
            "duration_minutes": (stats.last_activity - stats.created_at).total_seconds() / 60,
            "activity_rate": len(history) / max(1, (stats.last_activity - stats.created_at).total_seconds() / 3600),  # 每小时活动次数
            "last_activities": history[-5:] if history else []  # 最近5次活动
        }
