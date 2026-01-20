from typing import Dict, List
from fastapi import WebSocket
import json
import logging

logger = logging.getLogger(__name__)

class ConnectionManager:
    """WebSocket连接管理器"""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        
    async def connect(self, websocket: WebSocket, client_id: str):
        """接受WebSocket连接"""
        await websocket.accept()
        self.active_connections[client_id] = websocket
        logger.info(f"客户端 {client_id} 已连接")
        
    def disconnect(self, client_id: str):
        """断开WebSocket连接"""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
            logger.info(f"客户端 {client_id} 已断开")
    
    async def send_personal_message(self, message: str, client_id: str):
        """发送个人消息"""
        if client_id in self.active_connections:
            websocket = self.active_connections[client_id]
            try:
                await websocket.send_text(message)
            except Exception as e:
                logger.error(f"发送消息到客户端 {client_id} 失败: {e}")
                self.disconnect(client_id)
    
    async def send_json_message(self, data: dict, client_id: str):
        """发送JSON格式消息"""
        if client_id in self.active_connections:
            websocket = self.active_connections[client_id]
            try:
                await websocket.send_json(data)
            except Exception as e:
                logger.error(f"发送JSON消息到客户端 {client_id} 失败: {e}")
                self.disconnect(client_id)
    
    async def broadcast(self, message: str):
        """广播消息给所有连接的客户端"""
        disconnected_clients = []
        for client_id, websocket in list(self.active_connections.items()):
            try:
                await websocket.send_text(message)
            except Exception as e:
                logger.error(f"广播消息到客户端 {client_id} 失败: {e}")
                disconnected_clients.append(client_id)
        
        # 清理断开的连接
        for client_id in disconnected_clients:
            self.disconnect(client_id)
    
    async def broadcast_json(self, data: dict):
        """广播JSON消息给所有客户端"""
        disconnected_clients = []
        for client_id, websocket in list(self.active_connections.items()):
            try:
                await websocket.send_json(data)
            except Exception as e:
                logger.error(f"广播JSON消息到客户端 {client_id} 失败: {e}")
                disconnected_clients.append(client_id)
        
        # 清理断开的连接
        for client_id in disconnected_clients:
            self.disconnect(client_id)
    
    async def send_crawler_progress(self, progress_data: dict, client_id: str = None):
        """发送爬虫进度更新"""
        message = {
            "type": "crawler_progress",
            "data": progress_data,
            "timestamp": progress_data.get("timestamp")
        }
        
        if client_id:
            await self.send_json_message(message, client_id)
        else:
            await self.broadcast_json(message)
    
    async def send_analysis_result(self, analysis_data: dict, client_id: str = None):
        """发送分析结果"""
        message = {
            "type": "analysis_result", 
            "data": analysis_data,
            "timestamp": analysis_data.get("timestamp")
        }
        
        if client_id:
            await self.send_json_message(message, client_id)
        else:
            await self.broadcast_json(message)
    
    async def send_error(self, error_msg: str, client_id: str = None):
        """发送错误消息"""
        from datetime import datetime
        message = {
            "type": "error",
            "message": error_msg,
            "timestamp": datetime.now().isoformat()
        }
        
        if client_id:
            await self.send_json_message(message, client_id)
        else:
            await self.broadcast_json(message)
    
    def get_connected_clients(self) -> List[str]:
        """获取所有连接的客户端ID"""
        return list(self.active_connections.keys())
    
    def is_connected(self, client_id: str) -> bool:
        """检查客户端是否连接"""
        return client_id in self.active_connections


manager = ConnectionManager()
