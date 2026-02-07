"""WebSocket 代理事件广播器"""
from typing import Set
from fastapi import WebSocket
import json
import asyncio


class ProxyEventBroadcaster:
    """WebSocket 事件广播器"""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        """接受新的 WebSocket 连接"""
        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)

    async def disconnect(self, websocket: WebSocket):
        """断开 WebSocket 连接"""
        async with self._lock:
            self.active_connections.discard(websocket)

    async def broadcast_request(self, request_data: dict):
        """广播请求事件到所有客户端"""
        message = {
            "type": "new_request",
            "data": request_data
        }
        await self._broadcast(message)

    async def broadcast_response(self, response_data: dict):
        """广播响应事件到所有客户端"""
        message = {
            "type": "new_response",
            "data": response_data
        }
        await self._broadcast(message)

    async def broadcast_status(self, status_data: dict):
        """广播代理状态变化到所有客户端"""
        message = {
            "type": "proxy_status",
            "data": status_data
        }
        await self._broadcast(message)

    async def broadcast_websocket_event(self, ws_event: dict):
        """广播 WebSocket 事件（连接/消息/关闭）到所有客户端"""
        message = {
            "type": "websocket_event",
            "data": ws_event,
        }
        await self._broadcast(message)

    async def broadcast_js_event(self, js_event: dict):
        """广播 JS 注入事件（fetch/xhr/ws 调用栈等）到所有客户端"""
        message = {
            "type": "js_event",
            "data": js_event,
        }
        await self._broadcast(message)

    async def _broadcast(self, message: dict):
        """内部广播方法"""
        import logging
        logger = logging.getLogger(__name__)

        # 在锁保护下复制连接列表
        async with self._lock:
            connections = self.active_connections.copy()

        # 在锁外发送消息，避免阻塞
        disconnected = set()
        for connection in connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning(f"WebSocket发送失败: {e}")
                disconnected.add(connection)
                # 尝试关闭连接
                try:
                    await connection.close()
                except Exception:
                    pass

        # 再次获取锁清理断开的连接
        if disconnected:
            async with self._lock:
                for connection in disconnected:
                    self.active_connections.discard(connection)


# 全局广播器实例
broadcaster = ProxyEventBroadcaster()
