"""Proxy Capture 会话/索引数据库模型（SQLAlchemy）。

用于：
- proxy_sessions: 记录每次代理抓包 start/stop 的会话元信息（便于列表与备注）
- proxy_request_index: request_id -> session_id 的快速定位（用于跨重启查看详情/联动）
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, String, Integer, DateTime, Text, Index

from backend.app.database import Base


class ProxySessionModel(Base):
    __tablename__ = "proxy_sessions"

    session_id = Column(String, primary_key=True)
    status = Column(String, nullable=False, default="active")  # active/stopped/error
    host = Column(String, nullable=False, default="0.0.0.0")
    port = Column(Integer, nullable=False, default=0)
    started_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    ended_at = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=False, default="")
    request_count = Column(Integer, nullable=False, default=0)
    ws_message_count = Column(Integer, nullable=False, default=0)
    artifact_count = Column(Integer, nullable=False, default=0)


class ProxyRequestIndexModel(Base):
    __tablename__ = "proxy_request_index"

    request_id = Column(String, primary_key=True)
    session_id = Column(String, nullable=False, index=True)
    method = Column(String, nullable=False, default="")
    url = Column(Text, nullable=False, default="")
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)


Index("idx_proxy_request_session_time", ProxyRequestIndexModel.session_id, ProxyRequestIndexModel.timestamp)

