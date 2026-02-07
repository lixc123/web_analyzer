"""Native Hook 数据库模型（SQLAlchemy）。

用于持久化：
- HookSession：一次 attach/inject 的生命周期
- HookRecord：Frida send() 上来的事件记录
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, String, Integer, DateTime, Text, Index

from backend.app.database import Base


class HookSessionModel(Base):
    __tablename__ = "hook_sessions"

    session_id = Column(String, primary_key=True)
    process_name = Column(String, nullable=False)
    pid = Column(Integer, nullable=False)
    script_name = Column(String, nullable=False, default="")
    started_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    ended_at = Column(DateTime, nullable=True)
    status = Column(String, nullable=False, default="active")  # active/stopped/error
    record_count = Column(Integer, nullable=False, default=0)


class HookRecordModel(Base):
    __tablename__ = "hook_records"

    hook_id = Column(String, primary_key=True)
    session_id = Column(String, nullable=False, index=True)
    process_name = Column(String, nullable=False)
    pid = Column(Integer, nullable=False)
    hook_type = Column(String, nullable=False, index=True)
    api_name = Column(String, nullable=False, index=True)
    args_json = Column(Text, nullable=False, default="{}")
    return_value_json = Column(Text, nullable=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    stack_trace = Column(Text, nullable=True)
    thread_id = Column(Integer, nullable=True)


Index("idx_hook_records_session_time", HookRecordModel.session_id, HookRecordModel.timestamp)

