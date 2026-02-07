"""Native Hook 存储服务（SQLite）。"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select, func, delete, update

from backend.app.database import SessionLocal
from backend.models.hook_db import HookSessionModel, HookRecordModel

logger = logging.getLogger(__name__)


def _truncate_strings(obj: Any, max_len: int = 4000) -> Any:
    if obj is None:
        return None
    if isinstance(obj, str):
        if len(obj) <= max_len:
            return obj
        return obj[:max_len] + "...[truncated]"
    if isinstance(obj, list):
        return [_truncate_strings(v, max_len=max_len) for v in obj[:200]]
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in list(obj.items())[:200]:
            out[str(k)] = _truncate_strings(v, max_len=max_len)
        return out
    return obj


class HookStorage:
    """Hook 会话与记录持久化（线程安全：每次操作独立 SessionLocal）。"""

    def create_session(self, session_id: str, process_name: str, pid: int) -> None:
        with SessionLocal() as db:
            model = HookSessionModel(
                session_id=session_id,
                process_name=process_name,
                pid=int(pid),
                script_name="",
                started_at=datetime.utcnow(),
                status="active",
                record_count=0,
            )
            db.add(model)
            db.commit()

    def update_session(
        self,
        session_id: str,
        *,
        script_name: Optional[str] = None,
        status: Optional[str] = None,
        ended_at: Optional[datetime] = None,
        record_count_delta: int = 0,
    ) -> None:
        values: Dict[str, Any] = {}
        if script_name is not None:
            values["script_name"] = script_name
        if status is not None:
            values["status"] = status
        if ended_at is not None:
            values["ended_at"] = ended_at
        if record_count_delta:
            values["record_count"] = HookSessionModel.record_count + int(record_count_delta)

        if not values:
            return

        with SessionLocal() as db:
            db.execute(update(HookSessionModel).where(HookSessionModel.session_id == session_id).values(**values))
            db.commit()

    def add_record(
        self,
        *,
        hook_id: str,
        session_id: str,
        process_name: str,
        pid: int,
        hook_type: str,
        api_name: str,
        args: Dict[str, Any],
        timestamp: Optional[datetime] = None,
        return_value: Any = None,
        stack_trace: Optional[str] = None,
        thread_id: Optional[int] = None,
    ) -> None:
        ts = timestamp or datetime.utcnow()
        safe_args = _truncate_strings(args, max_len=8000)
        args_json = json.dumps(safe_args, ensure_ascii=False, default=str)
        rv_json = json.dumps(_truncate_strings(return_value, max_len=8000), ensure_ascii=False, default=str) if return_value is not None else None

        with SessionLocal() as db:
            db.add(
                HookRecordModel(
                    hook_id=hook_id,
                    session_id=session_id,
                    process_name=process_name,
                    pid=int(pid),
                    hook_type=hook_type or "unknown",
                    api_name=api_name or "unknown",
                    args_json=args_json or "{}",
                    return_value_json=rv_json,
                    timestamp=ts,
                    stack_trace=_truncate_strings(stack_trace, max_len=12000) if stack_trace else None,
                    thread_id=thread_id,
                )
            )
            db.commit()

        # 记录数累计（单独 update，避免记录写入失败影响会话）
        try:
            self.update_session(session_id, record_count_delta=1)
        except Exception as exc:
            logger.debug("update record_count failed: %s", exc)

    def list_sessions(self, limit: int = 200, offset: int = 0) -> Tuple[List[Dict[str, Any]], int]:
        with SessionLocal() as db:
            total = db.scalar(select(func.count()).select_from(HookSessionModel)) or 0
            rows = db.execute(
                select(HookSessionModel)
                .order_by(HookSessionModel.started_at.desc())
                .limit(int(limit))
                .offset(int(offset))
            ).scalars().all()

        sessions = [
            {
                "session_id": r.session_id,
                "process_name": r.process_name,
                "pid": r.pid,
                "script_name": r.script_name,
                "started_at": r.started_at.isoformat(),
                "ended_at": r.ended_at.isoformat() if r.ended_at else None,
                "record_count": r.record_count,
                "status": r.status,
            }
            for r in rows
        ]
        return sessions, int(total)

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        with SessionLocal() as db:
            row = db.execute(select(HookSessionModel).where(HookSessionModel.session_id == session_id)).scalar_one_or_none()
        if not row:
            return None
        return {
            "session_id": row.session_id,
            "process_name": row.process_name,
            "pid": row.pid,
            "script_name": row.script_name,
            "started_at": row.started_at.isoformat(),
            "ended_at": row.ended_at.isoformat() if row.ended_at else None,
            "record_count": row.record_count,
            "status": row.status,
        }

    def list_records(
        self,
        *,
        session_id: Optional[str] = None,
        hook_type: Optional[str] = None,
        api_name: Optional[str] = None,
        correlated_request_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        where = []
        if session_id:
            where.append(HookRecordModel.session_id == session_id)
        if hook_type:
            where.append(HookRecordModel.hook_type == hook_type)
        if api_name:
            where.append(HookRecordModel.api_name == api_name)
        if correlated_request_id:
            # correlated_request_id 存在于 args_json（JSON 文本）中，这里做 best-effort LIKE 过滤
            where.append(HookRecordModel.args_json.like(f"%{correlated_request_id}%"))

        with SessionLocal() as db:
            count_stmt = select(func.count()).select_from(HookRecordModel)
            if where:
                for cond in where:
                    count_stmt = count_stmt.where(cond)
            total = db.scalar(count_stmt) or 0

            stmt = select(HookRecordModel).order_by(HookRecordModel.timestamp.desc()).limit(int(limit)).offset(int(offset))
            if where:
                for cond in where:
                    stmt = stmt.where(cond)
            rows = db.execute(stmt).scalars().all()

        records: List[Dict[str, Any]] = []
        for r in rows:
            try:
                args = json.loads(r.args_json) if r.args_json else {}
            except Exception:
                args = {}
            correlated_request_id = None
            try:
                correlated_request_id = args.get("_correlated_request_id")
            except Exception:
                correlated_request_id = None
            records.append(
                {
                    "hook_id": r.hook_id,
                    "session_id": r.session_id,
                    "process_name": r.process_name,
                    "pid": r.pid,
                    "hook_type": r.hook_type,
                    "api_name": r.api_name,
                    "args": args,
                    "return_value": r.return_value_json,
                    "timestamp": r.timestamp.isoformat(),
                    "stack_trace": r.stack_trace,
                    "thread_id": r.thread_id,
                    "correlated_request_id": correlated_request_id,
                }
            )

        return records, int(total)

    def clear_records(self, session_id: Optional[str] = None) -> int:
        with SessionLocal() as db:
            stmt = delete(HookRecordModel)
            if session_id:
                stmt = stmt.where(HookRecordModel.session_id == session_id)
            result = db.execute(stmt)
            db.commit()
            deleted = int(getattr(result, "rowcount", 0) or 0)
        return deleted

    def total_records(self) -> int:
        with SessionLocal() as db:
            return int(db.scalar(select(func.count()).select_from(HookRecordModel)) or 0)
