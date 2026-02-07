"""Proxy capture 存储占用统计与清理（artifacts/sessions）。"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.app.config import settings


def _safe_stat(path: Path) -> Optional[os.stat_result]:
    try:
        return path.stat()
    except Exception:
        return None


def _walk_files(base: Path) -> List[Path]:
    files: List[Path] = []
    if not base.exists():
        return files
    for root, _dirs, filenames in os.walk(base):
        for name in filenames:
            files.append(Path(root) / name)
    return files


def _dir_usage(base: Path) -> Dict[str, Any]:
    total = 0
    count = 0
    oldest = None
    newest = None
    for f in _walk_files(base):
        st = _safe_stat(f)
        if not st:
            continue
        count += 1
        total += int(st.st_size)
        mtime = float(st.st_mtime)
        oldest = mtime if oldest is None else min(oldest, mtime)
        newest = mtime if newest is None else max(newest, mtime)
    return {
        "path": str(base),
        "file_count": count,
        "total_bytes": total,
        "oldest_mtime": oldest,
        "newest_mtime": newest,
    }


def get_storage_status() -> Dict[str, Any]:
    artifacts_dir = Path(settings.proxy_artifacts_dir).resolve()
    sessions_dir = (Path(settings.data_dir) / "sessions").resolve()

    artifacts_usage = _dir_usage(artifacts_dir)

    # sessions: per-session usage (proxy_capture only)
    sessions: List[Dict[str, Any]] = []
    if sessions_dir.exists():
        for d in sessions_dir.iterdir():
            if not d.is_dir():
                continue
            meta_path = d / "proxy_meta.json"
            if not meta_path.exists():
                continue
            meta = None
            try:
                import json

                meta = json.loads(meta_path.read_text(encoding="utf-8") or "{}")
            except Exception:
                meta = None
            if not isinstance(meta, dict) or meta.get("kind") != "proxy_capture":
                continue
            usage = _dir_usage(d)
            sessions.append(
                {
                    "session_id": str(meta.get("session_id") or d.name),
                    "status": meta.get("status"),
                    "started_at": meta.get("started_at"),
                    "ended_at": meta.get("ended_at"),
                    "request_count": meta.get("request_count"),
                    "ws_message_count": meta.get("ws_message_count"),
                    "artifact_count": meta.get("artifact_count"),
                    "notes": meta.get("notes") or "",
                    "usage": usage,
                }
            )

    sessions.sort(key=lambda s: str(s.get("started_at") or ""), reverse=True)

    sessions_total_bytes = sum(int(s.get("usage", {}).get("total_bytes", 0) or 0) for s in sessions)

    return {
        "artifacts": {
            **artifacts_usage,
            "policy": {
                "max_total_mb": int(settings.proxy_artifacts_max_total_mb),
                "max_age_days": int(settings.proxy_artifacts_max_age_days),
            },
        },
        "sessions": {
            "path": str(sessions_dir),
            "count": len(sessions),
            "total_bytes": sessions_total_bytes,
            "policy": {"max_age_days": int(settings.proxy_sessions_max_age_days)},
            "items": sessions,
        },
    }


def plan_artifacts_cleanup(*, max_total_mb: int = 0, max_age_days: int = 0) -> Dict[str, Any]:
    """计算 artifacts 清理计划（不执行删除）。"""
    artifacts_dir = Path(settings.proxy_artifacts_dir).resolve()
    now = time.time()

    max_total_bytes = int(max_total_mb) * 1024 * 1024 if int(max_total_mb) > 0 else 0
    max_age_seconds = int(max_age_days) * 86400 if int(max_age_days) > 0 else 0

    files: List[Tuple[Path, int, float]] = []  # path,size,mtime
    total_bytes = 0
    for f in _walk_files(artifacts_dir):
        if not f.is_file():
            continue
        st = _safe_stat(f)
        if not st:
            continue
        size = int(st.st_size)
        mtime = float(st.st_mtime)
        total_bytes += size
        files.append((f, size, mtime))

    # oldest first for LRU/age
    files.sort(key=lambda x: x[2])

    to_delete: List[Dict[str, Any]] = []
    kept_bytes = total_bytes

    # age-based
    if max_age_seconds:
        cutoff = now - float(max_age_seconds)
        for f, size, mtime in files:
            if mtime <= cutoff:
                to_delete.append({"artifact_id": f.name, "path": str(f), "size": size, "mtime": mtime, "reason": "age"})
                kept_bytes -= size

    # size-based (LRU)
    if max_total_bytes and kept_bytes > max_total_bytes:
        for f, size, mtime in files:
            if any(item.get("path") == str(f) for item in to_delete):
                continue
            to_delete.append({"artifact_id": f.name, "path": str(f), "size": size, "mtime": mtime, "reason": "lru"})
            kept_bytes -= size
            if kept_bytes <= max_total_bytes:
                break

    return {
        "artifacts_dir": str(artifacts_dir),
        "before_total_bytes": total_bytes,
        "after_total_bytes": max(0, kept_bytes),
        "delete_count": len(to_delete),
        "delete_bytes": sum(int(i.get("size", 0) or 0) for i in to_delete),
        "files": to_delete,
    }


def apply_artifacts_cleanup(plan: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
    """执行 artifacts 清理计划。"""
    deleted: List[Dict[str, Any]] = []
    failed: List[Dict[str, Any]] = []
    for item in plan.get("files", []) or []:
        path = item.get("path")
        if not path:
            continue
        if dry_run:
            deleted.append({**item, "dry_run": True})
            continue
        try:
            p = Path(path)
            p.unlink(missing_ok=True)
            deleted.append({**item, "dry_run": False})
        except Exception as exc:
            failed.append({**item, "error": str(exc)})

    return {
        "dry_run": bool(dry_run),
        "deleted": deleted,
        "failed": failed,
        "deleted_count": len(deleted),
        "failed_count": len(failed),
    }


def plan_sessions_cleanup(max_age_days: int = 0) -> Dict[str, Any]:
    sessions_dir = (Path(settings.data_dir) / "sessions").resolve()
    now = time.time()
    max_age_seconds = int(max_age_days) * 86400 if int(max_age_days) > 0 else 0

    to_delete: List[Dict[str, Any]] = []
    if not max_age_seconds or not sessions_dir.exists():
        return {"sessions_dir": str(sessions_dir), "delete_count": 0, "items": []}

    cutoff = now - float(max_age_seconds)
    for d in sessions_dir.iterdir():
        if not d.is_dir():
            continue
        meta_path = d / "proxy_meta.json"
        if not meta_path.exists():
            continue
        try:
            import json

            meta = json.loads(meta_path.read_text(encoding="utf-8") or "{}")
        except Exception:
            continue
        started_at = str(meta.get("started_at") or "")
        # 优先使用 ended_at；否则使用目录 mtime 作为近似
        st = _safe_stat(d)
        mtime = float(st.st_mtime) if st else now
        if mtime <= cutoff:
            usage = _dir_usage(d)
            to_delete.append({"session_id": d.name, "path": str(d), "mtime": mtime, "usage": usage, "started_at": started_at})

    to_delete.sort(key=lambda x: x.get("mtime") or 0)
    return {"sessions_dir": str(sessions_dir), "delete_count": len(to_delete), "items": to_delete}

