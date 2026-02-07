"""Streaming/SSE response capture utilities (best-effort).

mitmproxy 对长连接（例如 SSE: text/event-stream）可能不会在短时间内触发完整 response 事件，
导致前端看到“响应体为空/无状态码”。这里通过 responseheaders + stream callback：
- 及时更新 status/headers
- 统计 chunk/bytes/duration
- 记录首包/尾包预览
- 可选捕获前 N 字节为 artifact（用于复盘）
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, Optional


def _now() -> float:
    return time.time()


def _as_text_preview(data: bytes) -> str:
    if not data:
        return ""
    return data.decode("utf-8", errors="replace")


def _as_hex_preview(data: bytes) -> str:
    if not data:
        return ""
    return data.hex()


@dataclass
class StreamingCaptureStats:
    content_type: str
    preview_bytes: int
    capture_max_bytes: int
    is_text: bool = True

    started_at: float = 0.0
    first_chunk_at: Optional[float] = None
    last_chunk_at: Optional[float] = None

    chunk_count: int = 0
    total_bytes: int = 0
    min_chunk_bytes: Optional[int] = None
    max_chunk_bytes: int = 0

    _first_bytes: bytes = b""
    _last_bytes: bytearray = None  # type: ignore[assignment]
    _captured: bytearray = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.preview_bytes = max(0, int(self.preview_bytes))
        self.capture_max_bytes = max(0, int(self.capture_max_bytes))
        self.started_at = _now()
        self._last_bytes = bytearray()
        self._captured = bytearray()

    def consume(self, chunk: bytes) -> None:
        if not chunk:
            return

        size = len(chunk)
        self.chunk_count += 1
        self.total_bytes += size
        self.max_chunk_bytes = max(self.max_chunk_bytes, size)
        self.min_chunk_bytes = size if self.min_chunk_bytes is None else min(self.min_chunk_bytes, size)

        ts = _now()
        if self.first_chunk_at is None:
            self.first_chunk_at = ts
            if self.preview_bytes > 0:
                self._first_bytes = bytes(chunk[: self.preview_bytes])

        self.last_chunk_at = ts

        if self.preview_bytes > 0:
            if size >= self.preview_bytes:
                self._last_bytes = bytearray(chunk[-self.preview_bytes :])
            else:
                self._last_bytes.extend(chunk)
                if len(self._last_bytes) > self.preview_bytes:
                    self._last_bytes = self._last_bytes[-self.preview_bytes :]

        if self.capture_max_bytes > 0 and len(self._captured) < self.capture_max_bytes:
            remaining = self.capture_max_bytes - len(self._captured)
            if remaining > 0:
                self._captured.extend(chunk[:remaining])

    def get_captured_bytes(self) -> bytes:
        return bytes(self._captured or b"")

    def summary(self, *, state: str = "open") -> Dict[str, Any]:
        end_ts = self.last_chunk_at or _now()
        start_ts = self.first_chunk_at or self.started_at or end_ts
        duration_ms = max(0, int((end_ts - start_ts) * 1000))
        avg = int(self.total_bytes / self.chunk_count) if self.chunk_count else 0

        first_preview = _as_text_preview(self._first_bytes) if self.is_text else _as_hex_preview(self._first_bytes)
        last_preview = _as_text_preview(bytes(self._last_bytes)) if self.is_text else _as_hex_preview(bytes(self._last_bytes))

        return {
            "state": str(state),
            "content_type": str(self.content_type or ""),
            "is_text": bool(self.is_text),
            "chunk_count": int(self.chunk_count),
            "total_bytes": int(self.total_bytes),
            "min_chunk_bytes": int(self.min_chunk_bytes) if self.min_chunk_bytes is not None else None,
            "max_chunk_bytes": int(self.max_chunk_bytes),
            "avg_chunk_bytes": int(avg),
            "duration_ms": int(duration_ms),
            "first_chunk_at": float(self.first_chunk_at) if self.first_chunk_at is not None else None,
            "last_chunk_at": float(self.last_chunk_at) if self.last_chunk_at is not None else None,
            "first_preview": first_preview,
            "last_preview": last_preview,
            "captured_bytes": int(len(self._captured or b"")),
            "capture_max_bytes": int(self.capture_max_bytes),
        }

