"""抓包数据落盘工具（请求/响应体、WebSocket 二进制等）。"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
import uuid

from backend.app.config import settings


_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _guess_extension(content_type: str, fallback: str = ".bin") -> str:
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    if not ct:
        return fallback
    if ct in {"application/json"}:
        return ".json"
    if ct in {"text/html"}:
        return ".html"
    if ct in {"text/plain"}:
        return ".txt"
    if ct in {"application/javascript", "text/javascript"}:
        return ".js"
    if ct in {"text/css"}:
        return ".css"
    if ct in {"application/xml", "text/xml"}:
        return ".xml"
    if ct.startswith("text/"):
        return ".txt"
    return fallback


def _is_probably_text(content: bytes) -> bool:
    if not content:
        return True
    try:
        content.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def maybe_decompress(content: bytes, content_encoding: str) -> bytes:
    """best-effort 解压 gzip/deflate/br。

    - 失败则返回原始 content
    - 仅用于展示/分析场景的“更可读”内容，不保证与线上的原始字节完全一致
    """
    if not content:
        return content
    enc = (content_encoding or "").split(",", 1)[0].strip().lower()
    if not enc:
        return content

    try:
        if enc == "gzip":
            import gzip

            return gzip.decompress(content)
        if enc == "deflate":
            import zlib

            # 有的服务端使用 zlib wrapper，有的使用 raw deflate，这里都尝试
            try:
                return zlib.decompress(content)
            except zlib.error:
                return zlib.decompress(content, -zlib.MAX_WBITS)
        if enc == "br":
            try:
                import brotli  # type: ignore

                return brotli.decompress(content)
            except Exception:
                return content
    except Exception:
        return content

    return content


def _hexdump_preview(data: bytes, limit: int) -> str:
    if not data:
        return ""
    chunk = data[: max(0, int(limit))]
    return chunk.hex()


@dataclass(frozen=True)
class StoredArtifact:
    artifact_id: str
    relative_path: str
    size: int
    sha256: str
    content_type: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "relative_path": self.relative_path,
            "size": self.size,
            "sha256": self.sha256,
            "content_type": self.content_type,
        }


class ProxyArtifactStore:
    """将抓包产物保存到 data/proxy_artifacts 下。

    文件名使用 UUID，避免用户输入参与路径拼接，降低路径穿越风险。
    """

    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = Path(base_dir or settings.proxy_artifacts_dir).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def store_bytes(self, content: bytes, *, content_type: str = "", prefix: str = "body") -> StoredArtifact:
        ext = _guess_extension(content_type)
        artifact_id = f"{prefix}_{uuid.uuid4().hex}{ext}"
        file_path = self.base_dir / artifact_id

        sha256 = hashlib.sha256(content).hexdigest()
        file_path.write_bytes(content)

        rel = str(file_path.relative_to(self.base_dir)).replace("\\", "/")
        return StoredArtifact(
            artifact_id=artifact_id,
            relative_path=rel,
            size=len(content),
            sha256=sha256,
            content_type=(content_type or "application/octet-stream"),
        )

    def resolve_artifact_path(self, artifact_id: str) -> Path:
        if not artifact_id or not _SAFE_ID_RE.match(artifact_id) or ".." in artifact_id or "/" in artifact_id or "\\" in artifact_id:
            raise ValueError("invalid_artifact_id")
        path = (self.base_dir / artifact_id).resolve()
        # 防止绕出 base_dir
        if self.base_dir not in path.parents and path != self.base_dir:
            raise ValueError("invalid_artifact_path")
        return path


def capture_body(
    *,
    content: Optional[bytes],
    content_type: str,
    inline_limit_chars: int,
    preview_bytes: int,
    store: ProxyArtifactStore,
    prefix: str,
) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """将 body 转为“可展示文本 + 可选落盘 artifact 信息”。"""
    if not content:
        return None, None

    is_text = _is_probably_text(content)
    if is_text:
        text = content.decode("utf-8", errors="replace")
        if len(text) <= inline_limit_chars:
            return text, None

        artifact = store.store_bytes(content, content_type=content_type, prefix=prefix)
        preview = text[:inline_limit_chars]
        return (
            preview + f"\n... [已截断，完整内容已落盘: {artifact.artifact_id}]",
            {
                **artifact.to_dict(),
                "is_binary": False,
                "truncated": True,
            },
        )

    # binary
    artifact = store.store_bytes(content, content_type=content_type, prefix=prefix)
    preview = _hexdump_preview(content, preview_bytes)
    return (
        f"[二进制数据] hex预览(前{min(len(content), preview_bytes)}字节): {preview}\n[完整内容已落盘: {artifact.artifact_id}]",
        {
            **artifact.to_dict(),
            "is_binary": True,
            "truncated": False,
        },
    )
