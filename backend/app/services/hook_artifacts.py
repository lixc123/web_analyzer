"""Native Hook 原始 buffer 落盘（可选）。

用于保存 Frida send(payload, data) 传回来的二进制 buffer，避免只保留 preview
导致 AI 无法判断“网络前最后一次明文/压缩/加密”的字节特征。
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from backend.app.config import settings


_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _guess_extension(content_type: str, fallback: str = ".bin") -> str:
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    if not ct:
        return fallback
    if ct == "application/json":
        return ".json"
    if ct.startswith("text/"):
        return ".txt"
    return fallback


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


class HookArtifactStore:
    """将 Hook 原始 buffer 保存到 data/hook_artifacts 下。"""

    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = Path(base_dir or settings.hook_artifacts_dir).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def store_bytes(self, content: bytes, *, content_type: str = "", prefix: str = "hookbuf") -> StoredArtifact:
        ext = _guess_extension(content_type)
        artifact_id = f"{prefix}_{uuid.uuid4().hex}{ext}"
        file_path = self.base_dir / artifact_id

        sha256 = hashlib.sha256(content or b"").hexdigest()
        file_path.write_bytes(content or b"")

        rel = str(file_path.relative_to(self.base_dir)).replace("\\", "/")
        return StoredArtifact(
            artifact_id=artifact_id,
            relative_path=rel,
            size=int(len(content or b"")),
            sha256=sha256,
            content_type=(content_type or "application/octet-stream"),
        )

    def resolve_artifact_path(self, artifact_id: str) -> Path:
        if not artifact_id or not _SAFE_ID_RE.match(artifact_id) or ".." in artifact_id or "/" in artifact_id or "\\" in artifact_id:
            raise ValueError("invalid_artifact_id")
        path = (self.base_dir / artifact_id).resolve()
        if self.base_dir not in path.parents and path != self.base_dir:
            raise ValueError("invalid_artifact_path")
        return path

