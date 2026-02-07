"""gRPC/Protobuf best-effort helpers (no decoding)."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple


def normalize_content_type(content_type: str) -> str:
    return (content_type or "").split(";", 1)[0].strip().lower()


def is_grpc_content_type(content_type: str) -> bool:
    ct = normalize_content_type(content_type)
    return ct.startswith("application/grpc")


def is_protobuf_content_type(content_type: str) -> bool:
    ct = normalize_content_type(content_type)
    if ct in {"application/x-protobuf", "application/protobuf"}:
        return True
    return "protobuf" in ct


def parse_grpc_method_path(url_path: str) -> Dict[str, str]:
    """解析 gRPC method path: /package.Service/Method."""
    path = (url_path or "").strip()
    if not path:
        return {"method_path": ""}
    if not path.startswith("/"):
        path = "/" + path
    parts = path.split("/")
    if len(parts) >= 3 and parts[1] and parts[2]:
        service = parts[1]
        method = parts[2]
        return {"method_path": f"/{service}/{method}", "service": service, "method": method}
    return {"method_path": path}


def _u32be(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big", signed=False)


def parse_grpc_frames(data: bytes, *, max_frames: int = 50, max_scan_bytes: int = 1024 * 1024) -> Dict[str, Any]:
    """解析 gRPC message frame header（5 字节：1 flag + 4 length），不解码 protobuf。

    返回值：
    - frames: [{compressed, length}]
    - parsed_bytes / scanned_bytes / data_bytes
    - incomplete: True 表示数据不足以解析完整帧/消息体
    """
    if not data:
        return {"frames": [], "frame_count": 0, "data_bytes": 0, "scanned_bytes": 0, "parsed_bytes": 0, "incomplete": False}

    frames = []
    scanned = data[: max(0, int(max_scan_bytes))]
    i = 0
    parsed_bytes = 0
    incomplete = False

    try:
        while i + 5 <= len(scanned) and len(frames) < int(max_frames):
            flag = scanned[i]
            length = _u32be(scanned[i + 1 : i + 5])
            frames.append({"compressed": bool(flag & 0x1), "length": int(length)})
            i += 5
            parsed_bytes = i

            # Skip message body if present in scanned window
            if length < 0:
                break
            if i + length > len(scanned):
                incomplete = True
                break
            i += int(length)
            parsed_bytes = i

        # If we exit due to insufficient bytes for header, mark incomplete if data has more but scanned truncated
        if not incomplete and len(scanned) < len(data) and i >= len(scanned):
            incomplete = True
    except Exception:
        incomplete = True

    return {
        "frames": frames,
        "frame_count": len(frames),
        "data_bytes": len(data),
        "scanned_bytes": len(scanned),
        "parsed_bytes": int(parsed_bytes),
        "incomplete": bool(incomplete),
    }

