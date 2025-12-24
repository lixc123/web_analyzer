"""文件操作辅助工具模块"""
import hashlib
import os
import re
import shutil
from pathlib import Path
from typing import List, Optional, Union
from urllib.parse import urlparse, unquote


def ensure_dir(path: Union[str, Path]) -> Path:
    """确保目录存在，不存在则创建。
    
    Args:
        path: 目录路径
        
    Returns:
        Path 对象
    """
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def safe_filename(name: str, max_length: int = 200) -> str:
    """将字符串转换为安全的文件名。
    
    移除或替换不安全字符，限制长度。
    
    Args:
        name: 原始文件名
        max_length: 最大长度
        
    Returns:
        安全的文件名
    """
    # 移除 URL 编码
    name = unquote(name)
    
    # 移除不安全字符
    unsafe_chars = r'[<>:"/\\|?*\x00-\x1f]'
    safe_name = re.sub(unsafe_chars, "_", name)
    
    # 移除连续的下划线和空格
    safe_name = re.sub(r"[_\s]+", "_", safe_name)
    
    # 移除首尾的点和空格
    safe_name = safe_name.strip(". ")
    
    # 限制长度
    if len(safe_name) > max_length:
        # 保留扩展名
        ext = Path(safe_name).suffix
        base_max = max_length - len(ext)
        safe_name = safe_name[:base_max] + ext
    
    return safe_name or "unnamed"


def url_to_filename(url: str, include_query: bool = False) -> str:
    """将 URL 转换为文件名。
    
    Args:
        url: URL 字符串
        include_query: 是否包含查询参数
        
    Returns:
        文件名字符串
    """
    parsed = urlparse(url)
    
    # 获取路径的最后一部分作为文件名基础
    path_parts = parsed.path.rstrip("/").split("/")
    base_name = path_parts[-1] if path_parts[-1] else parsed.netloc
    
    if include_query and parsed.query:
        # 用 hash 压缩查询参数
        query_hash = hashlib.md5(parsed.query.encode()).hexdigest()[:8]
        base_name = f"{base_name}_{query_hash}"
    
    return safe_filename(base_name)


def get_extension_from_content_type(content_type: Optional[str]) -> str:
    """根据 Content-Type 获取文件扩展名。
    
    Args:
        content_type: HTTP Content-Type 头
        
    Returns:
        文件扩展名（含点号）
    """
    if not content_type:
        return ".bin"
    
    # 移除参数部分（如 charset）
    mime = content_type.split(";")[0].strip().lower()
    
    mime_to_ext = {
        "application/json": ".json",
        "application/javascript": ".js",
        "text/javascript": ".js",
        "text/css": ".css",
        "text/html": ".html",
        "text/plain": ".txt",
        "text/xml": ".xml",
        "application/xml": ".xml",
        "image/png": ".png",
        "image/jpeg": ".jpg",
        "image/gif": ".gif",
        "image/webp": ".webp",
        "image/svg+xml": ".svg",
        "image/x-icon": ".ico",
        "application/pdf": ".pdf",
        "application/zip": ".zip",
        "font/woff": ".woff",
        "font/woff2": ".woff2",
        "application/font-woff": ".woff",
        "application/font-woff2": ".woff2",
    }
    
    return mime_to_ext.get(mime, ".bin")


def get_file_hash(file_path: Union[str, Path], algorithm: str = "md5") -> str:
    """计算文件的哈希值。
    
    Args:
        file_path: 文件路径
        algorithm: 哈希算法 (md5, sha1, sha256)
        
    Returns:
        十六进制哈希字符串
    """
    hasher = hashlib.new(algorithm)
    
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    
    return hasher.hexdigest()


def get_content_hash(content: bytes, algorithm: str = "md5") -> str:
    """计算内容的哈希值。
    
    Args:
        content: 字节内容
        algorithm: 哈希算法
        
    Returns:
        十六进制哈希字符串
    """
    hasher = hashlib.new(algorithm)
    hasher.update(content)
    return hasher.hexdigest()


def copy_file_safe(src: Union[str, Path], dst: Union[str, Path]) -> bool:
    """安全地复制文件，自动创建目标目录。
    
    Args:
        src: 源文件路径
        dst: 目标文件路径
        
    Returns:
        是否成功
    """
    try:
        dst_path = Path(dst)
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        return True
    except Exception:
        return False


def read_text_safe(
    file_path: Union[str, Path],
    encoding: str = "utf-8",
    fallback_encodings: Optional[List[str]] = None,
) -> Optional[str]:
    """安全地读取文本文件，自动尝试多种编码。
    
    Args:
        file_path: 文件路径
        encoding: 首选编码
        fallback_encodings: 备用编码列表
        
    Returns:
        文件内容，失败返回 None
    """
    if fallback_encodings is None:
        fallback_encodings = ["utf-8-sig", "gbk", "gb2312", "latin-1"]
    
    encodings_to_try = [encoding] + [e for e in fallback_encodings if e != encoding]
    
    for enc in encodings_to_try:
        try:
            with open(file_path, "r", encoding=enc) as f:
                return f.read()
        except (UnicodeDecodeError, LookupError):
            continue
        except Exception:
            return None
    
    return None


def write_text_safe(
    file_path: Union[str, Path],
    content: str,
    encoding: str = "utf-8",
) -> bool:
    """安全地写入文本文件。
    
    Args:
        file_path: 文件路径
        content: 文件内容
        encoding: 编码
        
    Returns:
        是否成功
    """
    try:
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding=encoding) as f:
            f.write(content)
        return True
    except Exception:
        return False


def write_bytes_safe(file_path: Union[str, Path], content: bytes) -> bool:
    """安全地写入二进制文件。
    
    Args:
        file_path: 文件路径
        content: 文件内容
        
    Returns:
        是否成功
    """
    try:
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            f.write(content)
        return True
    except Exception:
        return False


def list_files(
    directory: Union[str, Path],
    pattern: str = "*",
    recursive: bool = False,
) -> List[Path]:
    """列出目录中的文件。
    
    Args:
        directory: 目录路径
        pattern: 文件名模式（glob 格式）
        recursive: 是否递归搜索
        
    Returns:
        文件路径列表
    """
    dir_path = Path(directory)
    if not dir_path.is_dir():
        return []
    
    if recursive:
        return list(dir_path.rglob(pattern))
    else:
        return list(dir_path.glob(pattern))


def get_relative_path(file_path: Union[str, Path], base_path: Union[str, Path]) -> str:
    """获取相对路径。
    
    Args:
        file_path: 文件路径
        base_path: 基准路径
        
    Returns:
        相对路径字符串
    """
    try:
        return str(Path(file_path).relative_to(Path(base_path)))
    except ValueError:
        return str(file_path)


def get_file_size_human(size_bytes: int) -> str:
    """将字节大小转换为人类可读格式。
    
    Args:
        size_bytes: 字节数
        
    Returns:
        人类可读的大小字符串
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(size_bytes) < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"
