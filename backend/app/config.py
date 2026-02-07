import os
from typing import Optional
from pydantic_settings import BaseSettings
from dotenv import load_dotenv
from pathlib import Path
import re
from pydantic import field_validator

# 加载环境变量
load_dotenv()

# 获取项目根目录的绝对路径
PROJECT_ROOT = Path(__file__).parent.parent.parent.resolve()

_WIN_ABS_PATH_RE = re.compile(r"^[A-Za-z]:[\\\\/]")


def _is_windows_abs_path(path_value: str) -> bool:
    return bool(_WIN_ABS_PATH_RE.match(path_value or ""))


def _resolve_path_from_root(path_value: str) -> str:
    """将路径（可相对）规范化为基于项目根目录的绝对路径。"""
    if not path_value:
        return str(PROJECT_ROOT)

    # Path.is_absolute 在非 Windows 平台上无法识别 'C:\\...'，需要额外判断
    if Path(path_value).is_absolute() or _is_windows_abs_path(path_value):
        return str(Path(path_value))

    return str((PROJECT_ROOT / path_value).resolve())


def _normalize_database_url(database_url: str) -> str:
    """规范化数据库 URL，避免因工作目录不同导致数据库文件落到错误位置。"""
    if not database_url:
        return database_url

    # 仅处理 sqlite 文件路径；其他类型交给用户自行配置
    prefix = "sqlite:///"
    if not database_url.startswith(prefix):
        return database_url

    sqlite_path = database_url[len(prefix):]

    # sqlite 内存数据库，不做处理
    if sqlite_path in {":memory:", "file::memory:"}:
        return database_url

    # 绝对路径（POSIX: 以 / 开头；Windows: 盘符开头）不做处理
    if sqlite_path.startswith("/") or _is_windows_abs_path(sqlite_path):
        return database_url

    # 相对路径：统一解析到项目根目录
    abs_path = Path(_resolve_path_from_root(sqlite_path)).as_posix()
    return f"{prefix}{abs_path}"

class Settings(BaseSettings):
    # 应用配置
    app_name: str = "Web Analyzer V2"
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    
    # 服务器配置
    backend_port: int = int(os.getenv("BACKEND_PORT", "8000"))
    frontend_port: int = int(os.getenv("FRONTEND_PORT", "3000"))
    terminal_service_port: int = int(os.getenv("TERMINAL_SERVICE_PORT", "3001"))
    
    # 数据目录配置 - 使用绝对路径确保一致性
    data_dir: str = str(PROJECT_ROOT / "data")
    logs_dir: str = str(PROJECT_ROOT / "logs")
    
    # 数据库配置 - 使用绝对路径
    database_url: str = f"sqlite:///{(PROJECT_ROOT / 'data' / 'app.db').as_posix()}"
    
    # AI 终端服务配置
    terminal_service_url: str = os.getenv("TERMINAL_SERVICE_URL", "http://localhost:3001")
    ai_cli_default: str = os.getenv("AI_CLI_DEFAULT", "qwen")
    # 保留OpenAI配置以备将来扩展（当前未使用）
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_base_url: str = os.getenv("OPENAI_BASE_URL", "")
    openai_model: str = os.getenv("OPENAI_MODEL", "")
    
    # 缓存配置
    cache_ttl: int = int(os.getenv("CACHE_TTL", "3600"))
    cache_max_size: int = int(os.getenv("CACHE_MAX_SIZE", "1000"))
    
    # WebSocket配置
    websocket_timeout: int = int(os.getenv("WEBSOCKET_TIMEOUT", "300"))

    # CORS配置 - 本地开发使用
    cors_origins: list = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "*"  # 本地使用允许所有来源
    ]

    # 代理服务配置
    proxy_port: int = int(os.getenv("PROXY_PORT", "8888"))

    # 代理抓包（mitmproxy）存储/脱敏配置
    mitmproxy_confdir: str = os.getenv("MITMPROXY_CONFDIR", str(PROJECT_ROOT / "data" / "mitmproxy"))
    proxy_artifacts_dir: str = os.getenv("PROXY_ARTIFACTS_DIR", str(PROJECT_ROOT / "data" / "proxy_artifacts"))
    hook_artifacts_dir: str = os.getenv("HOOK_ARTIFACTS_DIR", str(PROJECT_ROOT / "data" / "hook_artifacts"))
    proxy_body_inline_limit: int = int(os.getenv("PROXY_BODY_INLINE_LIMIT", "12000"))  # 内联最大字符数
    proxy_body_preview_bytes: int = int(os.getenv("PROXY_BODY_PREVIEW_BYTES", "4096"))  # 二进制预览字节
    proxy_ws_message_preview_bytes: int = int(os.getenv("PROXY_WS_PREVIEW_BYTES", "2048"))
    # 本地自用场景默认不脱敏；如需可通过环境变量开启
    proxy_mask_sensitive_default: bool = os.getenv("PROXY_MASK_SENSITIVE_DEFAULT", "false").lower() == "true"

    # Streaming/SSE（长连接响应）采集：首包/尾包预览与可选片段捕获上限
    proxy_stream_preview_bytes: int = int(os.getenv("PROXY_STREAM_PREVIEW_BYTES", "2048"))
    proxy_stream_capture_max_bytes: int = int(os.getenv("PROXY_STREAM_CAPTURE_MAX_BYTES", "262144"))

    # 存储清理策略（本地运行可按需配置；0 表示不限制）
    proxy_artifacts_max_total_mb: int = int(os.getenv("PROXY_ARTIFACTS_MAX_TOTAL_MB", "0"))
    proxy_artifacts_max_age_days: int = int(os.getenv("PROXY_ARTIFACTS_MAX_AGE_DAYS", "0"))
    proxy_sessions_max_age_days: int = int(os.getenv("PROXY_SESSIONS_MAX_AGE_DAYS", "0"))

    # JWT配置
    secret_key: str = os.getenv("SECRET_KEY", "your-secret-key-here-change-in-production")
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    
    # 文件路径配置 - 基于data_dir的绝对路径
    @property
    def requests_json_path(self) -> str:
        return os.path.join(self.data_dir, "requests.json")
    
    @property 
    def sessions_json_path(self) -> str:
        return os.path.join(self.data_dir, "sessions.json")
    
    class Config:
        env_file = ".env"

    @field_validator("data_dir", "logs_dir", "mitmproxy_confdir", "proxy_artifacts_dir", "hook_artifacts_dir")
    @classmethod
    def _normalize_paths(cls, v: str) -> str:
        return _resolve_path_from_root(v)

    @field_validator("database_url")
    @classmethod
    def _normalize_db_url(cls, v: str) -> str:
        return _normalize_database_url(v)

# 全局设置实例
settings = Settings()

# 确保必要目录存在
os.makedirs(settings.data_dir, exist_ok=True)
os.makedirs(settings.logs_dir, exist_ok=True)
os.makedirs(settings.mitmproxy_confdir, exist_ok=True)
os.makedirs(settings.proxy_artifacts_dir, exist_ok=True)
os.makedirs(settings.hook_artifacts_dir, exist_ok=True)
