import os
from typing import Optional
from pydantic_settings import BaseSettings
from dotenv import load_dotenv
from pathlib import Path

# 加载环境变量
load_dotenv()

# 获取项目根目录的绝对路径
PROJECT_ROOT = Path(__file__).parent.parent.parent.resolve()

class Settings(BaseSettings):
    # 应用配置
    app_name: str = "Web Analyzer V2"
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    
    # 服务器配置
    backend_port: int = int(os.getenv("BACKEND_PORT", "8000"))
    frontend_port: int = int(os.getenv("FRONTEND_PORT", "3000"))
    qwen_code_port: int = int(os.getenv("QWEN_CODE_PORT", "3001"))
    
    # 数据目录配置 - 使用绝对路径确保一致性
    data_dir: str = os.getenv("DATA_DIR", str(PROJECT_ROOT / "data"))
    logs_dir: str = os.getenv("LOGS_DIR", str(PROJECT_ROOT / "logs"))
    
    # 数据库配置 - 使用绝对路径
    database_url: str = os.getenv("DATABASE_URL", f"sqlite:///{PROJECT_ROOT / 'data' / 'app.db'}")
    
    # Qwen-Code本地模型配置
    qwen_code_url: str = os.getenv("QWEN_CODE_URL", "http://localhost:3001")
    qwen_model: str = os.getenv("QWEN_MODEL", "qwen-code")
    qwen_repo_root: str = os.getenv("QWEN_REPO_ROOT", "")
    # 保留OpenAI配置以备将来扩展（当前未使用）
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_base_url: str = os.getenv("OPENAI_BASE_URL", "")
    openai_model: str = os.getenv("OPENAI_MODEL", "")
    
    # 缓存配置
    cache_ttl: int = int(os.getenv("CACHE_TTL", "3600"))
    cache_max_size: int = int(os.getenv("CACHE_MAX_SIZE", "1000"))
    
    # WebSocket配置
    websocket_timeout: int = int(os.getenv("WEBSOCKET_TIMEOUT", "300"))
    
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

# 全局设置实例
settings = Settings()

# 确保必要目录存在
os.makedirs(settings.data_dir, exist_ok=True)
os.makedirs(settings.logs_dir, exist_ok=True)
