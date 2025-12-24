from sqlalchemy import create_engine, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from .config import settings
import os

# 创建数据库引擎
# SQLite配置为线程安全
engine = create_engine(
    settings.database_url,
    poolclass=StaticPool,
    connect_args={
        "check_same_thread": False,  # SQLite线程安全
        "timeout": 20,  # 20秒超时
    },
    echo=settings.debug  # 开发模式下显示SQL
)

# 会话工厂
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 声明式基类
Base = declarative_base()

# 元数据
metadata = MetaData()

def get_db():
    """
    获取数据库会话
    用于FastAPI依赖注入
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_tables():
    """
    创建所有数据表
    """
    Base.metadata.create_all(bind=engine)

def init_database():
    """
    初始化数据库
    确保数据目录存在并创建表
    """
    # 确保数据目录存在
    db_path = settings.database_url.replace("sqlite:///", "")
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    
    # 创建数据表
    create_tables()
    
    print(f"数据库初始化完成: {settings.database_url}")

# 混合存储策略支持
class HybridStorage:
    """
    混合存储策略：支持全局requests.json和session级别的requests.json
    - 向后兼容现有的全局requests.json格式
    - 新增session级别的独立requests.json存储
    - SQLite用于索引和查询优化
    """
    
    @staticmethod
    def get_requests_json_path():
        """获取requests.json路径"""
        return settings.requests_json_path
    
    @staticmethod
    def get_sessions_json_path():
        """获取sessions.json路径"""
        return settings.sessions_json_path
    
    @staticmethod
    def ensure_json_file_exists():
        """确保requests.json文件存在"""
        json_path = HybridStorage.get_requests_json_path()
        if not os.path.exists(json_path):
            # 创建空的requests.json
            import json
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump([], f, indent=2, ensure_ascii=False)
        return json_path
    
    @staticmethod
    def ensure_sessions_json_exists():
        """确保sessions.json文件存在"""
        json_path = HybridStorage.get_sessions_json_path()
        if not os.path.exists(json_path):
            # 创建空的sessions.json
            import json
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump([], f, indent=2, ensure_ascii=False)
        return json_path
    
    @staticmethod
    def load_json_data(file_path):
        """加载JSON数据"""
        if not os.path.exists(file_path):
            return []
        try:
            import json
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []
    
    @staticmethod
    def save_json_data(file_path, data):
        """保存JSON数据"""
        import json
        # 确保目录存在
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    
    @staticmethod
    def get_session_requests_path(session_id: str):
        """获取特定会话的requests.json路径"""
        return os.path.join(settings.data_dir, "sessions", session_id, "requests.json")
    
    @staticmethod
    def ensure_session_requests_exists(session_id: str):
        """确保会话级别的requests.json文件存在"""
        json_path = HybridStorage.get_session_requests_path(session_id)
        if not os.path.exists(json_path):
            # 创建空的requests.json
            import json
            os.makedirs(os.path.dirname(json_path), exist_ok=True)
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump([], f, indent=2, ensure_ascii=False)
        return json_path
    
    @staticmethod
    def load_session_requests(session_id: str):
        """加载特定会话的请求数据"""
        json_path = HybridStorage.get_session_requests_path(session_id)
        return HybridStorage.load_json_data(json_path)
    
    @staticmethod
    def save_session_requests(session_id: str, requests_data):
        """保存特定会话的请求数据"""
        json_path = HybridStorage.ensure_session_requests_exists(session_id)
        HybridStorage.save_json_data(json_path, requests_data)
    
    @staticmethod
    def migrate_requests_to_sessions():
        """将现有的requests.json数据迁移到各个session目录"""
        import json
        
        # 读取现有的requests.json
        requests_file = HybridStorage.get_requests_json_path()
        if not os.path.exists(requests_file):
            return "没有找到requests.json文件"
        
        requests_data = HybridStorage.load_json_data(requests_file)
        if not requests_data:
            return "requests.json为空"
        
        # 按session_id分组
        session_groups = {}
        for request in requests_data:
            session_id = request.get('session_id')
            if session_id:
                if session_id not in session_groups:
                    session_groups[session_id] = []
                session_groups[session_id].append(request)
        
        # 保存到各个session目录
        migrated_sessions = []
        for session_id, session_requests in session_groups.items():
            try:
                HybridStorage.save_session_requests(session_id, session_requests)
                migrated_sessions.append(session_id)
            except Exception as e:
                print(f"迁移会话 {session_id} 失败: {e}")
        
        # 备份原文件
        backup_path = requests_file + '.backup'
        import shutil
        shutil.copy2(requests_file, backup_path)
        
        return f"成功迁移 {len(migrated_sessions)} 个会话的数据。原文件已备份至 {backup_path}"
