from sqlalchemy import create_engine, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from concurrent.futures import ThreadPoolExecutor
import asyncio
import aiofiles
from pathlib import Path
from .config import settings
import os
import logging

logger = logging.getLogger(__name__)

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
    
    logger.info(f"数据库初始化完成: {settings.database_url}")

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
        """加载JSON数据（同步版本，保持向后兼容）"""
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
        """保存JSON数据（同步版本，保持向后兼容）"""
        import json
        # 确保目录存在
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    
    @staticmethod
    async def load_json_data_async(file_path):
        """异步加载JSON数据"""
        if not os.path.exists(file_path):
            return []
        try:
            import json
            async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                content = await f.read()
                return json.loads(content)
        except (json.JSONDecodeError, FileNotFoundError):
            return []
    
    @staticmethod
    async def save_json_data_async(file_path, data):
        """异步保存JSON数据"""
        import json
        # 确保目录存在
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        content = json.dumps(data, indent=2, ensure_ascii=False, default=str)
        async with aiofiles.open(file_path, 'w', encoding='utf-8') as f:
            await f.write(content)
    
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
        """加载特定会话的请求数据（同步版本）"""
        json_path = HybridStorage.get_session_requests_path(session_id)
        return HybridStorage.load_json_data(json_path)
    
    @staticmethod
    def save_session_requests(session_id: str, requests_data):
        """保存特定会话的请求数据（同步版本）"""
        json_path = HybridStorage.ensure_session_requests_exists(session_id)
        HybridStorage.save_json_data(json_path, requests_data)
    
    @staticmethod
    async def load_session_requests_async(session_id: str):
        """异步加载特定会话的请求数据"""
        json_path = HybridStorage.get_session_requests_path(session_id)
        return await HybridStorage.load_json_data_async(json_path)
    
    @staticmethod
    async def save_session_requests_async(session_id: str, requests_data):
        """异步保存特定会话的请求数据"""
        json_path = HybridStorage.ensure_session_requests_exists(session_id)
        await HybridStorage.save_json_data_async(json_path, requests_data)
    
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
                logger.error(f"迁移会话 {session_id} 失败: {e}")
        
        # 备份原文件
        backup_path = requests_file + '.backup'
        import shutil
        shutil.copy2(requests_file, backup_path)
        
        return f"成功迁移 {len(migrated_sessions)} 个会话的数据。原文件已备份至 {backup_path}"


class AsyncHybridStorage:
    """异步版本的混合存储策略，用于高性能场景"""
    
    # 线程池执行器，用于处理CPU密集型操作
    _executor = ThreadPoolExecutor(max_workers=4)
    
    @classmethod
    async def batch_load_session_requests(cls, session_ids: list) -> dict:
        """批量异步加载多个会话的请求数据"""
        tasks = []
        for session_id in session_ids:
            task = HybridStorage.load_session_requests_async(session_id)
            tasks.append(asyncio.create_task(task))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        session_data = {}
        for session_id, result in zip(session_ids, results):
            if isinstance(result, Exception):
                session_data[session_id] = []
            else:
                session_data[session_id] = result
        
        return session_data
    
    @classmethod
    async def batch_save_session_requests(cls, session_data: dict):
        """批量异步保存多个会话的请求数据"""
        tasks = []
        for session_id, requests_data in session_data.items():
            task = HybridStorage.save_session_requests_async(session_id, requests_data)
            tasks.append(asyncio.create_task(task))
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    @classmethod
    async def parallel_file_operations(cls, operations: list):
        """并行执行多个文件操作"""
        loop = asyncio.get_event_loop()
        
        tasks = []
        for operation in operations:
            if operation['type'] == 'load':
                task = loop.run_in_executor(
                    cls._executor, 
                    HybridStorage.load_json_data, 
                    operation['path']
                )
            elif operation['type'] == 'save':
                task = loop.run_in_executor(
                    cls._executor, 
                    HybridStorage.save_json_data, 
                    operation['path'], 
                    operation['data']
                )
            tasks.append(task)
        
        return await asyncio.gather(*tasks, return_exceptions=True)
