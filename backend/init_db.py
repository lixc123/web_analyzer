"""初始化数据库表"""
import sys
import os

# 添加路径
backend_path = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(backend_path)
sys.path.insert(0, project_root)
sys.path.insert(0, backend_path)

# 先导入Base
from backend.app.database import Base, engine

# 导入所有模型
from backend.models.filter_rule import FilterRuleModel

def init_db():
    """创建所有数据表"""
    print("开始创建数据库表...")
    print(f"Base的所有子类: {Base.__subclasses__()}")
    Base.metadata.create_all(bind=engine)
    print("数据库表创建完成！")
    
    # 显示创建的表
    from sqlalchemy import inspect
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    print(f"已创建的表: {tables}")

if __name__ == "__main__":
    init_db()
