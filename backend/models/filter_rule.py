"""过滤规则数据库模型"""
from sqlalchemy import Column, String, Boolean, Integer
from backend.app.database import Base


class FilterRuleModel(Base):
    """过滤规则数据库模型"""
    __tablename__ = "filter_rules"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    type = Column(String, nullable=False)  # "include" 或 "exclude"
    pattern = Column(String, nullable=False)
    enabled = Column(Boolean, default=True)
    order = Column(Integer, default=0)  # 规则顺序

    def to_dict(self):
        """转换为字典"""
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "pattern": self.pattern,
            "enabled": self.enabled,
            "order": self.order
        }
