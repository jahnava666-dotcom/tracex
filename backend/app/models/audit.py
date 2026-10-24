from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON
from ..db.session import Base

class AuditLogModel(Base):
    __tablename__ = "audit_trail"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(128), default="analyst-default")
    action = Column(String(64), nullable=False)
    resource_type = Column(String(64), nullable=False)
    resource_id = Column(String(128), nullable=True)
    metadata_json = Column(JSON, default=dict)
    user_agent = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": str(self.id),
            "user_id": self.user_id,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "metadata": self.metadata_json or {},
            "created_at": self.created_at.isoformat() if self.created_at else datetime.utcnow().isoformat()
        }
