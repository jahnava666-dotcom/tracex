from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON
from ..db.session import Base

class ThreatIndicatorModel(Base):
    __tablename__ = "threat_indicators"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), index=True, default="CASE-1024")
    indicator = Column(String(512), index=True, nullable=False)
    indicator_type = Column(String(32), nullable=False)  # 'Domain' | 'IP' | 'URL' | 'Attachment' | 'SHA-256'
    reputation = Column(String(32), default="Suspicious")  # 'Clean' | 'Suspicious' | 'Malicious'
    details = Column(Text, default="")
    confidence = Column(Integer, default=85)
    first_seen = Column(String(64), default="")
    metadata_json = Column(JSON, default=dict)
    
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": str(self.id),
            "caseId": self.case_id,
            "indicator": self.indicator,
            "type": self.indicator_type,
            "reputation": self.reputation,
            "details": self.details,
            "confidence": self.confidence,
            "firstSeen": self.first_seen or (self.created_at.strftime("%Y-%m-%d") if self.created_at else "2026-09-10"),
            "metadata": self.metadata_json or {}
        }
