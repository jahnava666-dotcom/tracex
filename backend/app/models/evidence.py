from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON
from ..db.session import Base

class EvidenceModel(Base):
    __tablename__ = "evidence_vault"

    id = Column(String(64), primary_key=True, index=True)
    investigation_id = Column(String(64), index=True, nullable=False)
    user_id = Column(String(128), default="analyst-default")
    evidence_type = Column(String(128), default="RFC-822 EML File")
    description = Column(Text, nullable=True)
    source = Column(String(255), nullable=True)
    sha256_hash = Column(String(64), nullable=False, index=True)
    integrity_status = Column(String(32), default="verified")  # 'verified' | 'unverified' | 'tampered' | 'pending'
    metadata_json = Column(JSON, default=dict)
    storage_path = Column(String(512), nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "user_id": self.user_id,
            "evidence_type": self.evidence_type,
            "description": self.description,
            "source": self.source,
            "sha256_hash": self.sha256_hash,
            "integrity_status": self.integrity_status,
            "metadata": self.metadata_json or {},
            "created_at": self.created_at.isoformat() if self.created_at else datetime.utcnow().isoformat()
        }
