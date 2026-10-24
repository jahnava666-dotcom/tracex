from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, JSON
from ..db.session import Base

class CaseModel(Base):
    __tablename__ = "investigation_cases"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    case_id = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(255), nullable=False)
    date = Column(String(128), nullable=False)
    received_time = Column(String(128), nullable=False)
    subject = Column(String(512), nullable=False)
    from_address = Column(String(255), nullable=False)
    reply_to = Column(String(255), default="")
    return_path = Column(String(255), default="")
    message_id = Column(String(255), default="")
    risk_score = Column(Integer, default=0)
    verdict = Column(String(64), default="Suspicious")  # 'Likely Safe' | 'Suspicious' | 'High Risk' | 'Critical Threat'
    summary = Column(Text, default="")
    status = Column(String(64), default="Open")  # 'Open' | 'Under Review' | 'Mitigated' | 'Closed'
    assigned_analyst = Column(String(128), default="Alex Carter (SOC Tier 2)")
    
    # Structured JSON forensics data
    auth = Column(JSON, default=dict)
    signals = Column(JSON, default=list)
    infrastructure_hops = Column(JSON, default=list)
    primary_infrastructure = Column(JSON, default=dict)
    timeline = Column(JSON, default=list)
    threat_intel = Column(JSON, default=list)
    iocs = Column(JSON, default=dict)
    recommended_actions = Column(JSON, default=list)
    geo_metadata = Column(JSON, default=dict)
    
    raw_headers = Column(Text, default="")
    is_simulated_demo = Column(Boolean, default=False)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "caseId": self.case_id,
            "email": self.email,
            "date": self.date,
            "receivedTime": self.received_time,
            "subject": self.subject,
            "from": self.from_address,
            "replyTo": self.reply_to,
            "returnPath": self.return_path,
            "messageId": self.message_id,
            "riskScore": self.risk_score,
            "verdict": self.verdict,
            "summary": self.summary,
            "status": self.status,
            "assignedAnalyst": self.assigned_analyst,
            "auth": self.auth or {},
            "signals": self.signals or [],
            "infrastructureHops": self.infrastructure_hops or [],
            "primaryInfrastructure": self.primary_infrastructure or {},
            "timeline": self.timeline or [],
            "threatIntel": self.threat_intel or [],
            "iocs": self.iocs or {"domains": [], "ips": [], "urls": [], "attachments": []},
            "recommendedActions": self.recommended_actions or [],
            "rawHeaders": self.raw_headers or "",
            "isSimulatedDemo": self.is_simulated_demo,
            "geoMetadata": self.geo_metadata or {}
        }
