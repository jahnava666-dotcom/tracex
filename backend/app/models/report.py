from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime
from ..db.session import Base

class ReportModel(Base):
    __tablename__ = "forensic_reports"

    report_id = Column(String(64), primary_key=True, index=True)
    case_id = Column(String(64), index=True, nullable=False)
    title = Column(String(255), nullable=False)
    threat_level = Column(String(64), default="Critical Threat")
    risk_score = Column(Integer, default=90)
    format = Column(String(32), default="PDF")  # 'PDF' | 'JSON' | 'STIX 2.1'
    summary = Column(Text, default="")
    content = Column(Text, default="")
    author = Column(String(128), default="TRACE-X Forensic Engine (Automated SOC Tier 2)")
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "reportId": self.report_id,
            "caseId": self.case_id,
            "title": self.title,
            "threatLevel": self.threat_level,
            "riskScore": self.risk_score,
            "createdAt": self.created_at.strftime("%b %d, %Y %H:%M") if self.created_at else "Just now",
            "author": self.author,
            "format": self.format,
            "summary": self.summary
        }
