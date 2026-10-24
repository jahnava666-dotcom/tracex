from typing import List, Optional, Dict, Any, Tuple
from pydantic import BaseModel, Field

class EmailAuthResult(BaseModel):
    status: str  # 'PASS' | 'FAIL' | 'SUSPICIOUS' | 'NEUTRAL'
    label: str
    summary: str
    technicalDetails: str
    recordFound: Optional[str] = None
    verificationSource: Optional[str] = "live_dns"  # 'live_dns' | 'header_telemetry' | 'heuristic'

class ThreatSignal(BaseModel):
    id: str
    title: str
    category: str
    severity: str  # 'low' | 'medium' | 'high' | 'critical'
    scoreImpact: int
    explanation: str
    evidence: str
    iconName: str

class InfrastructureHop(BaseModel):
    id: int
    step: str
    label: str
    ip: str
    country: str
    region: str
    asn: str
    isp: str
    hostingType: str  # 'Cloud' | 'VPS' | 'Enterprise Mail Gateway' | 'Internal Relay' | 'Residential' | 'MTA'
    status: str  # 'clean' | 'suspicious' | 'malicious'
    timestamp: str
    latency: str
    coordinates: Tuple[float, float]

class PrimaryInfrastructure(BaseModel):
    ip: str
    country: str
    region: str
    city: str
    asn: str
    isp: str
    hosting: str
    reverseDns: str
    coordinates: Tuple[float, float]

class ForensicTimelineEvent(BaseModel):
    id: str
    timestamp: str
    event: str
    node: str
    ip: str
    status: str  # 'normal' | 'flagged' | 'alert'
    details: str

class ThreatIntelligenceIndicator(BaseModel):
    id: Optional[str] = None
    indicator: str
    type: str  # 'Domain' | 'IP' | 'URL' | 'Attachment' | 'SHA-256'
    reputation: str  # 'Clean' | 'Suspicious' | 'Malicious'
    details: str
    confidence: int
    firstSeen: str

class AttachmentIOC(BaseModel):
    filename: str
    size: str
    sha256: str
    fileType: str
    verdict: str

class IOCCollection(BaseModel):
    domains: List[str] = []
    ips: List[str] = []
    urls: List[str] = []
    attachments: List[AttachmentIOC] = []

class RecommendedAction(BaseModel):
    id: int
    action: str
    priority: str  # 'Critical' | 'High' | 'Medium' | 'Low'
    completed: Optional[bool] = False

class GeoMetadata(BaseModel):
    provider: Optional[str] = "TRACE-X Telemetry Engine"
    lookupTimestamp: Optional[str] = None
    confidence: Optional[int] = 88
    isSimulated: Optional[bool] = False
    disclaimer: Optional[str] = "IP geolocation reflects ISP/infrastructure routing, not an attacker's verified physical address."

class EmailInvestigationCase(BaseModel):
    caseId: str
    email: str
    date: str
    receivedTime: str
    subject: str
    from_: str = Field(..., alias="from")
    replyTo: Optional[str] = ""
    returnPath: Optional[str] = ""
    messageId: Optional[str] = ""
    riskScore: int
    verdict: str  # 'Likely Safe' | 'Suspicious' | 'High Risk' | 'Critical Threat'
    summary: str
    status: str  # 'Open' | 'Under Review' | 'Mitigated' | 'Closed'
    assignedAnalyst: str = "Alex Carter (SOC Tier 2)"
    auth: Dict[str, EmailAuthResult]
    signals: List[ThreatSignal]
    infrastructureHops: List[InfrastructureHop]
    primaryInfrastructure: PrimaryInfrastructure
    timeline: List[ForensicTimelineEvent]
    threatIntel: List[ThreatIntelligenceIndicator]
    iocs: IOCCollection
    recommendedActions: List[RecommendedAction]
    rawHeaders: Optional[str] = ""
    isSimulatedDemo: Optional[bool] = False
    geoMetadata: Optional[GeoMetadata] = None

    class Config:
        populate_by_name = True

class GeneratedReport(BaseModel):
    reportId: str
    caseId: str
    title: str
    threatLevel: str
    riskScore: int
    createdAt: str
    author: str
    format: str  # 'PDF' | 'JSON' | 'STIX 2.1'
    summary: str
    content: Optional[str] = None

class EvidenceItem(BaseModel):
    id: str
    investigation_id: str
    user_id: str
    evidence_type: str
    description: Optional[str] = None
    source: Optional[str] = None
    sha256_hash: str
    integrity_status: str  # 'verified' | 'unverified' | 'tampered' | 'pending'
    metadata: Dict[str, Any] = {}
    created_at: str

class VerificationResult(BaseModel):
    verified: bool
    computedHash: Optional[str] = None
    expectedHash: str
    timestamp: str
    message: str
    forensicDisclaimer: Optional[str] = None

class VerifyHashRequest(BaseModel):
    evidenceId: Optional[str] = None
    expectedHash: str
    rawContent: Optional[str] = None

class CreateIndicatorRequest(BaseModel):
    indicator_type: str
    indicator_value: str
    risk_level: str
    case_id: Optional[str] = "CASE-1024"
    metadata: Optional[Dict[str, Any]] = None

class UpdateStatusRequest(BaseModel):
    status: str

class HealthResponse(BaseModel):
    status: str
    timestamp: str
    service: str
    version: str
    database: str
    evidenceVault: str
    features: Dict[str, bool]

class ChatAction(BaseModel):
    label: str
    action: str

class ChatResponse(BaseModel):
    response: str
    conversation_id: str
    intent: str
    topic: str
    confidence: float
    mode: str
    provider: str
    suggested_questions: List[str] = []
    actions: List[ChatAction] = []
    disclaimer: Optional[str] = None
