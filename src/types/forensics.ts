export type ThreatVerdict = 'Likely Safe' | 'Suspicious' | 'High Risk' | 'Critical Threat';

export type AuthStatus = 'PASS' | 'FAIL' | 'SUSPICIOUS' | 'NEUTRAL';

export interface EmailAuthResult {
  status: AuthStatus;
  label: string;
  summary: string;
  technicalDetails: string;
  recordFound?: string;
}

export interface ThreatSignal {
  id: string;
  title: string;
  category: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  scoreImpact: number;
  explanation: string;
  evidence: string;
  iconName: string;
}

export interface InfrastructureHop {
  id: number;
  step: string;
  label: string;
  ip: string;
  country: string;
  region: string;
  asn: string;
  isp: string;
  hostingType: 'Cloud' | 'VPS' | 'Enterprise Mail Gateway' | 'Internal Relay' | 'Residential' | 'MTA';
  status: 'clean' | 'suspicious' | 'malicious';
  timestamp: string;
  latency: string;
  coordinates: [number, number]; // [lat, lng]
}

export interface ForensicTimelineEvent {
  id: string;
  timestamp: string;
  event: string;
  node: string;
  ip: string;
  status: 'normal' | 'flagged' | 'alert';
  details: string;
}

export interface ThreatIntelligenceIndicator {
  id?: string;
  indicator: string;
  type: 'Domain' | 'IP' | 'URL' | 'Attachment' | 'SHA-256';
  reputation: 'Clean' | 'Suspicious' | 'Malicious';
  details: string;
  confidence: number;
  firstSeen: string;
}

export interface IOCCollection {
  domains: string[];
  ips: string[];
  urls: string[];
  attachments: {
    filename: string;
    size: string;
    sha256: string;
    fileType: string;
    verdict: string;
  }[];
}

export interface EmailInvestigationCase {
  caseId: string;
  email: string;
  date: string;
  receivedTime: string;
  subject: string;
  from: string;
  replyTo: string;
  returnPath: string;
  messageId: string;
  riskScore: number;
  verdict: ThreatVerdict;
  summary: string;
  status: 'Open' | 'Under Review' | 'Mitigated' | 'Closed';
  assignedAnalyst: string;
  auth: {
    spf: EmailAuthResult;
    dkim: EmailAuthResult;
    dmarc: EmailAuthResult;
  };
  signals: ThreatSignal[];
  infrastructureHops: InfrastructureHop[];
  primaryInfrastructure: {
    ip: string;
    country: string;
    region: string;
    city: string;
    asn: string;
    isp: string;
    hosting: string;
    reverseDns: string;
    coordinates: [number, number];
  };
  timeline: ForensicTimelineEvent[];
  threatIntel: ThreatIntelligenceIndicator[];
  iocs: IOCCollection;
  recommendedActions: {
    id: number;
    action: string;
    priority: 'Critical' | 'High' | 'Medium' | 'Low';
    completed?: boolean;
  }[];
  rawHeaders: string;
  isSimulatedDemo?: boolean;
  geoMetadata?: {
    provider?: string;
    lookupTimestamp?: string;
    confidence?: number;
    isSimulated?: boolean;
  };
}

export interface AssistantMessage {
  id: string;
  sender: 'investigator' | 'ai';
  text: string;
  timestamp: string;
}

export interface GeneratedReport {
  reportId: string;
  caseId: string;
  title: string;
  threatLevel: ThreatVerdict;
  riskScore: number;
  createdAt: string;
  author: string;
  format: 'PDF' | 'JSON' | 'STIX 2.1';
  summary: string;
}
