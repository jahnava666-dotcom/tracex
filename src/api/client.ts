import { CASE_1024, RECENT_INVESTIGATIONS, MOCK_REPORTS, AI_PRESET_RESPONSES } from '../data/mockData';
import { EmailInvestigationCase, GeneratedReport, ThreatIntelligenceIndicator } from '../types/forensics';
import { EvidenceItem, VerificationResult } from '../services/evidenceService';

const API_BASE_URL = import.meta.env.VITE_API_URL || '';

/**
 * TRACE-X Production Client Layer
 * Communicates with FastAPI Digital Forensics & Threat Intelligence Backend
 */
export const apiClient = {
  // GET /api/health
  checkHealth: async (): Promise<{ status: string; version: string; database: string }> => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/health`);
      if (res.ok) {
        return await res.json();
      }
    } catch (err) {
      console.warn('[TRACE-X] Backend health check failed:', err);
    }
    return { status: 'offline', version: '1.0.0', database: 'unavailable' };
  },

  // POST /api/analyze-email
  analyzeEmail: async (input: { file?: File; rawText?: string; isDemo?: boolean }): Promise<EmailInvestigationCase> => {
    // If explicit demo requested
    if (input.isDemo) {
      try {
        const formData = new FormData();
        formData.append('isDemo', 'true');
        const res = await fetch(`${API_BASE_URL}/api/analyze-email`, {
          method: 'POST',
          body: formData
        });
        if (res.ok) {
          const data = await res.json();
          return { ...data, isSimulatedDemo: true };
        }
      } catch {
        // fallback
      }
      return {
        ...CASE_1024,
        isSimulatedDemo: true
      };
    }

    try {
      const formData = new FormData();
      if (input.file) {
        formData.append('file', input.file);
      }
      if (input.rawText) {
        formData.append('rawText', input.rawText);
      }

      const res = await fetch(`${API_BASE_URL}/api/analyze-email`, {
        method: 'POST',
        body: formData
      });

      if (res.ok) {
        const caseResult: EmailInvestigationCase = await res.json();
        return caseResult;
      } else {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.detail || `Server returned HTTP ${res.status}`);
      }
    } catch (err) {
      console.warn('[TRACE-X] Direct API email analysis failed, falling back to local simulation:', err);
      // Fallback only if backend is disconnected
      return {
        ...CASE_1024,
        caseId: `CASE-${Math.floor(1000 + Math.random() * 9000)}`,
        date: new Date().toLocaleString(),
        subject: input.file?.name.replace(/\.[^/.]+$/, '') || 'Manual Offline Analysis',
        isSimulatedDemo: true
      };
    }
  },

  // GET /api/cases
  getInvestigations: async (): Promise<{ cases: EmailInvestigationCase[]; isDemo: boolean }> => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/cases`);
      if (res.ok) {
        const cases: EmailInvestigationCase[] = await res.json();
        if (cases && cases.length > 0) {
          return { cases, isDemo: false };
        }
      }
    } catch (err) {
      console.warn('[TRACE-X] Error fetching cases from backend API:', err);
    }
    return {
      cases: RECENT_INVESTIGATIONS.map((c) => ({ ...c, isSimulatedDemo: true })),
      isDemo: true
    };
  },

  // GET /api/cases/{id}
  getInvestigationById: async (id: string): Promise<EmailInvestigationCase | null> => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/cases/${id}`);
      if (res.ok) {
        return await res.json();
      }
    } catch (err) {
      console.warn(`[TRACE-X] Error fetching case ${id}:`, err);
    }
    return CASE_1024;
  },

  // PATCH /api/cases/{id}/status
  updateCaseStatus: async (
    caseId: string,
    status: 'Open' | 'Under Review' | 'Mitigated' | 'Closed'
  ): Promise<boolean> => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/cases/${caseId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status })
      });
      return res.ok;
    } catch {
      return false;
    }
  },

  // DELETE /api/cases/{id}
  deleteCase: async (caseId: string): Promise<boolean> => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/cases/${caseId}`, {
        method: 'DELETE'
      });
      return res.ok;
    } catch {
      return false;
    }
  },

  // GET /api/threat-intelligence
  getThreatIntelligence: async (search?: string, type?: string): Promise<ThreatIntelligenceIndicator[]> => {
    try {
      const params = new URLSearchParams();
      if (search) params.append('search', search);
      if (type && type !== 'All') params.append('type', type);

      const url = `${API_BASE_URL}/api/threat-intelligence${params.toString() ? `?${params.toString()}` : ''}`;
      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        if (data && data.length > 0) return data;
      }
    } catch (err) {
      console.warn('[TRACE-X] Failed to fetch threat intel from API:', err);
    }
    return CASE_1024.threatIntel;
  },

  // POST /api/threat-intelligence
  addThreatIndicator: async (indicator: {
    indicator_type: string;
    indicator_value: string;
    risk_level: string;
    case_id?: string;
    metadata?: Record<string, any>;
  }): Promise<ThreatIntelligenceIndicator | null> => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/threat-intelligence`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(indicator)
      });
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('[TRACE-X] Failed to add threat indicator:', err);
    }
    return null;
  },

  // GET /api/geolocation?ip=...
  getGeolocation: async (ip: string) => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/geolocation?ip=${encodeURIComponent(ip)}`);
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('[TRACE-X] Geolocation lookup error:', err);
    }
    return null;
  },

  // GET /api/evidence
  getEvidence: async (investigationId?: string): Promise<EvidenceItem[]> => {
    try {
      const url = investigationId
        ? `${API_BASE_URL}/api/evidence?investigation_id=${encodeURIComponent(investigationId)}`
        : `${API_BASE_URL}/api/evidence`;
      const res = await fetch(url);
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('[TRACE-X] Failed to fetch evidence from API:', err);
    }
    return [];
  },

  // POST /api/evidence (upload file)
  uploadEvidence: async (
    file: File,
    investigationId: string,
    evidenceType: string,
    description: string
  ): Promise<EvidenceItem | null> => {
    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('investigation_id', investigationId);
      formData.append('evidence_type', evidenceType);
      formData.append('description', description);

      const res = await fetch(`${API_BASE_URL}/api/evidence`, {
        method: 'POST',
        body: formData
      });
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('[TRACE-X] Failed to upload evidence to API:', err);
    }
    return null;
  },

  // POST /api/evidence/verify
  verifyEvidenceHash: async (
    evidenceId: string,
    expectedHash: string,
    rawContent?: string
  ): Promise<VerificationResult> => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/evidence/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ evidenceId, expectedHash, rawContent })
      });
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('[TRACE-X] Evidence verification request error:', err);
    }
    return {
      verified: false,
      computedHash: null,
      expectedHash,
      timestamp: new Date().toISOString(),
      message: 'Network error communicating with forensic verification engine.',
      forensicDisclaimer: 'Integrity verification requires an active backend connection.'
    };
  },

  // POST /api/reports/generate
  generateReport: async (
    caseId: string,
    format: 'PDF' | 'JSON' | 'STIX 2.1' = 'PDF'
  ): Promise<GeneratedReport> => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/reports/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ caseId, format })
      });
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('[TRACE-X] Report generation API request error:', err);
    }

    // Fallback report
    return {
      reportId: `REP-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`,
      caseId,
      title: `Forensic Dossier: ${caseId}`,
      threatLevel: CASE_1024.verdict,
      riskScore: CASE_1024.riskScore,
      createdAt: 'Just now',
      author: 'TRACE-X Forensic Engine (Automated SOC Tier 2)',
      format,
      summary: `Automated forensic export containing header anomalies, IOCs, SPF/DKIM/DMARC breakdown, and remediation plan for ${caseId}.`
    };
  },

  // GET /api/reports
  getReports: async (): Promise<GeneratedReport[]> => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/reports`);
      if (res.ok) {
        const data = await res.json();
        if (data && data.length > 0) return data;
      }
    } catch {
      // fallback
    }
    return MOCK_REPORTS;
  },

  // POST /api/cases
  createInvestigationCase: async (caseData: Partial<EmailInvestigationCase>): Promise<EmailInvestigationCase | null> => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/cases`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(caseData)
      });
      if (res.ok) {
        return await res.json();
      }
    } catch (err) {
      console.warn('[TRACE-X] Failed to create case via API:', err);
    }
    return null;
  },

  // POST /api/chat
  sendChatMessage: async (
    message: string,
    conversationId: string = 'default-session',
    context?: {
      current_page?: string;
      case_id?: string;
      case_data?: EmailInvestigationCase;
    }
  ): Promise<ChatMessageResponse> => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message,
          conversation_id: conversationId,
          context
        })
      });
      if (res.ok) {
        return await res.json();
      }
    } catch (err) {
      console.warn('[TRACE-X] Chat endpoint request failed, using local cyber-forensic fallback:', err);
    }

    // Client-side fallback if backend disconnected
    const q = message.toLowerCase();
    let respText = AI_PRESET_RESPONSES.default;
    let topic = 'general_triage';

    if (q.includes('why') || q.includes('malicious') || q.includes('classified') || q.includes('score')) {
      respText = AI_PRESET_RESPONSES.why;
      topic = 'risk_score_interpretation';
    } else if (q.includes('next') || q.includes('investigate') || q.includes('step') || q.includes('how to')) {
      respText = AI_PRESET_RESPONSES.investigate;
      topic = 'investigation_workflow';
    } else if (q.includes('dmarc') || q.includes('spf') || q.includes('dkim') || q.includes('auth')) {
      respText = AI_PRESET_RESPONSES.dmarc;
      topic = 'email_authentication_protocols';
    } else if (q.includes('attachment') || q.includes('zip') || q.includes('file')) {
      respText = AI_PRESET_RESPONSES.attachment;
      topic = 'malicious_attachments';
    } else if (q.includes('mitigate') || q.includes('action') || q.includes('block') || q.includes('fix')) {
      respText = AI_PRESET_RESPONSES.mitigation;
      topic = 'defensive_posture';
    } else if (q.includes('phish') || q.includes('fake') || q.includes('scam')) {
      respText = "### Evaluating Phishing Threats\n\nPhishing emails typically exhibit sender discrepancies (e.g., Return-Path mismatch), suspicious redirects, and urgent language demanding immediate compliance. You can upload this email into TRACE-X for automated SPF, DKIM, DMARC, and BGP routing verification.";
      topic = 'suspicious_email_assessment';
    }

    return {
      response: respText,
      conversation_id: conversationId,
      intent: 'general_cybersecurity',
      topic,
      confidence: 0.85,
      mode: 'rule_based_expert',
      provider: 'TRACE-X Local Client Fallback',
      suggested_questions: [
        'How do I analyze an email?',
        'What do SPF, DKIM, and DMARC mean?',
        'How do I verify evidence integrity?'
      ],
      actions: [
        { label: 'Analyze an Email', action: 'navigate_analyze' },
        { label: 'Open Dashboard', action: 'navigate_dashboard' }
      ],
      disclaimer: 'Offline mode: Operating via TRACE-X Local Cyber-Forensic Knowledge Base.'
    };
  },

  // POST /api/chat/clear
  clearChatHistory: async (conversationId: string = 'default-session'): Promise<boolean> => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/chat/clear`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ conversation_id: conversationId })
      });
      return res.ok;
    } catch {
      return false;
    }
  },

  // POST /api/ai-assistant (maintained for backward compatibility)
  askAiAssistant: async (query: string, caseData?: EmailInvestigationCase): Promise<string> => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/ai-assistant`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query, caseData })
      });
      if (res.ok) {
        const data = await res.json();
        if (data.response) return data.response;
      }
    } catch {
      // fallback
    }

    // Heuristic fallback
    const q = query.toLowerCase();
    if (q.includes('why') || q.includes('malicious') || q.includes('classified')) {
      return AI_PRESET_RESPONSES.why;
    }
    if (q.includes('next') || q.includes('investigate') || q.includes('step')) {
      return AI_PRESET_RESPONSES.investigate;
    }
    if (q.includes('dmarc') || q.includes('spf') || q.includes('dkim') || q.includes('auth')) {
      return AI_PRESET_RESPONSES.dmarc;
    }
    if (q.includes('attachment') || q.includes('zip') || q.includes('file')) {
      return AI_PRESET_RESPONSES.attachment;
    }
    if (q.includes('mitigate') || q.includes('action') || q.includes('block') || q.includes('fix')) {
      return AI_PRESET_RESPONSES.mitigation;
    }
    return AI_PRESET_RESPONSES.default;
  }
};

export interface ChatActionItem {
  label: string;
  action: string;
}

export interface ChatMessageResponse {
  response: string;
  conversation_id: string;
  intent: string;
  topic: string;
  confidence: number;
  mode: 'ai_llm' | 'rule_based_expert' | 'fallback_error';
  provider: string;
  suggested_questions: string[];
  actions: ChatActionItem[];
  disclaimer?: string;
  error?: string;
}
