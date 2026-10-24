import { supabase } from '../lib/supabase';
import { EmailInvestigationCase, ThreatVerdict } from '../types/forensics';
import { RECENT_INVESTIGATIONS, CASE_1024 } from '../data/mockData';
import { recordAuditLog } from './auditService';
import { fetchIocsForInvestigation, createIocRecord } from './iocService';
import { uploadAndRecordEvidence } from './evidenceService';

export interface DbInvestigation {
  id: string;
  user_id: string;
  case_number: string;
  title: string;
  description: string | null;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  status: 'Open' | 'Under Review' | 'Mitigated' | 'Closed';
  created_at: string;
  updated_at: string;
}

const API_BASE_URL = import.meta.env.VITE_API_URL || '';

export async function fetchInvestigations(): Promise<{
  cases: EmailInvestigationCase[];
  isDemoFallback: boolean;
}> {
  // 1. Try FastAPI backend first
  try {
    const res = await fetch(`${API_BASE_URL}/api/cases`);
    if (res.ok) {
      const cases: EmailInvestigationCase[] = await res.json();
      if (cases && cases.length > 0) {
        return { cases, isDemoFallback: false };
      }
    }
  } catch (backendErr) {
    console.warn('[TRACE-X] Backend API fetch error, checking secondary sources:', backendErr);
  }

  // 2. Try Supabase if authenticated
  try {
    const { data: authData } = await supabase.auth.getUser();
    if (!authData.user) {
      return {
        cases: RECENT_INVESTIGATIONS.map((c) => ({ ...c, isSimulatedDemo: true })),
        isDemoFallback: true
      };
    }

    // Query investigations from Supabase
    const { data: invData, error: invError } = await supabase
      .from('investigations')
      .select('*')
      .order('created_at', { ascending: false });

    if (invError || !invData || invData.length === 0) {
      return {
        cases: RECENT_INVESTIGATIONS.map((c) => ({ ...c, isSimulatedDemo: true })),
        isDemoFallback: true
      };
    }

    // Also fetch email analyses to restore complete forensic payloads
    const { data: analysisData } = await supabase
      .from('email_analyses')
      .select('*')
      .order('created_at', { ascending: false });

    const analysisMap = new Map<string, any>();
    (analysisData || []).forEach((item) => {
      // Index by subject or stored caseId
      const results = item.analysis_results as any;
      if (results?.caseId) {
        analysisMap.set(results.caseId, results);
      }
    });

    const cases: EmailInvestigationCase[] = invData.map((inv) => {
      const storedCase = analysisMap.get(inv.case_number);
      if (storedCase) {
        return {
          ...storedCase,
          status: inv.status,
          date: new Date(inv.created_at).toLocaleString(),
          isSimulatedDemo: false
        };
      }

      // Reconstruct case from investigation row
      let verdict: ThreatVerdict = 'Suspicious';
      let riskScore = 50;
      if (inv.severity === 'Critical') {
        verdict = 'Critical Threat';
        riskScore = 90;
      } else if (inv.severity === 'High') {
        verdict = 'High Risk';
        riskScore = 75;
      } else if (inv.severity === 'Low') {
        verdict = 'Likely Safe';
        riskScore = 20;
      }

      return {
        caseId: inv.case_number,
        email: inv.title.includes('<') ? inv.title : 'security@analyzed-threat.org',
        date: new Date(inv.created_at).toLocaleDateString(),
        receivedTime: new Date(inv.created_at).toLocaleTimeString() + ' UTC',
        subject: inv.title,
        from: inv.title,
        replyTo: 'noreply@analyzed-threat.org',
        returnPath: '<bounce@analyzed-threat.org>',
        messageId: `<${inv.case_number.toLowerCase()}@tracex-soc.local>`,
        riskScore,
        verdict,
        summary: inv.description || 'Forensic investigation case cataloged in TRACE-X.',
        status: inv.status,
        assignedAnalyst: 'Alex Carter (SOC Analyst)',
        auth: CASE_1024.auth,
        signals: CASE_1024.signals,
        infrastructureHops: CASE_1024.infrastructureHops,
        primaryInfrastructure: CASE_1024.primaryInfrastructure,
        timeline: CASE_1024.timeline,
        threatIntel: [],
        iocs: { domains: [], ips: [], urls: [], attachments: [] },
        recommendedActions: CASE_1024.recommendedActions,
        rawHeaders: 'Subject: ' + inv.title,
        isSimulatedDemo: false
      };
    });

    return { cases, isDemoFallback: false };
  } catch (err) {
    console.warn('[TRACE-X] Error in fetchInvestigations, falling back to demo:', err);
    return {
      cases: RECENT_INVESTIGATIONS.map((c) => ({ ...c, isSimulatedDemo: true })),
      isDemoFallback: true
    };
  }
}

/**
 * Save an investigation and its associated email analysis to Supabase
 */
export async function saveInvestigationToDb(
  caseData: EmailInvestigationCase,
  evidenceFile?: File
): Promise<{ success: boolean; error: string | null }> {
  try {
    const { data: authData } = await supabase.auth.getUser();
    const userId = authData.user?.id;
    if (!userId) {
      return { success: false, error: 'User must be authenticated to persist investigations' };
    }

    let severity: 'Low' | 'Medium' | 'High' | 'Critical' = 'Medium';
    if (caseData.verdict === 'Critical Threat') severity = 'Critical';
    else if (caseData.verdict === 'High Risk') severity = 'High';
    else if (caseData.verdict === 'Likely Safe') severity = 'Low';

    // 1. Upsert Investigation
    const { data: invRow, error: invError } = await supabase
      .from('investigations')
      .upsert(
        {
          case_number: caseData.caseId,
          user_id: userId,
          title: caseData.subject || `Investigation ${caseData.caseId}`,
          description: caseData.summary,
          severity,
          status: caseData.status || 'Open'
        },
        { onConflict: 'case_number' }
      )
      .select()
      .single();

    if (invError) {
      return { success: false, error: invError.message };
    }

    // 2. Insert Email Analysis
    const { error: analysisError } = await supabase
      .from('email_analyses')
      .insert({
        user_id: userId,
        sender: caseData.from || caseData.email,
        subject: caseData.subject,
        threat_type: caseData.verdict,
        risk_score: caseData.riskScore,
        confidence: 90,
        status: 'completed',
        analysis_results: caseData
      });

    if (analysisError) {
      console.warn('[TRACE-X Analysis] Analysis insert error:', analysisError.message);
    }

    // 3. Persist IOCs into indicators_of_compromise table
    if (caseData.iocs) {
      let iocRisk: 'Clean' | 'Suspicious' | 'Malicious' | 'High' | 'Critical' = 'Suspicious';
      if (severity === 'Critical') iocRisk = 'Critical';
      else if (severity === 'High') iocRisk = 'High';
      else if (severity === 'Low') iocRisk = 'Clean';

      for (const dom of caseData.iocs.domains || []) {
        await createIocRecord(invRow.id, {
          indicator_type: 'Domain',
          indicator_value: dom,
          risk_level: iocRisk,
          metadata: { source: 'Email Header & Body Parser' }
        });
      }
      for (const ip of caseData.iocs.ips || []) {
        await createIocRecord(invRow.id, {
          indicator_type: 'IP',
          indicator_value: ip,
          risk_level: iocRisk,
          metadata: { source: 'Received Relay Hop Analysis' }
        });
      }
      for (const url of caseData.iocs.urls || []) {
        await createIocRecord(invRow.id, {
          indicator_type: 'URL',
          indicator_value: url,
          risk_level: iocRisk,
          metadata: { source: 'Extracted Phishing Link' }
        });
      }
      for (const att of caseData.iocs.attachments || []) {
        await createIocRecord(invRow.id, {
          indicator_type: 'SHA-256',
          indicator_value: att.sha256,
          risk_level: iocRisk,
          metadata: { filename: att.filename, size: att.size, verdict: att.verdict }
        });
      }
    }

    // 4. Upload evidence file if provided
    if (evidenceFile) {
      await uploadAndRecordEvidence(
        evidenceFile,
        invRow.id,
        'Original Message File',
        `Evidence file: ${evidenceFile.name}`
      );
    }

    // 5. Append-only audit record
    await recordAuditLog('INVESTIGATION_CREATED', 'INVESTIGATION', invRow.id, {
      caseNumber: caseData.caseId,
      verdict: caseData.verdict,
      riskScore: caseData.riskScore
    });

    return { success: true, error: null };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, error: msg };
  }
}

/**
 * Update investigation status in Supabase (Open, Under Review, Mitigated, Closed)
 */
export async function updateInvestigationStatusInDb(
  caseNumber: string,
  newStatus: 'Open' | 'Under Review' | 'Mitigated' | 'Closed'
): Promise<boolean> {
  // 1. Try FastAPI backend
  try {
    const res = await fetch(`${API_BASE_URL}/api/cases/${caseNumber}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus })
    });
    if (res.ok) {
      return true;
    }
  } catch (err) {
    console.warn('[TRACE-X] Backend status update error:', err);
  }

  // 2. Try Supabase
  try {
    const { error } = await supabase
      .from('investigations')
      .update({ status: newStatus })
      .eq('case_number', caseNumber);

    if (error) {
      console.warn('[TRACE-X] Update status error:', error.message);
      return false;
    }

    await recordAuditLog('INVESTIGATION_STATUS_UPDATED', 'INVESTIGATION', caseNumber, {
      newStatus
    });

    return true;
  } catch {
    return false;
  }
}

/**
 * Delete an investigation from Supabase / Backend
 */
export async function deleteInvestigationFromDb(caseNumber: string): Promise<boolean> {
  // 1. Try FastAPI backend
  try {
    const res = await fetch(`${API_BASE_URL}/api/cases/${caseNumber}`, {
      method: 'DELETE'
    });
    if (res.ok) {
      return true;
    }
  } catch (err) {
    console.warn('[TRACE-X] Backend case deletion error:', err);
  }

  // 2. Try Supabase
  try {
    const { error } = await supabase
      .from('investigations')
      .delete()
      .eq('case_number', caseNumber);

    if (error) {
      console.warn('[TRACE-X] Delete investigation error:', error.message);
      return false;
    }

    await recordAuditLog('INVESTIGATION_DELETED', 'INVESTIGATION', caseNumber);
    return true;
  } catch {
    return false;
  }
}
