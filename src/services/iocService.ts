import { supabase } from '../lib/supabase';
import { recordAuditLog } from './auditService';
import { ThreatIntelligenceIndicator } from '../types/forensics';

export interface IOCRecord {
  id: string;
  investigation_id: string;
  indicator_type: 'Domain' | 'IP' | 'URL' | 'Attachment' | 'SHA-256';
  indicator_value: string;
  risk_level: 'Clean' | 'Suspicious' | 'Malicious' | 'High' | 'Critical';
  metadata: {
    source?: string;
    details?: string;
    confidence?: number;
    firstSeen?: string;
    isSimulated?: boolean;
    [key: string]: any;
  };
  created_at: string;
}

const API_BASE_URL = import.meta.env.VITE_API_URL || '';

/**
 * Fetch IOCs from backend for a specific investigation
 */
export async function fetchIocsForInvestigation(investigationId: string): Promise<IOCRecord[]> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/threat-intelligence?case_id=${encodeURIComponent(investigationId)}`);
    if (res.ok) {
      const data: ThreatIntelligenceIndicator[] = await res.json();
      return data.map((d) => ({
        id: d.id || d.indicator,
        investigation_id: investigationId,
        indicator_type: d.type as any,
        indicator_value: d.indicator,
        risk_level: d.reputation as any,
        metadata: {
          details: d.details,
          confidence: d.confidence,
          firstSeen: d.firstSeen
        },
        created_at: new Date().toISOString()
      }));
    }
  } catch (err) {
    console.warn('[TRACE-X IOC] Backend fetch error:', err);
  }

  // Supabase fallback
  try {
    const { data, error } = await supabase
      .from('indicators_of_compromise')
      .select('*')
      .eq('investigation_id', investigationId)
      .order('created_at', { ascending: false });

    if (!error && data) return data as IOCRecord[];
  } catch {
    //
  }

  return [];
}

/**
 * Fetch all IOCs across user's authorized investigations
 */
export async function fetchAllUserIocs(): Promise<IOCRecord[]> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/threat-intelligence`);
    if (res.ok) {
      const data: ThreatIntelligenceIndicator[] = await res.json();
      return data.map((d) => ({
        id: d.id || d.indicator,
        investigation_id: 'CASE-1024',
        indicator_type: d.type as any,
        indicator_value: d.indicator,
        risk_level: d.reputation as any,
        metadata: {
          details: d.details,
          confidence: d.confidence,
          firstSeen: d.firstSeen
        },
        created_at: new Date().toISOString()
      }));
    }
  } catch (err) {
    console.warn('[TRACE-X IOC] Backend fetch all error:', err);
  }

  // Supabase fallback
  try {
    const { data, error } = await supabase
      .from('indicators_of_compromise')
      .select('*')
      .order('created_at', { ascending: false });

    if (!error && data) return data as IOCRecord[];
  } catch {
    //
  }

  return [];
}

/**
 * Add an IOC to an investigation
 */
export async function createIocRecord(
  investigationId: string,
  indicator: {
    indicator_type: 'Domain' | 'IP' | 'URL' | 'Attachment' | 'SHA-256';
    indicator_value: string;
    risk_level: 'Clean' | 'Suspicious' | 'Malicious' | 'High' | 'Critical';
    metadata?: Record<string, any>;
  }
): Promise<{ ioc: IOCRecord | null; error: string | null }> {
  // 1. Try FastAPI backend
  try {
    const res = await fetch(`${API_BASE_URL}/api/threat-intelligence`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        indicator_type: indicator.indicator_type,
        indicator_value: indicator.indicator_value,
        risk_level: indicator.risk_level,
        case_id: investigationId,
        metadata: indicator.metadata || {}
      })
    });
    if (res.ok) {
      const created: ThreatIntelligenceIndicator = await res.json();
      return {
        ioc: {
          id: created.id || created.indicator,
          investigation_id: investigationId,
          indicator_type: created.type as any,
          indicator_value: created.indicator,
          risk_level: created.reputation as any,
          metadata: {
            details: created.details,
            confidence: created.confidence,
            firstSeen: created.firstSeen
          },
          created_at: new Date().toISOString()
        },
        error: null
      };
    }
  } catch (backendErr) {
    console.warn('[TRACE-X IOC] Backend create error:', backendErr);
  }

  // 2. Try Supabase fallback
  try {
    const { data, error } = await supabase
      .from('indicators_of_compromise')
      .upsert(
        {
          investigation_id: investigationId,
          indicator_type: indicator.indicator_type,
          indicator_value: indicator.indicator_value,
          risk_level: indicator.risk_level,
          metadata: indicator.metadata || {}
        },
        { onConflict: 'investigation_id,indicator_type,indicator_value' }
      )
      .select()
      .single();

    if (!error && data) {
      return { ioc: data as IOCRecord, error: null };
    }
  } catch {
    //
  }

  // Memory fallback
  return {
    ioc: {
      id: `ioc-${Date.now()}`,
      investigation_id: investigationId,
      indicator_type: indicator.indicator_type,
      indicator_value: indicator.indicator_value,
      risk_level: indicator.risk_level,
      metadata: indicator.metadata || {},
      created_at: new Date().toISOString()
    },
    error: null
  };
}

/**
 * Delete an IOC record
 */
export async function deleteIocRecord(iocId: string): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/threat-intelligence/${iocId}`, {
      method: 'DELETE'
    });
    if (res.ok) return true;
  } catch {
    //
  }

  try {
    const { error } = await supabase
      .from('indicators_of_compromise')
      .delete()
      .eq('id', iocId);
    return !error;
  } catch {
    return false;
  }
}

/**
 * Map IOCRecords to UI ThreatIntelligenceIndicator format
 */
export function mapIocToThreatIntel(ioc: IOCRecord): ThreatIntelligenceIndicator {
  let mappedReputation: 'Clean' | 'Suspicious' | 'Malicious' = 'Suspicious';
  if (ioc.risk_level === 'Clean') mappedReputation = 'Clean';
  else if (ioc.risk_level === 'Malicious' || ioc.risk_level === 'Critical' || ioc.risk_level === 'High')
    mappedReputation = 'Malicious';

  return {
    id: ioc.id,
    indicator: ioc.indicator_value,
    type: ioc.indicator_type,
    reputation: mappedReputation,
    details: ioc.metadata?.details || `${ioc.indicator_type} correlated in case investigation`,
    confidence: ioc.metadata?.confidence || 88,
    firstSeen: ioc.metadata?.firstSeen || ioc.created_at.split('T')[0]
  };
}
