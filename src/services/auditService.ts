import { supabase } from '../lib/supabase';

export interface AuditLogEntry {
  id: string;
  user_id: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  metadata: Record<string, any>;
  created_at: string;
}

const API_BASE_URL = import.meta.env.VITE_API_URL || '';

/**
 * Append-only audit logger for TRACE-X Digital Forensics
 */
export async function recordAuditLog(
  action: string,
  resourceType: string,
  resourceId?: string | null,
  metadata: Record<string, any> = {}
): Promise<AuditLogEntry | null> {
  try {
    const { data: authData } = await supabase.auth.getUser();
    const userId = authData.user?.id || 'analyst-soc';

    const { data, error } = await supabase
      .from('audit_logs')
      .insert({
        user_id: userId,
        action,
        resource_type: resourceType,
        resource_id: resourceId ?? null,
        metadata: {
          ...metadata,
          userAgent: navigator.userAgent,
          loggedAt: new Date().toISOString()
        }
      })
      .select()
      .maybeSingle();

    if (!error && data) {
      return data as AuditLogEntry;
    }
  } catch {
    //
  }
  return null;
}

/**
 * Fetch append-only audit trail logs
 */
export async function fetchAuditLogs(limit = 50): Promise<AuditLogEntry[]> {
  // 1. Try FastAPI backend audit-logs
  try {
    const res = await fetch(`${API_BASE_URL}/api/audit-logs?limit=${limit}`);
    if (res.ok) {
      const data: AuditLogEntry[] = await res.json();
      if (data && data.length > 0) return data;
    }
  } catch (err) {
    console.warn('[TRACE-X Audit] API fetch error:', err);
  }

  // 2. Try Supabase fallback
  try {
    const { data, error } = await supabase
      .from('audit_logs')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(limit);

    if (!error && data) {
      return data as AuditLogEntry[];
    }
  } catch {
    //
  }

  return [];
}
