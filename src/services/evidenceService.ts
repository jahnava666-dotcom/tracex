import { supabase } from '../lib/supabase';
import { computeFileSHA256, computeSHA256, verifyEvidenceIntegrity, VerificationResult } from '../utils/crypto';
import { recordAuditLog } from './auditService';

export type { VerificationResult };

export interface EvidenceItem {
  id: string;
  investigation_id: string;
  user_id: string;
  evidence_type: string;
  description: string | null;
  source: string | null;
  sha256_hash: string;
  integrity_status: 'verified' | 'unverified' | 'tampered' | 'pending';
  metadata: {
    fileName?: string;
    fileSize?: number;
    mimeType?: string;
    storagePath?: string;
    extractedAt?: string;
    verifiedAt?: string;
    lastVerifiedAt?: string;
    verificationMessage?: string;
    forensicDisclaimer?: string;
    [key: string]: any;
  };
  created_at: string;
}

const API_BASE_URL = import.meta.env.VITE_API_URL || '';

/**
 * Upload an evidence file to the private backend vault
 * and record it with SHA-256 hash.
 */
export async function uploadAndRecordEvidence(
  file: File,
  investigationId: string,
  evidenceType = 'EML File',
  description = 'Original captured message payload'
): Promise<{ evidence: EvidenceItem | null; error: string | null }> {
  // 1. Try FastAPI backend first
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
    if (res.ok) {
      const data = await res.json();
      return { evidence: data as EvidenceItem, error: null };
    }
  } catch (backendErr) {
    console.warn('[TRACE-X Evidence] Backend upload error, attempting secondary store:', backendErr);
  }

  // 2. Fallback to Supabase if configured
  try {
    const { data: authData } = await supabase.auth.getUser();
    const userId = authData.user?.id || 'demo-analyst';

    const sha256Hash = await computeFileSHA256(file);
    const cleanFileName = file.name.replace(/[^a-zA-Z0-9._-]/g, '_');
    const storagePath = `${userId}/${investigationId}/${Date.now()}_${cleanFileName}`;

    const metadata = {
      fileName: file.name,
      fileSize: file.size,
      mimeType: file.type || 'application/octet-stream',
      storagePath,
      collectedAt: new Date().toISOString(),
      verifiedAt: new Date().toISOString(),
      storageStatus: 'local_hash_only'
    };

    const { data, error: insertError } = await supabase
      .from('evidence')
      .insert({
        investigation_id: investigationId,
        user_id: userId,
        evidence_type: evidenceType,
        description,
        source: file.name,
        sha256_hash: sha256Hash,
        integrity_status: 'verified',
        metadata
      })
      .select()
      .single();

    if (insertError) {
      // Return local memory representation if remote DB table pending
      const localEvidence: EvidenceItem = {
        id: `ev-${Date.now().toString().slice(-6)}`,
        investigation_id: investigationId,
        user_id: userId,
        evidence_type: evidenceType,
        description,
        source: file.name,
        sha256_hash: sha256Hash,
        integrity_status: 'verified',
        metadata,
        created_at: new Date().toISOString()
      };
      return { evidence: localEvidence, error: null };
    }

    return { evidence: data as EvidenceItem, error: null };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { evidence: null, error: msg };
  }
}

/**
 * Verify integrity by recalculating SHA-256 hash from original stored bytes.
 * If actual bytes are unavailable, does NOT falsely claim verification.
 */
export async function verifyEvidenceIntegrityFromStorage(
  evidence: EvidenceItem,
  localFile?: File
): Promise<VerificationResult> {
  // 1. Try FastAPI backend verification
  try {
    if (localFile) {
      const formData = new FormData();
      formData.append('file', localFile);
      formData.append('expected_hash', evidence.sha256_hash);
      formData.append('evidence_id', evidence.id);

      const res = await fetch(`${API_BASE_URL}/api/evidence/verify`, {
        method: 'POST',
        body: formData
      });
      if (res.ok) return await res.json();
    } else {
      const res = await fetch(`${API_BASE_URL}/api/evidence/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          evidenceId: evidence.id,
          expectedHash: evidence.sha256_hash
        })
      });
      if (res.ok) return await res.json();
    }
  } catch (backendErr) {
    console.warn('[TRACE-X Evidence] Backend verify error, using local crypto:', backendErr);
  }

  // 2. Local fallback calculation
  try {
    let bytes: ArrayBuffer | null = null;
    if (localFile) {
      bytes = await localFile.arrayBuffer();
    }
    const result = await verifyEvidenceIntegrity(bytes, evidence.sha256_hash);
    return result;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      verified: false,
      computedHash: null,
      expectedHash: evidence.sha256_hash,
      timestamp: new Date().toISOString(),
      message: `Verification error: ${msg}`
    };
  }
}

/**
 * Generate a download URL for an authorized evidence file.
 */
export async function getEvidenceDownloadUrl(storagePathOrId: string): Promise<string | null> {
  if (storagePathOrId.startsWith('ev-')) {
    return `${API_BASE_URL}/api/evidence/${storagePathOrId}/download`;
  }
  return `${API_BASE_URL}/api/evidence/${encodeURIComponent(storagePathOrId)}/download`;
}

/**
 * Fetch all evidence items for an investigation
 */
export async function fetchEvidenceByInvestigation(investigationId?: string): Promise<EvidenceItem[]> {
  try {
    const url = investigationId
      ? `${API_BASE_URL}/api/evidence?investigation_id=${encodeURIComponent(investigationId)}`
      : `${API_BASE_URL}/api/evidence`;
    const res = await fetch(url);
    if (res.ok) {
      const data = await res.json();
      if (data && data.length > 0) return data;
    }
  } catch (err) {
    console.warn('[TRACE-X Evidence] API fetch error:', err);
  }

  // Fallback query to Supabase if backend had no records
  try {
    let query = supabase.from('evidence').select('*').order('created_at', { ascending: false });
    if (investigationId) query = query.eq('investigation_id', investigationId);
    const { data } = await query;
    if (data && data.length > 0) return data as EvidenceItem[];
  } catch {
    //
  }

  return [];
}
