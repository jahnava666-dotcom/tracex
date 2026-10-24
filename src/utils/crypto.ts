/**
 * Cryptographic utility for TRACE-X Digital Forensics
 * Generates and verifies SHA-256 hashes from actual binary bytes using the Web Crypto API.
 */

export async function computeSHA256(data: ArrayBuffer | Uint8Array | string): Promise<string> {
  let buffer: ArrayBuffer;

  if (typeof data === 'string') {
    buffer = new TextEncoder().encode(data).buffer;
  } else if (data instanceof Uint8Array) {
    buffer = data.buffer as ArrayBuffer;
  } else {
    buffer = data;
  }

  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
}

/**
 * Computes SHA-256 from a File object
 */
export async function computeFileSHA256(file: File): Promise<string> {
  const arrayBuffer = await file.arrayBuffer();
  return computeSHA256(arrayBuffer);
}

export interface VerificationResult {
  verified: boolean;
  computedHash: string | null;
  expectedHash: string;
  timestamp: string;
  message: string;
  forensicDisclaimer?: string;
}

/**
 * Verifies evidence integrity by recalculating the SHA-256 hash from the actual evidence bytes.
 * If bytes are unavailable, integrity CANNOT be verified.
 */
export async function verifyEvidenceIntegrity(
  actualBytes: ArrayBuffer | null | undefined,
  expectedHash: string
): Promise<VerificationResult> {
  const timestamp = new Date().toISOString();

  if (!actualBytes) {
    return {
      verified: false,
      computedHash: null,
      expectedHash,
      timestamp,
      message: 'Integrity verification failed: Original evidence bytes unavailable. Database record alone cannot prove integrity.'
    };
  }

  const computedHash = await computeSHA256(actualBytes);
  const verified = computedHash.toLowerCase() === expectedHash.toLowerCase();

  return {
    verified,
    computedHash,
    expectedHash,
    timestamp,
    message: verified
      ? 'Integrity verified: SHA-256 hash matches the original bitstream.'
      : 'INTEGRITY MISMATCH DETECTED: The computed hash differs from the stored chain of custody hash.'
  };
}
