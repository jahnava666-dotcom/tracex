import hashlib
import re
from pathlib import Path
from typing import Tuple

def compute_sha256_bytes(data: bytes) -> str:
    """Compute standard SHA-256 hex digest for binary data."""
    return hashlib.sha256(data).hexdigest()

def compute_sha256_file(filepath: Path) -> str:
    """Compute standard SHA-256 hex digest for a file stream."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent directory traversal and illegal characters.
    """
    clean = re.sub(r"[^a-zA-Z0-9._-]", "_", Path(filename).name)
    return clean[:120] if clean else "evidence_artifact.bin"

def validate_file_payload(filename: str, content: bytes, max_size: int = 25 * 1024 * 1024) -> Tuple[bool, str]:
    """Validate file size and structure."""
    if len(content) > max_size:
        return False, f"File size exceeds maximum allowed threshold of {max_size // (1024 * 1024)} MB."
    if len(content) == 0:
        return False, "Uploaded file payload is empty."
    return True, "Valid"

# Digital Forensic Legal Caveat
FORENSIC_INTEGRITY_DISCLAIMER = (
    "Cryptographic hash (SHA-256) verifies data integrity from the moment of capture, "
    "confirming that the payload has not been modified or tampered with in storage. "
    "A valid hash does not independently prove the provenance, authenticity, or legal admissibility "
    "of the originating sender or MTA relay."
)

GEOLOCATION_DISCLAIMER = (
    "IP geolocation represents network infrastructure routing and Autonomous System (ASN) intelligence. "
    "It does not prove or establish the physical location, identity, or personal device of an attacker."
)
