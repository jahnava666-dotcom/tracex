import os
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session
from ..core.config import settings
from ..core.security import compute_sha256_bytes, compute_sha256_file, sanitize_filename, FORENSIC_INTEGRITY_DISCLAIMER
from ..models.evidence import EvidenceModel
from ..models.audit import AuditLogModel

def store_evidence_file(
    db: Session,
    file_bytes: bytes,
    filename: str,
    investigation_id: str,
    user_id: str = "analyst-soc",
    evidence_type: str = "RFC-822 EML File",
    description: Optional[str] = None
) -> Tuple[EvidenceModel, str]:
    """
    Store an evidence artifact in the local private evidence vault, compute SHA-256,
    and persist metadata to the database with audit record.
    """
    # 1. Compute authentic SHA-256 hash
    sha256_hash = compute_sha256_bytes(file_bytes)
    
    # 2. Sanitize and save to disk
    clean_name = sanitize_filename(filename)
    timestamp_prefix = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    stored_filename = f"{timestamp_prefix}_{sha256_hash[:12]}_{clean_name}"
    
    # Folder organized by investigation
    inv_dir = settings.EVIDENCE_VAULT_DIR / investigation_id
    inv_dir.mkdir(parents=True, exist_ok=True)
    target_path = inv_dir / stored_filename
    
    with open(target_path, "wb") as f:
        f.write(file_bytes)
        
    evidence_id = f"ev-{datetime.utcnow().strftime('%y%m')}-{int(datetime.utcnow().timestamp()) % 100000:05d}"
    
    metadata = {
        "fileName": clean_name,
        "fileSize": len(file_bytes),
        "mimeType": "message/rfc822" if clean_name.endswith(".eml") else "application/octet-stream",
        "storagePath": str(target_path),
        "collectedAt": datetime.utcnow().isoformat(),
        "verifiedAt": datetime.utcnow().isoformat(),
        "storageStatus": "persisted_vault",
        "forensicDisclaimer": FORENSIC_INTEGRITY_DISCLAIMER
    }
    
    # 3. Create database record
    db_item = EvidenceModel(
        id=evidence_id,
        investigation_id=investigation_id,
        user_id=user_id,
        evidence_type=evidence_type,
        description=description or f"Captured digital evidence payload for {investigation_id}",
        source=clean_name,
        sha256_hash=sha256_hash,
        integrity_status="verified",
        metadata_json=metadata,
        storage_path=str(target_path)
    )
    db.add(db_item)
    
    # 4. Append-only audit record
    audit_entry = AuditLogModel(
        user_id=user_id,
        action="EVIDENCE_COLLECTED",
        resource_type="EVIDENCE",
        resource_id=evidence_id,
        metadata_json={
            "investigationId": investigation_id,
            "fileName": clean_name,
            "sha256Hash": sha256_hash,
            "fileSize": len(file_bytes),
            "disclaimer": FORENSIC_INTEGRITY_DISCLAIMER
        }
    )
    db.add(audit_entry)
    db.commit()
    db.refresh(db_item)
    
    return db_item, sha256_hash

def verify_evidence_hash(
    db: Session,
    evidence_id: Optional[str],
    expected_hash: str,
    raw_bytes: Optional[bytes] = None,
    user_id: str = "analyst-soc"
) -> Dict[str, Any]:
    """
    Verify SHA-256 evidence integrity by recalculating hash from actual stored bytes.
    Does not falsely claim integrity if bytes are missing.
    """
    timestamp = datetime.utcnow().isoformat()
    computed_hash = None
    
    # If raw bytes provided directly
    if raw_bytes is not None:
        computed_hash = compute_sha256_bytes(raw_bytes)
    elif evidence_id:
        db_item = db.query(EvidenceModel).filter(EvidenceModel.id == evidence_id).first()
        if db_item and db_item.storage_path and os.path.exists(db_item.storage_path):
            computed_hash = compute_sha256_file(Path(db_item.storage_path))
        elif db_item:
            # Metadata exists but stored file was moved or is simulated
            return {
                "verified": False,
                "computedHash": None,
                "expectedHash": expected_hash,
                "timestamp": timestamp,
                "message": "Actual raw evidence payload bytes not accessible on disk to recalculate cryptographic hash.",
                "forensicDisclaimer": FORENSIC_INTEGRITY_DISCLAIMER
            }

    if not computed_hash:
        return {
            "verified": False,
            "computedHash": None,
            "expectedHash": expected_hash,
            "timestamp": timestamp,
            "message": "No payload bytes or valid evidence identifier provided for verification.",
            "forensicDisclaimer": FORENSIC_INTEGRITY_DISCLAIMER
        }

    is_verified = computed_hash.lower() == expected_hash.strip().lower()
    status_str = "verified" if is_verified else "tampered"
    
    message = (
        f"Cryptographic SHA-256 digest verified. Payload bytes match registered hash ({expected_hash[:16]}...)."
        if is_verified else
        f"INTEGRITY ALERT: Computed hash ({computed_hash[:16]}...) does NOT match expected hash ({expected_hash[:16]}...). Payload may have been tampered with."
    )

    # Update database record status if item exists
    if evidence_id:
        db_item = db.query(EvidenceModel).filter(EvidenceModel.id == evidence_id).first()
        if db_item:
            db_item.integrity_status = status_str
            current_meta = dict(db_item.metadata_json or {})
            current_meta["lastVerifiedAt"] = timestamp
            current_meta["verificationMessage"] = message
            db_item.metadata_json = current_meta
            
            # Audit log
            audit = AuditLogModel(
                user_id=user_id,
                action="EVIDENCE_INTEGRITY_VERIFIED",
                resource_type="EVIDENCE",
                resource_id=evidence_id,
                metadata_json={
                    "status": status_str,
                    "computedHash": computed_hash,
                    "expectedHash": expected_hash,
                    "verified": is_verified
                }
            )
            db.add(audit)
            db.commit()

    return {
        "verified": is_verified,
        "computedHash": computed_hash,
        "expectedHash": expected_hash,
        "timestamp": timestamp,
        "message": message,
        "forensicDisclaimer": FORENSIC_INTEGRITY_DISCLAIMER
    }
