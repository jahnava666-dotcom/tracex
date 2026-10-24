import os
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, Depends, UploadFile, File, Form, Query, HTTPException, status, Request
from fastapi.responses import FileResponse, PlainTextResponse
from sqlalchemy.orm import Session
from ...db.session import get_db
from ...core.config import settings
from ...core.security import validate_file_payload, compute_sha256_bytes
from ...services.evidence_service import store_evidence_file, verify_evidence_hash
from ...models.evidence import EvidenceModel
from ...models.audit import AuditLogModel
from ...schemas.forensics import VerificationResult, VerifyHashRequest

router = APIRouter(tags=["Digital Evidence Vault"])

@router.get("/evidence")
def list_evidence(
    investigation_id: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """List all digital evidence items in the forensic vault."""
    query = db.query(EvidenceModel).order_by(EvidenceModel.created_at.desc())
    if investigation_id:
        query = query.filter(EvidenceModel.investigation_id == investigation_id)
    records = query.all()
    return [r.to_dict() for r in records]

@router.post("/evidence", status_code=status.HTTP_201_CREATED)
async def upload_evidence(
    file: UploadFile = File(...),
    investigation_id: str = Form("CASE-1024"),
    evidence_type: str = Form("RFC-822 EML File"),
    description: Optional[str] = Form("Manual evidence capture"),
    db: Session = Depends(get_db)
):
    """
    Ingest a digital evidence artifact, compute genuine SHA-256, and store in private vault.
    """
    file_bytes = await file.read()
    valid, msg = validate_file_payload(file.filename or "evidence.bin", file_bytes, settings.MAX_UPLOAD_SIZE_BYTES)
    if not valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    evidence_item, sha256_hash = store_evidence_file(
        db=db,
        file_bytes=file_bytes,
        filename=file.filename or "evidence_file.bin",
        investigation_id=investigation_id,
        evidence_type=evidence_type,
        description=description
    )
    return evidence_item.to_dict()

@router.post("/evidence/verify", response_model=VerificationResult)
async def verify_evidence(
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Verify digital evidence integrity by calculating authentic SHA-256 hash.
    Supports application/json and multipart/form-data.
    """
    content_type = request.headers.get("content-type", "")
    target_expected = None
    target_id = None
    raw_bytes = None

    if "application/json" in content_type:
        body = await request.json()
        target_expected = body.get("expectedHash")
        target_id = body.get("evidenceId")
        if body.get("rawContent"):
            raw_bytes = body["rawContent"].encode("utf-8")
    else:
        form = await request.form()
        target_expected = form.get("expected_hash") or form.get("expectedHash")
        target_id = form.get("evidence_id") or form.get("evidenceId")
        uploaded_file = form.get("file")
        if uploaded_file and hasattr(uploaded_file, "read"):
            raw_bytes = await uploaded_file.read()

    if not target_expected:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="expectedHash is required for cryptographic integrity verification."
        )

    result = verify_evidence_hash(
        db=db,
        evidence_id=str(target_id) if target_id else None,
        expected_hash=str(target_expected),
        raw_bytes=raw_bytes
    )
    return result

@router.get("/evidence/{evidence_id}/download")
def download_evidence(
    evidence_id: str,
    db: Session = Depends(get_db)
):
    """Securely download an evidence artifact from the private vault."""
    item = db.query(EvidenceModel).filter(EvidenceModel.id == evidence_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Evidence item not found.")

    if item.storage_path and os.path.exists(item.storage_path):
        filename = item.metadata_json.get("fileName", f"{evidence_id}.bin")
        return FileResponse(
            path=item.storage_path,
            filename=filename,
            media_type="application/octet-stream"
        )
    else:
        # Generate downloadable text export of evidence metadata
        text_export = (
            f"TRACE-X DIGITAL FORENSICS EVIDENCE EXPORT\n"
            f"ID:                 {item.id}\n"
            f"Investigation:      {item.investigation_id}\n"
            f"Type:               {item.evidence_type}\n"
            f"SHA-256 Hash:       {item.sha256_hash}\n"
            f"Integrity Status:   {item.integrity_status}\n"
            f"Collected:          {item.created_at}\n"
            f"Source:             {item.source}\n"
        )
        return PlainTextResponse(
            content=text_export,
            headers={"Content-Disposition": f"attachment; filename={item.id}_export.txt"}
        )

@router.get("/audit-logs")
def get_audit_trail(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    """Retrieve immutable forensic audit trail logs."""
    logs = db.query(AuditLogModel).order_by(AuditLogModel.created_at.desc()).limit(limit).all()
    return [l.to_dict() for l in logs]
