import os
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException, status
from sqlalchemy.orm import Session
from ...db.session import get_db
from ...core.config import settings
from ...core.security import validate_file_payload
from ...services.email_parser import parse_and_analyze_email
from ...services.evidence_service import store_evidence_file
from ...models.case import CaseModel
from ...models.audit import AuditLogModel
from ...models.threat_intel import ThreatIndicatorModel

router = APIRouter(tags=["Email Analysis"])

@router.post("/analyze-email")
async def analyze_email_endpoint(
    file: Optional[UploadFile] = File(None),
    rawText: Optional[str] = Form(None),
    isDemo: Optional[bool] = Form(False),
    db: Session = Depends(get_db)
):
    """
    Forensic Email Threat Ingestion Endpoint.
    Parses RFC-822 headers, analyzes SPF/DKIM/DMARC authentication, performs URL/domain extraction,
    correlates BGP transit hops, computes genuine SHA-256 evidence digests, and persists the investigation.
    """
    # 1. Check for demo mode request
    if isDemo and not file and not rawText:
        demo_case = db.query(CaseModel).filter(CaseModel.case_id == "CASE-1024").first()
        if demo_case:
            case_dict = demo_case.to_dict()
            case_dict["isSimulatedDemo"] = True
            return case_dict

    # 2. Extract content
    file_bytes: bytes = b""
    filename: Optional[str] = None

    if file:
        file_bytes = await file.read()
        filename = file.filename or "uploaded_forensic_artifact.eml"
        valid, msg = validate_file_payload(filename, file_bytes, settings.MAX_UPLOAD_SIZE_BYTES)
        if not valid:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
    elif rawText:
        file_bytes = rawText.encode("utf-8", errors="ignore")
        filename = "pasted_rfc822_headers.txt"
    else:
        # Fallback to CASE-1024 demo if completely empty
        demo_case = db.query(CaseModel).filter(CaseModel.case_id == "CASE-1024").first()
        if demo_case:
            case_dict = demo_case.to_dict()
            case_dict["isSimulatedDemo"] = True
            return case_dict
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide either an email file (.eml, .msg, .txt) or pasted raw RFC-822 header text."
        )

    # 3. Perform Deep Forensic Analysis
    try:
        case_dict = await parse_and_analyze_email(
            content=file_bytes,
            filename=filename,
            raw_text=rawText
        )
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Forensic parsing engine exception: {str(err)}"
        )

    # 4. Persist Investigation Case to Database
    db_case = CaseModel(
        case_id=case_dict["caseId"],
        email=case_dict["email"],
        date=case_dict["date"],
        received_time=case_dict["receivedTime"],
        subject=case_dict["subject"],
        from_address=case_dict["from"],
        reply_to=case_dict.get("replyTo", ""),
        return_path=case_dict.get("returnPath", ""),
        message_id=case_dict.get("messageId", ""),
        risk_score=case_dict["riskScore"],
        verdict=case_dict["verdict"],
        summary=case_dict["summary"],
        status=case_dict["status"],
        assigned_analyst=case_dict["assignedAnalyst"],
        auth=case_dict["auth"],
        signals=case_dict["signals"],
        infrastructure_hops=case_dict["infrastructureHops"],
        primary_infrastructure=case_dict["primaryInfrastructure"],
        timeline=case_dict["timeline"],
        threat_intel=case_dict["threatIntel"],
        iocs=case_dict["iocs"],
        recommended_actions=case_dict["recommendedActions"],
        raw_headers=case_dict.get("rawHeaders", ""),
        is_simulated_demo=False,
        geo_metadata=case_dict.get("geoMetadata", {})
    )
    db.add(db_case)

    # 5. Automatically Store Raw Captured Evidence Payload in Private Vault
    try:
        store_evidence_file(
            db=db,
            file_bytes=file_bytes,
            filename=filename,
            investigation_id=case_dict["caseId"],
            evidence_type="RFC-822 EML File" if filename.endswith(".eml") else "Captured Message Artifact",
            description=f"Raw evidence payload captured for {case_dict['caseId']}"
        )
    except Exception as e:
        print(f"[TRACE-X] Non-fatal evidence vault write warning: {e}")

    # 6. Record IOCs into threat intelligence pool
    for ind in case_dict.get("threatIntel", []):
        try:
            db.add(ThreatIndicatorModel(
                case_id=case_dict["caseId"],
                indicator=ind["indicator"],
                indicator_type=ind["type"],
                reputation=ind["reputation"],
                details=ind["details"],
                confidence=ind.get("confidence", 85),
                first_seen=datetime.utcnow().strftime("%Y-%m-%d")
            ))
        except Exception:
            pass

    # 7. Audit Logging
    audit = AuditLogModel(
        action="EMAIL_ANALYZED",
        resource_type="INVESTIGATION",
        resource_id=case_dict["caseId"],
        metadata_json={
            "subject": case_dict["subject"],
            "sender": case_dict["from"],
            "verdict": case_dict["verdict"],
            "riskScore": case_dict["riskScore"],
            "fileName": filename
        }
    )
    db.add(audit)
    db.commit()

    return case_dict
