from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from ...db.session import get_db
from ...models.case import CaseModel
from ...models.audit import AuditLogModel
from ...schemas.forensics import UpdateStatusRequest

router = APIRouter(tags=["Investigation Cases"])

@router.get("/cases")
def list_investigation_cases(
    db: Session = Depends(get_db)
):
    """List all recorded investigation cases ordered by creation date."""
    cases = db.query(CaseModel).order_by(CaseModel.created_at.desc()).all()
    return [c.to_dict() for c in cases]

@router.post("/cases", status_code=status.HTTP_201_CREATED)
def create_investigation_case(
    payload: dict,
    db: Session = Depends(get_db)
):
    """
    Directly ingest or persist an investigation case record.
    Supports creating new cases and saving customized investigations.
    """
    case_id = payload.get("caseId") or f"CASE-{int(datetime.utcnow().timestamp()) % 10000}"
    
    # Check if case exists already
    existing = db.query(CaseModel).filter(CaseModel.case_id.ilike(case_id)).first()
    if existing:
        # Update existing
        if "subject" in payload: existing.subject = payload["subject"]
        if "verdict" in payload: existing.verdict = payload["verdict"]
        if "riskScore" in payload: existing.risk_score = payload["riskScore"]
        if "status" in payload: existing.status = payload["status"]
        if "summary" in payload: existing.summary = payload["summary"]
        if "auth" in payload: existing.auth = payload["auth"]
        if "signals" in payload: existing.signals = payload["signals"]
        if "infrastructureHops" in payload: existing.infrastructure_hops = payload["infrastructureHops"]
        if "primaryInfrastructure" in payload: existing.primary_infrastructure = payload["primaryInfrastructure"]
        if "threatIntel" in payload: existing.threat_intel = payload["threatIntel"]
        if "iocs" in payload: existing.iocs = payload["iocs"]
        if "recommendedActions" in payload: existing.recommended_actions = payload["recommendedActions"]
        db.commit()
        db.refresh(existing)
        return existing.to_dict()

    new_case = CaseModel(
        case_id=case_id,
        email=payload.get("email") or payload.get("from") or "security@analyzed-threat.org",
        date=payload.get("date") or datetime.utcnow().strftime("%b %d, %Y, %I:%M %p"),
        received_time=payload.get("receivedTime") or datetime.utcnow().strftime("%H:%M:%S UTC"),
        subject=payload.get("subject") or f"Investigation {case_id}",
        from_address=payload.get("from") or payload.get("from_address") or payload.get("email") or "unknown@sender.org",
        reply_to=payload.get("replyTo") or "",
        return_path=payload.get("returnPath") or "",
        message_id=payload.get("messageId") or f"<{case_id.lower()}@tracex.local>",
        risk_score=payload.get("riskScore", 50),
        verdict=payload.get("verdict", "Suspicious"),
        summary=payload.get("summary") or "Investigation case cataloged in TRACE-X.",
        status=payload.get("status", "Open"),
        assigned_analyst=payload.get("assignedAnalyst", "Alex Carter (SOC Tier 2)"),
        auth=payload.get("auth", {}),
        signals=payload.get("signals", []),
        infrastructure_hops=payload.get("infrastructureHops", []),
        primary_infrastructure=payload.get("primaryInfrastructure", {}),
        timeline=payload.get("timeline", []),
        threat_intel=payload.get("threatIntel", []),
        iocs=payload.get("iocs", {"domains": [], "ips": [], "urls": [], "attachments": []}),
        recommended_actions=payload.get("recommendedActions", []),
        raw_headers=payload.get("rawHeaders", ""),
        is_simulated_demo=payload.get("isSimulatedDemo", False),
        geo_metadata=payload.get("geoMetadata", {})
    )
    db.add(new_case)

    audit = AuditLogModel(
        action="CASE_RECORDED",
        resource_type="INVESTIGATION",
        resource_id=case_id,
        metadata_json={
            "subject": new_case.subject,
            "verdict": new_case.verdict,
            "riskScore": new_case.risk_score
        }
    )
    db.add(audit)
    db.commit()
    db.refresh(new_case)
    return new_case.to_dict()

@router.get("/cases/{case_id}")
def get_investigation_case(
    case_id: str,
    db: Session = Depends(get_db)
):
    """Retrieve detailed forensic telemetry for a specific investigation case."""
    case = db.query(CaseModel).filter(CaseModel.case_id.ilike(case_id)).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation case '{case_id}' not found."
        )
    return case.to_dict()

@router.patch("/cases/{case_id}/status")
def update_case_status(
    case_id: str,
    payload: UpdateStatusRequest,
    db: Session = Depends(get_db)
):
    """Update investigation case status ('Open' | 'Under Review' | 'Mitigated' | 'Closed')."""
    valid_statuses = {"Open", "Under Review", "Mitigated", "Closed"}
    if payload.status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status '{payload.status}'. Allowed: {', '.join(valid_statuses)}"
        )

    case = db.query(CaseModel).filter(CaseModel.case_id.ilike(case_id)).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found."
        )

    old_status = case.status
    case.status = payload.status
    
    audit = AuditLogModel(
        action="CASE_STATUS_UPDATED",
        resource_type="INVESTIGATION",
        resource_id=case.case_id,
        metadata_json={
            "oldStatus": old_status,
            "newStatus": payload.status
        }
    )
    db.add(audit)
    db.commit()
    db.refresh(case)
    return case.to_dict()

@router.delete("/cases/{case_id}")
def delete_investigation_case(
    case_id: str,
    db: Session = Depends(get_db)
):
    """Delete an investigation case and associated telemetry."""
    case = db.query(CaseModel).filter(CaseModel.case_id.ilike(case_id)).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found."
        )

    db.delete(case)
    audit = AuditLogModel(
        action="CASE_DELETED",
        resource_type="INVESTIGATION",
        resource_id=case_id
    )
    db.add(audit)
    db.commit()
    return {"message": f"Case '{case_id}' successfully removed."}
