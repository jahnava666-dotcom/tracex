from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session
from ...db.session import get_db
from ...models.threat_intel import ThreatIndicatorModel
from ...models.audit import AuditLogModel
from ...schemas.forensics import ThreatIntelligenceIndicator, CreateIndicatorRequest

router = APIRouter(tags=["Threat Intelligence"])

@router.get("/threat-intelligence", response_model=List[ThreatIntelligenceIndicator])
def get_threat_indicators(
    search: Optional[str] = Query(None),
    indicator_type: Optional[str] = Query(None, alias="type"),
    case_id: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Query correlated threat intelligence indicators (IPs, domains, URLs, hashes).
    """
    query = db.query(ThreatIndicatorModel).order_by(ThreatIndicatorModel.created_at.desc())
    
    if case_id:
        query = query.filter(ThreatIndicatorModel.case_id == case_id)
        
    if indicator_type and indicator_type.lower() != "all":
        query = query.filter(ThreatIndicatorModel.indicator_type.ilike(indicator_type))
        
    if search:
        s = f"%{search}%"
        query = query.filter(
            (ThreatIndicatorModel.indicator.ilike(s)) |
            (ThreatIndicatorModel.details.ilike(s))
        )
        
    records = query.all()
    return [r.to_dict() for r in records]

@router.post("/threat-intelligence", response_model=ThreatIntelligenceIndicator, status_code=status.HTTP_201_CREATED)
def create_threat_indicator(
    payload: CreateIndicatorRequest,
    db: Session = Depends(get_db)
):
    """
    Submit a new IOC indicator to the enterprise threat intelligence catalog.
    """
    mapped_reputation = "Malicious"
    if payload.risk_level in ("Clean", "Suspicious", "Malicious"):
        mapped_reputation = payload.risk_level
    elif payload.risk_level in ("High", "Critical"):
        mapped_reputation = "Malicious"

    meta = payload.metadata or {}
    details = meta.get("details", f"Manually cataloged {payload.indicator_type} threat")
    confidence = meta.get("confidence", 90)

    record = ThreatIndicatorModel(
        case_id=payload.case_id or "CASE-1024",
        indicator=payload.indicator_value.strip(),
        indicator_type=payload.indicator_type,
        reputation=mapped_reputation,
        details=details,
        confidence=confidence,
        first_seen=datetime.utcnow().strftime("%Y-%m-%d"),
        metadata_json=meta
    )
    db.add(record)
    
    audit = AuditLogModel(
        action="IOC_ADDED",
        resource_type="INDICATOR_OF_COMPROMISE",
        resource_id=payload.indicator_value,
        metadata_json={
            "caseId": payload.case_id,
            "type": payload.indicator_type,
            "reputation": mapped_reputation
        }
    )
    db.add(audit)
    db.commit()
    db.refresh(record)

    return record.to_dict()

@router.delete("/threat-intelligence/{indicator_id}")
def delete_threat_indicator(
    indicator_id: int,
    db: Session = Depends(get_db)
):
    """Delete a threat indicator from the catalog."""
    rec = db.query(ThreatIndicatorModel).filter(ThreatIndicatorModel.id == indicator_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="Indicator not found")
        
    db.delete(rec)
    audit = AuditLogModel(
        action="IOC_DELETED",
        resource_type="INDICATOR_OF_COMPROMISE",
        resource_id=str(indicator_id)
    )
    db.add(audit)
    db.commit()
    return {"message": "Indicator deleted successfully"}
