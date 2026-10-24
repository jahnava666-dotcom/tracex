from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from ...db.session import get_db
from ...models.case import CaseModel
from ...models.report import ReportModel
from ...services.report_generator import generate_case_report
from ...schemas.forensics import GeneratedReport

router = APIRouter(tags=["Forensic Reports"])

class GenerateReportRequest(BaseModel):
    caseId: str
    format: Optional[str] = "PDF"  # 'PDF' | 'JSON' | 'STIX 2.1'

@router.get("/reports", response_model=List[GeneratedReport])
def list_reports(
    db: Session = Depends(get_db)
):
    """List all generated forensic dossiers and reports."""
    reports = db.query(ReportModel).order_by(ReportModel.created_at.desc()).all()
    return [r.to_dict() for r in reports]

@router.post("/reports/generate", response_model=GeneratedReport)
def generate_report_endpoint(
    payload: GenerateReportRequest,
    db: Session = Depends(get_db)
):
    """
    Generate an authoritative digital forensic report (PDF Dossier, STIX 2.1 CTI bundle, or JSON).
    """
    case = db.query(CaseModel).filter(CaseModel.case_id.ilike(payload.caseId)).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation case '{payload.caseId}' not found."
        )

    report_dict = generate_case_report(
        db=db,
        case_data=case.to_dict(),
        report_format=payload.format or "PDF"
    )
    return report_dict

@router.get("/reports/{report_id}/download")
def download_report(
    report_id: str,
    db: Session = Depends(get_db)
):
    """Download forensic report content."""
    report = db.query(ReportModel).filter(ReportModel.report_id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    ext = "json" if report.format in ("JSON", "STIX 2.1") else "txt"
    filename = f"{report.report_id}_{report.case_id}.{ext}"

    return PlainTextResponse(
        content=report.content or report.summary,
        media_type="text/plain" if ext == "txt" else "application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
