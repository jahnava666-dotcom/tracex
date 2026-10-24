from datetime import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from ...db.session import get_db
from ...core.config import settings
from ...schemas.forensics import HealthResponse

router = APIRouter(tags=["System Health"])

@router.get("/health", response_model=HealthResponse)
def health_check(db: Session = Depends(get_db)):
    """
    Check backend health status, database connectivity, and forensic engine capabilities.
    """
    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"error: {str(e)}"

    vault_status = "ready" if settings.EVIDENCE_VAULT_DIR.exists() else "missing"

    return HealthResponse(
        status="operational",
        timestamp=datetime.utcnow().isoformat() + "Z",
        service=settings.PROJECT_NAME,
        version=settings.PROJECT_VERSION,
        database=db_status,
        evidenceVault=vault_status,
        features={
            "emailAnalysis": True,
            "geolocation": True,
            "threatIntelligence": True,
            "evidenceIntegrityVerification": True,
            "reportGeneration": True,
            "auditLogging": True
        }
    )
