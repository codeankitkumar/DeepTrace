from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from sqlalchemy.orm import Session

from app.core import audit, security
from app.db import models
from app.db.database import get_db
from app.schemas.evidence import (AnalysisRunRead, CustodyRead, EvidenceIngest,
                                  EvidenceRead, FindingRead)
from app.services import chain_of_custody, evidence_service
from app.services.evidence_service import run_analysis, verify_integrity

router = APIRouter(prefix="/evidence", tags=["evidence"])


def _get_evidence_or_404(db: Session, evidence_id: int) -> models.Evidence:
    ev = db.get(models.Evidence, evidence_id)
    if not ev:
        raise HTTPException(404, detail="Evidence not found")
    return ev


@router.get("", response_model=list[EvidenceRead])
def list_evidence(case_id: int, db: Session = Depends(get_db),
                  _: models.User = Depends(security.get_current_user)):
    return db.query(models.Evidence).filter(models.Evidence.case_id == case_id).all()


@router.post("", response_model=EvidenceRead, status_code=201)
async def upload_evidence(
    request: Request,
    case_id: int = Form(...),
    file: UploadFile = File(...),
    category: str = Form("uncategorized"),
    description: str = Form(""),
    source: str | None = Form(None),
    identification: str | None = Form(None),
    evidence_type: str | None = Form(None),
    db: Session = Depends(get_db),
    user: models.User = Depends(security.ROLE_ANALYST),
):
    data = await file.read()
    if not file.filename:
        raise HTTPException(400, detail="Missing file name")
    try:
        ev = evidence_service.ingest_evidence(
            db, user, case_id, file.filename, data,
            category=category, description=description, source=source,
            identification=identification, evidence_type=evidence_type,
        )
    except ValueError as exc:
        raise HTTPException(400, detail=str(exc))
    ip = request.client.host if request.client else None
    audit.record_audit(db, user.id, user.username, "evidence.uploaded",
                       target_type="evidence", target_id=ev.id,
                       detail={"name": ev.original_name, "sha256": ev.sha256_original}, ip=ip)
    return ev


@router.get("/{evidence_id}", response_model=EvidenceRead)
def get_evidence(evidence_id: int, db: Session = Depends(get_db),
                 _: models.User = Depends(security.get_current_user)):
    return _get_evidence_or_404(db, evidence_id)


@router.post("/{evidence_id}/verify", response_model=EvidenceRead)
def verify(evidence_id: int, request: Request, db: Session = Depends(get_db),
           user: models.User = Depends(security.ROLE_ANALYST)):
    ev = _get_evidence_or_404(db, evidence_id)
    ok = verify_integrity(db, ev)
    audit.record_audit(db, user.id, user.username, "evidence.verified",
                       target_type="evidence", target_id=ev.id,
                       detail={"ok": ok, "sha256": ev.sha256_working_copy},
                       ip=request.client.host if request.client else None)
    db.refresh(ev)
    return ev


@router.get("/{evidence_id}/custody", response_model=list[CustodyRead])
def custody(evidence_id: int, db: Session = Depends(get_db),
            _: models.User = Depends(security.get_current_user)):
    _get_evidence_or_404(db, evidence_id)
    valid, _count = chain_of_custody.verify_chain(db, evidence_id)
    records = db.query(models.CustodyRecord).filter(
        models.CustodyRecord.evidence_id == evidence_id
    ).order_by(models.CustodyRecord.timestamp.asc()).all()
    return records


@router.post("/{evidence_id}/run/{module_name}", response_model=AnalysisRunRead)
def run(evidence_id: int, module_name: str, request: Request, db: Session = Depends(get_db),
        user: models.User = Depends(security.ROLE_ANALYST)):
    ev = _get_evidence_or_404(db, evidence_id)
    run = run_analysis(db, user, ev, module_name)
    audit.record_audit(db, user.id, user.username, "analysis.run",
                       target_type="analysis_run", target_id=run.id,
                       detail={"module": module_name, "evidence_id": evidence_id,
                               "status": run.status},
                       ip=request.client.host if request.client else None)
    return run


@router.get("/{evidence_id}/findings", response_model=list[FindingRead])
def findings(evidence_id: int, db: Session = Depends(get_db),
             _: models.User = Depends(security.get_current_user)):
    return db.query(models.Finding).filter(models.Finding.evidence_id == evidence_id).all()