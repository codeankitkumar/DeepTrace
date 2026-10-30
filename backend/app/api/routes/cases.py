from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core import audit, security
from app.db import models
from app.db.database import get_db
from app.schemas.case import CaseCreate, CaseRead, CaseUpdate

router = APIRouter(prefix="/cases", tags=["cases"])


def _get_case_or_404(db: Session, case_id: int) -> models.Case:
    case = db.get(models.Case, case_id)
    if not case:
        raise HTTPException(404, detail="Case not found")
    return case


@router.get("", response_model=list[CaseRead])
def list_cases(db: Session = Depends(get_db), _: models.User = Depends(security.get_current_user)):
    return db.query(models.Case).order_by(models.Case.created_at.desc()).all()


@router.post("", response_model=CaseRead, status_code=201)
def create_case(payload: CaseCreate, request_user: models.User = Depends(security.ROLE_ANALYST),
                db: Session = Depends(get_db)):
    case = models.Case(
        name=payload.name,
        description=payload.description,
        reference_number=payload.reference_number,
        status="open",
        created_by=request_user.id,
    )
    db.add(case)
    db.commit()
    db.refresh(case)
    audit.record_audit(db, request_user.id, request_user.username, "case.created",
                       target_type="case", target_id=case.id)
    return case


@router.get("/{case_id}", response_model=CaseRead)
def get_case(case_id: int, db: Session = Depends(get_db),
             _: models.User = Depends(security.get_current_user)):
    return _get_case_or_404(db, case_id)


@router.patch("/{case_id}", response_model=CaseRead)
def update_case(case_id: int, payload: CaseUpdate, db: Session = Depends(get_db),
                request_user: models.User = Depends(security.ROLE_ANALYST)):
    case = _get_case_or_404(db, case_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(case, field, value)
    db.commit()
    db.refresh(case)
    audit.record_audit(db, request_user.id, request_user.username, "case.updated",
                       target_type="case", target_id=case.id, detail=payload.model_dump())
    return case