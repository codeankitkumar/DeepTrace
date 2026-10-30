from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.core import security
from app.db import models
from app.db.database import get_db
from app.services import report_service

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/{case_id}/generate")
def generate_report(case_id: int, db: Session = Depends(get_db),
                    user: models.User = Depends(security.ROLE_ANALYST)):
    report = report_service.build_report(db, case_id, user.username)
    return report


@router.get("/{case_id}/markdown", response_class=PlainTextResponse)
def generate_markdown(case_id: int, db: Session = Depends(get_db),
                      user: models.User = Depends(security.ROLE_ANALYST)):
    report = report_service.build_report(db, case_id, user.username)
    return report_service.render_markdown(report)