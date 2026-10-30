from fastapi import APIRouter, Depends

from app.core import security
from app.db import models
from app.db.database import get_db
from app.services import timeline_engine
from sqlalchemy.orm import Session

router = APIRouter(prefix="/timeline", tags=["timeline"])


@router.get("/{case_id}/events")
def events(case_id: int, db: Session = Depends(get_db),
           _: models.User = Depends(security.get_current_user)):
    return {"events": timeline_engine.build_timeline(db, case_id)}


@router.get("/{case_id}/anomalies")
def anomalies(case_id: int, db: Session = Depends(get_db),
              _: models.User = Depends(security.get_current_user)):
    return {"anomalies": timeline_engine.detect_unusual_sequences(db, case_id)}


@router.get("/{case_id}/summary")
def summary(case_id: int, db: Session = Depends(get_db),
            _: models.User = Depends(security.get_current_user)):
    return timeline_engine.correlation_summary(db, case_id)