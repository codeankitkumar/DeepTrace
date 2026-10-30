from fastapi import APIRouter, Depends

from app.core import security
from app.db import models
from app.db.database import get_db
from app.services import timeline_engine
from sqlalchemy.orm import Session
from collections import Counter

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/overview")
def overview(db: Session = Depends(get_db), _: models.User = Depends(security.get_current_user)):
    cases = db.query(models.Case).count()
    evidence = db.query(models.Evidence).count()
    verified = db.query(models.Evidence).filter(models.Evidence.integrity_status == "verified").count()
    failed = db.query(models.Evidence).filter(models.Evidence.integrity_status == "failed").count()
    findings_total = db.query(models.Finding).count()
    findings_by_sev = dict(Counter(f.severity for f in db.query(models.Finding).all()))
    events_total = db.query(models.TimelineEvent).count()
    evidence_by_type = dict(Counter(t for (t,) in db.query(models.Evidence.evidence_type).all()))
    auto_analyzed = db.query(models.AnalysisRun).filter(models.AnalysisRun.status == "completed").count()
    return {
        "cases": cases,
        "evidence_total": evidence,
        "evidence_verified": verified,
        "evidence_failed": failed,
        "findings_total": findings_total,
        "findings_by_severity": findings_by_sev,
        "events_total": events_total,
        "evidence_by_type": evidence_by_type,
        "analysis_runs_completed": auto_analyzed,
    }


@router.get("/activity")
def activity(db: Session = Depends(get_db), _: models.User = Depends(security.get_current_user)):
    logs = db.query(models.AuditLog).order_by(models.AuditLog.timestamp.desc()).limit(50).all()
    return {
        "activity": [
            {
                "id": a.id,
                "actor": a.actor_username,
                "action": a.action,
                "target_type": a.target_type,
                "target_id": a.target_id,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            }
            for a in logs
        ]
    }


@router.get("/timeline-bucket")
def timeline_bucket(db: Session = Depends(get_db), _: models.User = Depends(security.get_current_user)):
    events = db.query(models.TimelineEvent).all()
    buckets: dict[str, int] = {}
    for e in events:
        key = e.event_time_utc.strftime("%Y-%m-%d %H:%M")
        buckets[key] = buckets.get(key, 0) + 1
    return {"buckets": [{"time": k, "count": v} for k, v in sorted(buckets.items())]}