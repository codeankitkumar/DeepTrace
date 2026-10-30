from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import models
from app.db.database import Base
from app.services import timeline_engine


def _session():
    engine = create_engine("sqlite://", poolclass=__import__("sqlalchemy.pool", fromlist=["StaticPool"]).StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()


def test_build_timeline_sorted():
    db = _session()
    base = datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    db.add_all([
        models.Case(name="c1", created_by=1),
    ])
    db.commit()
    case = db.query(models.Case).first()
    db.add_all([
        models.TimelineEvent(case_id=case.id, source_module="evtx", category="logon",
                             description="later", event_time_utc=base + timedelta(minutes=5), confidence=0.8),
        models.TimelineEvent(case_id=case.id, source_module="browser", category="browsing",
                             description="earlier", event_time_utc=base, confidence=0.8),
    ])
    db.commit()
    tl = timeline_engine.build_timeline(db, case.id)
    assert tl[0]["description"] == "earlier"
    assert tl[1]["description"] == "later"


def test_bruteforce_anomaly_detected():
    db = _session()
    db.add(models.Case(name="c", created_by=1))
    db.commit()
    case = db.query(models.Case).first()
    base = datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(5):
        db.add(models.TimelineEvent(
            case_id=case.id, source_module="evtx", category="logon",
            description=f"fail {i}", event_time_utc=base + timedelta(seconds=i * 10),
            properties_json={"EventID": "4625"}, confidence=0.8))
    db.add(models.TimelineEvent(
        case_id=case.id, source_module="evtx", category="logon",
        description="success", event_time_utc=base + timedelta(seconds=90),
        properties_json={"EventID": "4624"}, confidence=0.8))
    db.commit()
    anomalies = timeline_engine.detect_unusual_sequences(db, case.id)
    assert any(a["type"] == "bruteforce_pattern" for a in anomalies)