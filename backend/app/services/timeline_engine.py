"""Timeline reconstruction engine.

Extracts/normalizes timestamps (stored as UTC in the DB), sorts events chronologically,
correlates events across evidence sources, and flags unusual sequences for analyst review.
All outputs are hypotheses unless explicitly verified.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.db import models


def build_timeline(db: Session, case_id: int) -> list[dict[str, Any]]:
    events = (
        db.query(models.TimelineEvent)
        .filter(models.TimelineEvent.case_id == case_id)
        .order_by(models.TimelineEvent.event_time_utc.asc())
        .all()
    )
    return [
        {
            "id": e.id,
            "event_time_utc": _iso(e.event_time_utc),
            "source_module": e.source_module,
            "category": e.category,
            "description": e.description,
            "confidence": e.confidence,
            "evidence_id": e.evidence_id,
            "properties": e.properties_json or {},
        }
        for e in events
    ]


def detect_unusual_sequences(db: Session, case_id: int) -> list[dict[str, Any]]:
    """Rule-based anomaly detection over correlated timeline events."""
    events = (
        db.query(models.TimelineEvent)
        .filter(models.TimelineEvent.case_id == case_id)
        .order_by(models.TimelineEvent.event_time_utc.asc())
        .all()
    )
    anomalies: list[dict[str, Any]] = []
    _bruteforce_signature(events, anomalies)
    _activity_spikes(events, anomalies)
    _overtime_clustering(events, anomalies)
    return anomalies


def _bruteforce_signature(events: list[models.TimelineEvent], anomalies: list[dict]) -> None:
    recent_failures: list[models.TimelineEvent] = []
    window = 300  # seconds
    for ev in events:
        if ev.category == "logon":
            eid = (ev.properties_json or {}).get("EventID")
            if str(eid) == "4625":
                recent_failures.append(ev)
            elif str(eid) == "4624" and recent_failures:
                first = recent_failures[0]
                last = recent_failures[-1]
                if _seconds_between(first.event_time_utc, ev.event_time_utc) <= window:
                    anomalies.append({
                        "type": "bruteforce_pattern",
                        "severity": "high",
                        "description": (
                            f"{len(recent_failures)} failed logons followed by a successful logon, "
                            "suggesting credential brute-force/harvesting."
                        ),
                        "confidence": 0.7,
                        "event_ids": [x.id for x in recent_failures] + [ev.id],
                        "is_hypothesis": True,
                    })
                recent_failures = []
    if recent_failures:
        anomalies.append({
            "type": "failed_logon_burst",
            "severity": "medium",
            "description": f"{len(recent_failures)} failed logons observed without subsequent success.",
            "confidence": 0.5,
            "event_ids": [x.id for x in recent_failures],
            "is_hypothesis": True,
        })


def _activity_spikes(events: list[models.TimelineEvent], anomalies: list[dict]) -> None:
    bucket: defaultdict[int, Counter] = defaultdict(Counter)
    for ev in events:
        ts = int(ev.event_time_utc.timestamp()) // 60
        bucket[ts][ev.source_module] += 1
    for minute, cnt in bucket.items():
        total = sum(cnt.values())
        if total >= 8:
            anomalies.append({
                "type": "activity_spike",
                "severity": "medium",
                "description": f"{total} events in a single minute suggests automated activity.",
                "confidence": 0.5,
                "event_ids": [e.id for e in events if int(e.event_time_utc.timestamp()) // 60 == minute],
                "is_hypothesis": True,
            })


def _overtime_clustering(events: list[models.TimelineEvent], anomalies: list[dict]) -> None:
    by_source: dict[str, list[models.TimelineEvent]] = defaultdict(list)
    for ev in events:
        by_source[ev.source_module].append(ev)
    for source, evs in by_source.items():
        if len(evs) < 3:
            continue
        times = [e.event_time_utc.timestamp() for e in evs]
        span = max(times) - min(times)
        if span > 0 and (len(evs) / (span / 3600.0)) > 360:
            anomalies.append({
                "type": "high_volume_source",
                "severity": "low",
                "description": f"Source '{source}' produced {len(evs)} events in {span/3600:.1f}h.",
                "confidence": 0.4,
                "event_ids": [e.id for e in evs],
                "is_hypothesis": True,
            })


def correlation_summary(db: Session, case_id: int) -> dict[str, Any]:
    events = db.query(models.TimelineEvent).filter(models.TimelineEvent.case_id == case_id).all()
    sources: Counter = Counter(e.source_module for e in events)
    categories: Counter = Counter(e.category or "general" for e in events)
    total = len(events)
    earliest = min((e.event_time_utc for e in events), default=None)
    latest = max((e.event_time_utc for e in events), default=None)
    return {
        "total_events": total,
        "by_source": dict(sources),
        "by_category": dict(categories),
        "earliest_utc": _iso(earliest) if earliest else None,
        "latest_utc": _iso(latest) if latest else None,
        "span_seconds": (latest - earliest).total_seconds() if earliest and latest else 0,
    }


def _seconds_between(a: datetime, b: datetime) -> float:
    if a.tzinfo is None:
        a = a.replace(tzinfo=timezone.utc)
    if b.tzinfo is None:
        b = b.replace(tzinfo=timezone.utc)
    return (b - a).total_seconds()


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None