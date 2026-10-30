"""Chain-of-custody records.

Maintains a sequential, hash-linked log of custody events for each evidence item.
Every event is recorded with actor, action, and an optional checksum so the chain can
be verified for tampering between records.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.db import models


def _checksum(action: str, evidence_id: int, actor: str, prev_hash: str | None) -> str:
    data = f"{action}|{evidence_id}|{actor}|{prev_hash}"
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def record_custody(
    db: Session,
    evidence_id: int,
    actor_id: int,
    actor_name: str,
    action: str,
    notes: str = "",
    from_party: str | None = None,
    to_party: str | None = None,
) -> models.CustodyRecord:
    prev = (
        db.query(models.CustodyRecord)
        .filter(models.CustodyRecord.evidence_id == evidence_id)
        .order_by(models.CustodyRecord.id.desc())
        .first()
    )
    prev_hash = prev.checksum if prev else None
    rec = models.CustodyRecord(
        evidence_id=evidence_id,
        action=action,
        actor_id=actor_id,
        actor_name=actor_name,
        from_party=from_party,
        to_party=to_party,
        notes=notes,
        timestamp=datetime.now(timezone.utc),
        checksum=_checksum(action, evidence_id, actor_name, prev_hash),
    )
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return rec


def verify_chain(db: Session, evidence_id: int) -> tuple[bool, int]:
    records = (
        db.query(models.CustodyRecord)
        .filter(models.CustodyRecord.evidence_id == evidence_id)
        .order_by(models.CustodyRecord.id.asc())
        .all()
    )
    prev_hash: str | None = None
    for r in records:
        expected = _checksum(r.action, evidence_id, r.actor_name, prev_hash)
        if r.checksum != expected:
            return False, len(records)
        prev_hash = r.checksum
    return True, len(records)