"""Audit logging.

Records security-relevant and evidence operations in the database audit trail.
Writes are append-only through the ORM; a `checksum` protects each row's integrity
(CDC-style hash chaining against the previous row).
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.db import models


def _hash_row(prev: str | None, data_json: str) -> str:
    return hashlib.sha256(f"{prev}|{data_json}".encode("utf-8")).hexdigest()


def record_audit(
    db: Session,
    actor_id: Optional[int],
    actor_username: str,
    action: str,
    target_type: str = "",
    target_id: Optional[int] = None,
    detail: Optional[dict[str, Any]] = None,
    ip: Optional[str] = None,
) -> models.AuditLog:
    prev = (
        db.query(models.AuditLog)
        .order_by(models.AuditLog.id.desc())
        .first()
    )
    prev_hash = prev.checksum if prev else None
    data_json = json.dumps(detail or {}, sort_keys=True, default=str)
    checksum = _hash_row(prev_hash, data_json)

    entry = models.AuditLog(
        actor_id=actor_id,
        actor_username=actor_username,
        action=action,
        target_type=target_type,
        target_id=target_id,
        detail=detail,
        ip_address=ip,
        checksum=checksum,
        previous_hash=prev_hash,
        timestamp=datetime.now(timezone.utc),
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def verify_audit_chain(db: Session) -> tuple[bool, int]:
    """Verify the hash chain of the audit log. Returns (valid, rows_checked)."""
    entries = db.query(models.AuditLog).order_by(models.AuditLog.id.asc()).all()
    prev_hash: str | None = None
    for e in entries:
        data_json = json.dumps(e.detail or {}, sort_keys=True, default=str)
        expected = _hash_row(prev_hash, data_json)
        if e.checksum != expected or e.previous_hash != prev_hash:
            return False, len(entries)
        prev_hash = e.checksum
    return True, len(entries)