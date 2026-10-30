"""Evidence management service.

Handles secure ingestion, encrypted-at-rest storage, integrity verification, ephemeral
working-copy creation, and the orchestration of forensic analysis. Original evidence
is never modified: uploaded bytes are encrypted once and hashed; all analysis runs on
decrypted, hash-verified working copies that are deleted after each run.
"""
from __future__ import annotations

import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.crypto import decrypt_bytes, encrypt_bytes
from app.db import models
from app.forensics.base import AnalysisResult
from app.forensics.registry import get_module
from app.services import chain_of_custody, hashing

ALLOWED_EXTENSIONS = {
    ".txt", ".log", ".csv", ".json", ".xml", ".evtx", ".sqlite", ".sqlite3", ".db",
    ".raw", ".img", ".dmp", ".bin", ".dat", ".doc", ".docx", ".pdf", ".png", ".jpg",
    ".jpeg", ".gz", ".zip", ".eml", ".pcap", ".pcapng",
}


def classify_evidence_type(name: str) -> str:
    lower = name.lower()
    if lower.endswith((".evtx", ".xml")):
        return "evtx"
    if lower.endswith((".sqlite", ".sqlite3", ".db")):
        return "browser"
    if lower.endswith((".raw", ".img", ".dmp", ".bin", ".mem")):
        return "memory"
    if lower.endswith((".csv", ".log", ".txt")):
        return "network"
    return "file"


def _storage_paths(case_id: int, evidence_id: int) -> dict[str, Path]:
    root = Path(settings.storage_root).resolve()
    original = root / "cases" / str(case_id) / "evidence" / str(evidence_id)
    working = root / "cases" / str(case_id) / "working" / str(evidence_id)
    return {"original": original, "working": working}


def ingest_evidence(
    db: Session, user: models.User, case_id: int, original_name: str, file_bytes: bytes,
    category: str = "uncategorized", description: str = "", source: str | None = None,
    identification: str | None = None, evidence_type: str | None = None,
) -> models.Evidence:
    ext = os.path.splitext(original_name)[1].lower()
    if ext and ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"File extension '{ext}' is not in the allowed upload list.")
    if len(file_bytes) > settings.max_upload_size_bytes:
        raise ValueError("Uploaded file exceeds the configured maximum size.")

    ev_type = evidence_type or classify_evidence_type(original_name)
    sha_original = hashing.sha256_bytes(file_bytes)

    ev = models.Evidence(
        case_id=case_id,
        original_name=original_name,
        stored_path="",
        size_bytes=len(file_bytes),
        sha256_original=sha_original,
        category=category,
        identification=identification,
        evidence_type=ev_type,
        description=description,
        source=source,
        status="ingested",
        integrity_status="pending",
        uploaded_by=user.id,
    )
    db.add(ev)
    db.flush()
    db.refresh(ev)

    paths = _storage_paths(case_id, ev.id)
    paths["original"].mkdir(parents=True, exist_ok=True)
    enc_path = paths["original"] / (uuid.uuid4().hex + ".enc")
    enc_path.write_bytes(encrypt_bytes(file_bytes))
    ev.stored_path = str(enc_path)

    ev.metadata_json = _basic_metadata(original_name, len(file_bytes), ev_type)

    # Verify the working copy immediately at ingest (integrity gate).
    try:
        proc = create_working_copy(ev)
        try:
            wc = proc.name
            actual = hashing.sha256_file(wc)
            ev.sha256_working_copy = actual
            ev.integrity_status = "verified" if actual == sha_original else "failed"
        finally:
            _safe_unlink(proc.name)
    except Exception:
        ev.integrity_status = "failed"

    db.commit()
    db.refresh(ev)

    chain_of_custody.record_custody(
        db, ev.id, user.id, user.username, "captured",
        notes="Evidence ingested and hash-verified.",
        from_party=source or "external",
    )
    return ev


def create_working_copy(evidence: models.Evidence) -> BinaryIO:
    """Open a decrypted, hash-verified temporary working copy of the evidence.

    The caller is responsible for closing and unlinking the returned handle.
    """
    encrypted = Path(evidence.stored_path).read_bytes()
    raw = decrypt_bytes(encrypted)
    actual = hashing.sha256_bytes(raw)
    if evidence.sha256_original and actual != evidence.sha256_original:
        raise ValueError("Integrity verification failed: working copy hash mismatch.")

    tmp = tempfile.NamedTemporaryFile(
        mode="w+b", suffix=os.path.splitext(evidence.original_name)[1], delete=False
    )
    tmp.write(raw)
    tmp.flush()
    os.fsync(tmp.fileno())
    return tmp


def _safe_unlink(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def verify_integrity(db: Session, evidence: models.Evidence) -> bool:
    try:
        proc = create_working_copy(evidence)
        try:
            actual = hashing.sha256_file(proc.name)
        finally:
            _safe_unlink(proc.name)
    except Exception:
        evidence.integrity_status = "failed"
        db.commit()
        return False
    evidence.sha256_working_copy = actual
    evidence.integrity_status = "verified" if actual == evidence.sha256_original else "failed"
    evidence.verified_at = datetime.now(timezone.utc)
    db.commit()
    return evidence.integrity_status == "verified"


def run_analysis(
    db: Session, user: models.User, evidence: models.Evidence, module_name: str,
) -> models.AnalysisRun:
    run = models.AnalysisRun(evidence_id=evidence.id, module=module_name, status="running",
                             started_at=datetime.now(timezone.utc))
    db.add(run)
    db.commit()
    db.refresh(run)

    module = get_module(module_name)
    try:
        proc = create_working_copy(evidence)
        try:
            result: AnalysisResult = module.analyze(proc.name, context={"case_id": evidence.case_id})
        finally:
            _safe_unlink(proc.name)
    except ValueError as exc:
        run.status = "error"
        run.finished_at = datetime.now(timezone.utc)
        run.error = str(exc)
        db.commit()
        return run
    except Exception as exc:  # pragma: no cover - defensive
        run.status = "error"
        run.finished_at = datetime.now(timezone.utc)
        run.error = f"{type(exc).__name__}: {exc}"
        db.commit()
        return run

    _persist_result(db, user, evidence, run, result)
    evidence.status = "analyzed"
    db.commit()
    chain_of_custody.record_custody(
        db, evidence.id, user.id, user.username, "analyzed",
        notes=f"Forensic module '{module_name}' executed on verified working copy.",
    )
    return run


def _persist_result(db: Session, user: models.User, evidence: models.Evidence,
                    run: models.AnalysisRun, result: AnalysisResult) -> None:
    for f in result.findings:
        db.add(models.Finding(
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            analysis_run_id=run.id,
            module=result.module,
            severity=f["severity"],
            title=f["title"][:255],
            description=f["description"],
            is_hypothesis=f["is_hypothesis"],
            confidence=f["confidence"],
            analyst_id=user.id,
        ))
    for ev in sorted(result.events, key=lambda e: e["event_time_utc"]):
        db.add(models.TimelineEvent(
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            event_time_utc=ev["event_time_utc"],
            source_module=ev["source_module"],
            category=ev["category"],
            description=ev["description"],
            properties_json=ev["properties"],
            confidence=ev["confidence"],
        ))
    run.summary = {
        "module": result.module,
        "summary": result.summary,
        "findings_count": len(result.findings),
        "events_count": len(result.events),
        "errors": result.errors,
    }
    run.status = "completed"
    run.finished_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(run)


def _basic_metadata(name: str, size: int, ev_type: str) -> dict[str, Any]:
    return {
        "size_bytes": size,
        "extension": os.path.splitext(name)[1].lower(),
        "evidence_type": ev_type,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }