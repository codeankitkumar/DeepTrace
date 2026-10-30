from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class EvidenceIngest(BaseModel):
    category: str = "uncategorized"
    description: str = ""
    source: str | None = None
    identification: str | None = None
    evidence_type: str | None = None


class EvidenceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    case_id: int
    original_name: str
    size_bytes: int
    sha256_original: str | None
    sha256_working_copy: str | None
    category: str
    evidence_type: str
    status: str
    integrity_status: str
    source: str | None
    uploaded_at: datetime | None


class CustodyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    action: str
    actor_name: str
    from_party: str | None
    to_party: str | None
    notes: str
    timestamp: datetime
    checksum: str | None


class AnalysisRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    evidence_id: int
    module: str
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    summary: dict | None
    error: str | None


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    module: str
    severity: str
    title: str
    description: str
    is_hypothesis: bool
    confidence: float
    created_at: datetime | None