from pydantic import BaseModel, ConfigDict, Field


class CaseCreate(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    description: str = ""
    reference_number: str | None = None
    status: str = "open"


class CaseUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    reference_number: str | None = None
    status: str | None = None


class CaseRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    description: str
    status: str
    reference_number: str | None
    created_by: int