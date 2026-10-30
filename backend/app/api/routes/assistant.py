from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core import audit, security
from app.db import models
from app.db.database import get_db
from app.ai import assistant

router = APIRouter(prefix="/assistant", tags=["assistant"])


class AssistantAsk(BaseModel):
    query: str


@router.post("/{case_id}/ask")
def ask(case_id: int, payload: AssistantAsk, request: Request, db: Session = Depends(get_db),
        user: models.User = Depends(security.ROLE_ANALYST)):
    if not db.get(models.Case, case_id):
        raise HTTPException(404, detail="Case not found")
    result = assistant.answer(db, case_id, payload.query, user.id)
    msg = models.AssistantMessage(
        case_id=case_id, actor_id=user.id, role="user", content=payload.query,
        is_hypothesis=False,
    )
    db.add(msg)
    resp = models.AssistantMessage(
        case_id=case_id, actor_id=user.id, role="assistant", content=result["content"],
        is_hypothesis=result.get("is_hypothesis", True), intent=result.get("intent"),
    )
    db.add(resp)
    db.commit()
    audit.record_audit(db, user.id, user.username, "assistant.query",
                       target_type="case", target_id=case_id,
                       detail={"intent": result.get("intent")},
                       ip=request.client.host if request.client else None)
    return result


@router.get("/{case_id}/history")
def history(case_id: int, db: Session = Depends(get_db),
            _: models.User = Depends(security.get_current_user)):
    msgs = db.query(models.AssistantMessage).filter(models.AssistantMessage.case_id == case_id).all()
    return {
        "messages": [
            {"role": m.role, "content": m.content, "is_hypothesis": m.is_hypothesis,
             "created_at": m.created_at.isoformat() if m.created_at else None}
            for m in msgs
        ]
    }