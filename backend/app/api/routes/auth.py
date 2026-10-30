from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core import audit, security
from app.core.security import create_access_token, create_refresh_token, decode_token, verify_password
from app.db import models
from app.db.database import get_db
from app.schemas.auth import RefreshRequest, TokenResponse, UserLogin, UserRead
from datetime import datetime, timezone

router = APIRouter(prefix="/auth", tags=["auth"])


def _client_ip(request: Request) -> str | None:
    if request.client:
        return request.client.host
    return None


@router.post("/login", response_model=TokenResponse)
def login(payload: UserLogin, request: Request, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        audit.record_audit(db, None, payload.username, "login.failed", ip=_client_ip(request))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    audit.record_audit(db, user.id, user.username, "login.success", ip=_client_ip(request))
    return TokenResponse(
        access_token=create_access_token(user.username, user.role, user.id),
        refresh_token=create_refresh_token(user.username),
        user=UserRead.model_validate(user),
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh(payload: RefreshRequest, request: Request, db: Session = Depends(get_db)):
    try:
        data = decode_token(payload.refresh_token, expected_type="refresh")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    user = db.query(models.User).filter(models.User.username == data["sub"]).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or disabled")
    audit.record_audit(db, user.id, user.username, "token.refresh", ip=_client_ip(request))
    return TokenResponse(
        access_token=create_access_token(user.username, user.role, user.id),
        refresh_token=create_refresh_token(user.username),
        user=UserRead.model_validate(user),
    )


@router.get("/me", response_model=UserRead)
def me(user: models.User = Depends(security.get_current_user)):
    return UserRead.model_validate(user)