from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core import security
from app.core.security import hash_password
from app.db import models
from app.db.database import get_db
from app.schemas.auth import UserCreate, UserRead

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserRead])
def list_users(db: Session = Depends(get_db), _: models.User = Depends(security.ROLE_ADMIN)):
    return db.query(models.User).all()


@router.post("", response_model=UserRead, status_code=201)
def create_user(payload: UserCreate, db: Session = Depends(get_db),
                _: models.User = Depends(security.ROLE_ADMIN)):
    if payload.role not in ("admin", "analyst", "viewer"):
        raise HTTPException(400, detail="Role must be admin, analyst, or viewer")
    if db.query(models.User).filter(models.User.username == payload.username).first():
        raise HTTPException(409, detail="Username already exists")
    if db.query(models.User).filter(models.User.email == payload.email).first():
        raise HTTPException(409, detail="Email already exists")
    user = models.User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user