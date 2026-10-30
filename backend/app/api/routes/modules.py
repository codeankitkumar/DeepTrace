from fastapi import APIRouter, Depends

from app.core import security
from app.db import models
from app.db.database import get_db
from app.forensics.registry import list_modules
from sqlalchemy.orm import Session

router = APIRouter(prefix="/modules", tags=["modules"])


@router.get("")
def modules(_: models.User = Depends(security.get_current_user)):
    return {"modules": list_modules()}