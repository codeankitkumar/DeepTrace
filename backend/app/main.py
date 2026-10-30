"""DeepTrace FastAPI application entrypoint."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core import security
from app.core.config import settings
from app.db import models
from app.db.database import Base, SessionLocal, engine
from app.api.routes import (
    assistant, auth, cases, dashboard, evidence, modules, reports, timeline, users,
)


def create_tables() -> None:
    Base.metadata.create_all(bind=engine)


def seed_admin() -> None:
    db = SessionLocal()
    try:
        if db.query(models.User).filter(models.User.role == "admin").first():
            return
        admin = models.User(
            username=settings.seed_admin_username,
            email=settings.seed_admin_email,
            hashed_password=security.hash_password(settings.seed_admin_password),
            role="admin",
            is_active=True,
        )
        db.add(admin)
        db.commit()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    seed_admin()
    yield


app = FastAPI(
    title="DeepTrace — Digital Forensics Investigation Platform",
    version="0.1.0",
    description=(
        "API for evidence management, forensic analysis modules, timeline reconstruction, "
        "AI investigation assistance, and structured report generation. "
        "AI outputs are hypotheses, not verified findings."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_PREFIX = "/api"

for r in (auth.router, users.router, cases.router, evidence.router, modules.router,
          timeline.router, dashboard.router, assistant.router, reports.router):
    app.include_router(r, prefix=API_PREFIX)


@app.get("/api/health", tags=["system"])
def health():
    return {"status": "ok", "app": settings.app_name, "version": "0.1.0"}