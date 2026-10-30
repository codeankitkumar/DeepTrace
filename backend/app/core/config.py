from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment / .env."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "DeepTrace"
    app_env: str = "development"
    secret_key: str = "change-me-to-a-long-random-string"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    refresh_token_expire_days: int = 7

    database_url: str = "sqlite:///./deeptrace.db"
    evidence_encryption_key: str = ""  # Fernet key; auto-generated if empty (dev only)

    storage_root: str = "./storage"
    max_upload_size_mb: int = 2048

    backend_cors_origins: str = "http://localhost:5173,http://localhost:3000"
    volatility_path: str = ""

    seed_admin_username: str = "admin"
    seed_admin_email: str = "admin@deeptrace.local"
    seed_admin_password: str = "ChangeMe!2026"

    @property
    def cors_origins(self) -> List[str]:
        return [o.strip() for o in self.backend_cors_origins.split(",") if o.strip()]

    @property
    def max_upload_size_bytes(self) -> int:
        return int(self.max_upload_size_mb) * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()