from functools import lru_cache
from pathlib import Path

from pydantic import EmailStr, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "API Sentry"
    app_env: str = "development"
    app_debug: bool = False
    app_version: str = "1.0.0"

    app_host: str = "127.0.0.1"
    app_port: int = 8050

    app_url: str
    frontend_url: str

    secret_key: str = Field(min_length=32)

    jwt_secret_key: str = Field(min_length=32)
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 30

    database_url: str

    smtp_host: str
    smtp_port: int = 465
    smtp_username: str
    smtp_password: str
    smtp_from_email: EmailStr
    smtp_from_name: str = "API Sentry"
    smtp_use_ssl: bool = True

    email_verification_expire_minutes: int = 30
    password_reset_expire_minutes: int = 30

    max_project_upload_mb: int = 200

    project_storage_path: Path = Path(
        "/opt/apisentry/storage/projects"
    )

    report_storage_path: Path = Path(
        "/opt/apisentry/storage/reports"
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
