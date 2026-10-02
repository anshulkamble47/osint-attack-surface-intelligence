"""Application configuration using Pydantic Settings."""

from typing import List, Union
from pydantic import AnyHttpUrl, field_validator, ValidationInfo
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Global application settings and environment variables."""

    # Project metadata
    PROJECT_NAME: str = "OSINT-Based Attack Surface Intelligence & Risk Analysis Platform"
    PROJECT_SLUG: str = "osint_attack_surface_platform"
    VERSION: str = "0.1.0"
    API_V1_PREFIX: str = "/api"

    # Environment
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # Server configuration
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000

    # CORS configuration
    CORS_ORIGINS: Union[str, List[str]] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    # Database
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_DB: str = "osint_platform"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    DATABASE_URL: str = "postgresql+psycopg://postgres:postgres@localhost:5432/osint_platform"

    # Security & Authentication
    JWT_SECRET: str = "development_jwt_secret_replace_in_production_environment_random_key_64chars"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440

    @field_validator("JWT_SECRET")
    @classmethod
    def validate_jwt_secret(cls, v: str, info: ValidationInfo) -> str:
        env = info.data.get("ENVIRONMENT", "development")
        if env == "production":
            if not v or "replace_in_production" in v or len(v) < 32:
                raise ValueError(
                    "In production environment, JWT_SECRET must be explicitly set to a cryptographically strong secret via environment configuration."
                )
        return v

    # External APIs & Certificate Transparency Configuration
    GROQ_API_KEY: str = ""
    CTLOGS_API_KEY: str = ""
    CT_PRIMARY_PROVIDER: str = "crt.sh"
    CT_FALLBACK_ENABLED: bool = True
    CT_PROVIDER_TIMEOUT_SECONDS: float = 15.0

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
