from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env.local", env_prefix="", case_sensitive=True, extra="ignore"
    )

    # Application
    APP_NAME: str = Field(..., description="Application display name")
    APP_VERSION: str = Field(..., description="Application version")
    APP_DESCRIPTION: str = Field(..., description="OpenAPI / system description")
    DEBUG: bool = Field(..., description="Enable debug mode")
    APP_URL: str = Field(..., description="Public base URL of this API / auth host")
    API_V1_PREFIX: str = Field(..., description="API v1 route prefix")

    # Security
    SECRET_KEY: str = Field(..., min_length=32)
    ALGORITHM: str = Field(..., description="JWT/signing algorithm label")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(..., ge=1)
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(..., ge=1)

    # Database URLs
    POSTGRES_URL: str = Field(..., description="PostgreSQL connection URL")
    MONGODB_URL: str = Field(..., description="MongoDB connection URL")
    REDIS_URL: str = Field(..., description="Redis connection URL")

    # PostgreSQL specific
    POSTGRES_POOL_SIZE: int = Field(..., ge=1)
    POSTGRES_MAX_OVERFLOW: int = Field(..., ge=0)
    POSTGRES_SSL: bool = Field(
        default=False,
        description="Enable SSL for PostgreSQL (set true for hosted databases)",
    )

    # MongoDB specific
    MONGODB_DB_NAME: str = Field(..., description="MongoDB database name")

    # Redis specific
    REDIS_DB: int = Field(..., ge=0)
    REDIS_MAX_CONNECTIONS: int = Field(..., ge=1)

    # JWT Settings
    JWT_SECRET_KEY: str = Field(..., min_length=32)
    JWT_ALGORITHM: str = Field(...)
    JWT_ISSUER: str = Field(...)
    JWT_AUDIENCE: str = Field(...)

    # OIDC RS256 signing key (mount into the container; must be readable by the app user)
    OIDC_PRIVATE_KEY_PATH: str = Field(..., description="Path to OIDC RS256 private key PEM")

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = Field(..., ge=1)
    RATE_LIMIT_ENABLED: bool = Field(...)

    # Session Management
    MAX_CONCURRENT_SESSIONS: int = Field(..., ge=1)
    SESSION_TIMEOUT_MINUTES: int = Field(..., ge=1)

    # AWS infrastructure (SES region — tenant email credentials live in the DB)
    AWS_REGION: str = Field(..., description="AWS region for SES")

    # WebAuthn / Passkeys
    WEBAUTHN_RP_ID: str = Field(..., description="WebAuthn Relying Party ID")

    # CORS Settings
    CORS_ORIGINS: list[str] = Field(..., description="List of allowed origins for CORS")


settings = Settings()  # type: ignore[call-arg]
