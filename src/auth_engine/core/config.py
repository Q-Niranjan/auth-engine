from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="", case_sensitive=True, extra="ignore"
    )

    # Application
    APP_NAME: str = "AuthEngine"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = (
        "Production-ready IAM system built with "
        "FastAPI — supports authentication, multi-tenancy, fine-grained permissions, "
        "and token introspection to power multiple apps from a unified identity layer."
    )
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"

    # Super Admin Bootstrap
    # Defaulting to values that should be changed in .env
    SUPERADMIN_EMAIL: str = "admin@authengine.com"
    SUPERADMIN_PASSWORD: str = "ChangeThisStrongPassword123!"

    # Security
    SECRET_KEY: str = Field(..., min_length=32)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Database URLs
    POSTGRES_URL: str = Field(..., description="PostgreSQL connection URL")
    MONGODB_URL: str = Field(..., description="MongoDB connection URL")
    REDIS_URL: str = Field(..., description="Redis connection URL")

    # PostgreSQL specific
    POSTGRES_POOL_SIZE: int = 20
    POSTGRES_MAX_OVERFLOW: int = 10

    # MongoDB specific
    MONGODB_DB_NAME: str = "authengine"

    # Redis specific
    REDIS_DB: int = 0
    REDIS_MAX_CONNECTIONS: int = 50

    # JWT Settings
    JWT_SECRET_KEY: str = Field(..., min_length=32)
    JWT_ALGORITHM: str = "HS256"
    JWT_ISSUER: str = "authengine"
    JWT_AUDIENCE: str = "authengine-api"

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 10
    RATE_LIMIT_ENABLED: bool = True

    # Password Policy
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGIT: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True

    # Session Management
    MAX_CONCURRENT_SESSIONS: int = 5
    SESSION_TIMEOUT_MINUTES: int = 60

    # Email Settings
    EMAIL_PROVIDER: str = "sendgrid"
    EMAIL_PROVIDER_API_KEY: str = Field(
        default="", description="API Key for the configured email provider"
    )
    EMAIL_SENDER: str = Field(default="noreply@authengine.com", description="Default email sender")

    # SMS Settings
    SMS_PROVIDER: str = "twilio"
    SMS_PROVIDER_API_KEY: str = Field(
        default="", description="API Key or Secret for the configured SMS provider"
    )
    SMS_PROVIDER_ACCOUNT_SID: str = Field(default="", description="Account SID for Twilio if used")
    SMS_SENDER: str = Field(default="+1234567890", description="Default SMS sender number")

    # OAuth Settings
    GOOGLE_CLIENT_ID: str = Field(default="", description="Google OAuth Client ID")
    GOOGLE_CLIENT_SECRET: str = Field(default="", description="Google OAuth Client Secret")
    GOOGLE_REDIRECT_URI: str = Field(default="", description="Google OAuth Redirect URI")

    GITHUB_CLIENT_ID: str = Field(default="", description="GitHub OAuth Client ID")
    GITHUB_CLIENT_SECRET: str = Field(default="", description="GitHub OAuth Client Secret")
    GITHUB_REDIRECT_URI: str = Field(default="", description="GitHub OAuth Redirect URI")

    MICROSOFT_CLIENT_ID: str = Field(default="", description="Microsoft OAuth Client ID")
    MICROSOFT_CLIENT_SECRET: str = Field(default="", description="Microsoft OAuth Client Secret")
    MICROSOFT_REDIRECT_URI: str = Field(default="", description="Microsoft OAuth Redirect URI")


settings = Settings()
