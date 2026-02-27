# core/security.py

import re
import secrets
import string
from datetime import datetime, timedelta
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext

from auth_engine.core import settings

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


class SecurityUtils:
    @staticmethod
    def hash_password(password: str) -> str:
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def validate_password_strength(password: str) -> tuple[bool, str]:
        if len(password) < settings.PASSWORD_MIN_LENGTH:
            return False, f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters"

        if settings.PASSWORD_REQUIRE_UPPERCASE and not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter"

        if settings.PASSWORD_REQUIRE_LOWERCASE and not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter"

        if settings.PASSWORD_REQUIRE_DIGIT and not re.search(r"\d", password):
            return False, "Password must contain at least one digit"

        if settings.PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"

        return True, ""

    @staticmethod
    def generate_random_token(length: int = 32) -> str:
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def generate_otp(length: int = 6) -> str:
        return "".join(secrets.choice(string.digits) for _ in range(length))

    @staticmethod
    def _get_fernet_key() -> bytes:
        import base64
        import hashlib

        # Derive a 32-byte URL-safe base64-encoded key from the secret key
        digest = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
        return base64.urlsafe_b64encode(digest)

    @staticmethod
    def encrypt_data(data: str) -> str:
        from cryptography.fernet import Fernet

        if not data:
            return ""

        f = Fernet(SecurityUtils._get_fernet_key())
        return f.encrypt(data.encode()).decode()

    @staticmethod
    def decrypt_data(encrypted_data: str) -> str:
        from cryptography.fernet import Fernet

        if not encrypted_data:
            return ""

        f = Fernet(SecurityUtils._get_fernet_key())
        return f.decrypt(encrypted_data.encode()).decode()


class TokenManager:
    @staticmethod
    def create_access_token(data: dict[str, Any], expires_delta: timedelta | None = None) -> str:
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

        to_encode.update(
            {
                "exp": expire,
                "iat": datetime.utcnow(),
                "iss": settings.JWT_ISSUER,
                "aud": settings.JWT_AUDIENCE,
            }
        )
        if "type" not in to_encode:
            to_encode["type"] = "access"

        encoded_jwt = jwt.encode(
            to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
        )
        return encoded_jwt

    @staticmethod
    def create_refresh_token(data: dict[str, Any], expires_delta: timedelta | None = None) -> str:
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

        to_encode.update(
            {
                "exp": expire,
                "iat": datetime.utcnow(),
                "iss": settings.JWT_ISSUER,
                "aud": settings.JWT_AUDIENCE,
            }
        )
        if "type" not in to_encode:
            to_encode["type"] = "refresh"

        encoded_jwt = jwt.encode(
            to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
        )
        return encoded_jwt

    @staticmethod
    def decode_token(token: str) -> dict[str, Any]:
        try:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM],
                audience=settings.JWT_AUDIENCE,
                issuer=settings.JWT_ISSUER,
            )
            return payload
        except JWTError as e:
            raise ValueError(f"Invalid token: {str(e)}") from e

    @staticmethod
    def verify_access_token(token: str) -> dict[str, Any]:
        payload = TokenManager.decode_token(token)

        if payload.get("type") != "access":
            raise ValueError("Invalid token type")

        return payload

    @staticmethod
    def verify_refresh_token(token: str) -> dict[str, Any]:
        payload = TokenManager.decode_token(token)

        if payload.get("type") != "refresh":
            raise ValueError("Invalid token type")

        return payload


# Export instances
security = SecurityUtils()
token_manager = TokenManager()
pwd_context = pwd_context
