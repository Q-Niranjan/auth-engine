# core/exceptions.py

from typing import Any

from fastapi import HTTPException, status


class AuthEngineException(Exception):
    def __init__(
        self, message: str, error_code: str | None = None, details: dict[str, Any] | None = None
    ):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)


class AuthenticationError(AuthEngineException):
    pass


class InvalidCredentialsError(AuthenticationError):
    def __init__(self, message: str = "Invalid credentials"):
        super().__init__(message, error_code="INVALID_CREDENTIALS")


class UserNotFoundError(AuthenticationError):
    def __init__(self, message: str = "User not found"):
        super().__init__(message, error_code="USER_NOT_FOUND")


class UserAlreadyExistsError(AuthEngineException):
    def __init__(self, message: str = "User already exists"):
        super().__init__(message, error_code="USER_ALREADY_EXISTS")


class InvalidTokenError(AuthenticationError):
    def __init__(self, message: str = "Invalid or expired token"):
        super().__init__(message, error_code="INVALID_TOKEN")


class TokenExpiredError(AuthenticationError):
    def __init__(self, message: str = "Token has expired"):
        super().__init__(message, error_code="TOKEN_EXPIRED")


class SessionExpiredError(AuthenticationError):
    def __init__(self, message: str = "Session has expired"):
        super().__init__(message, error_code="SESSION_EXPIRED")


class MaxSessionsExceededError(AuthEngineException):
    def __init__(self, message: str = "Maximum concurrent sessions exceeded"):
        super().__init__(message, error_code="MAX_SESSIONS_EXCEEDED")


class WeakPasswordError(AuthEngineException):
    def __init__(self, message: str = "Password is too weak"):
        super().__init__(message, error_code="WEAK_PASSWORD")


class RateLimitExceededError(AuthEngineException):
    def __init__(self, message: str = "Rate limit exceeded", retry_after: int | None = None):
        super().__init__(
            message, error_code="RATE_LIMIT_EXCEEDED", details={"retry_after": retry_after}
        )


# HTTP Exception converters
def convert_to_http_exception(exc: AuthEngineException) -> HTTPException:
    status_map = {
        "INVALID_CREDENTIALS": status.HTTP_401_UNAUTHORIZED,
        "USER_NOT_FOUND": status.HTTP_404_NOT_FOUND,
        "USER_ALREADY_EXISTS": status.HTTP_409_CONFLICT,
        "INVALID_TOKEN": status.HTTP_401_UNAUTHORIZED,
        "TOKEN_EXPIRED": status.HTTP_401_UNAUTHORIZED,
        "INVALID_OTP": status.HTTP_401_UNAUTHORIZED,
        "WEAK_PASSWORD": status.HTTP_400_BAD_REQUEST,
        "RATE_LIMIT_EXCEEDED": status.HTTP_429_TOO_MANY_REQUESTS,
        "SESSION_EXPIRED": status.HTTP_401_UNAUTHORIZED,
        "MAX_SESSIONS_EXCEEDED": status.HTTP_403_FORBIDDEN,
    }

    status_code = status_map.get(exc.error_code or "", status.HTTP_500_INTERNAL_SERVER_ERROR)

    return HTTPException(
        status_code=status_code,
        detail={"message": exc.message, "error_code": exc.error_code, "details": exc.details},
    )
