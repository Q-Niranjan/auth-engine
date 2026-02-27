import pyotp

from auth_engine.auth_strategies.base import TokenBasedStrategy
from auth_engine.core.exceptions import AuthenticationError, InvalidTokenError
from auth_engine.core.security import SecurityUtils


class TOTPStrategy(TokenBasedStrategy):
    def __init__(self) -> None:
        super().__init__("totp")

    @staticmethod
    def generate_secret() -> str:
        return pyotp.random_base32()

    @staticmethod
    def get_provisioning_uri(secret: str, email: str, issuer: str = "AuthEngine") -> str:
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=email, issuer_name=issuer)

    @staticmethod
    def verify_code(encrypted_secret: str, code: str) -> bool:
        secret = SecurityUtils.decrypt_data(encrypted_secret)
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)

    async def authenticate(self, credentials: dict) -> dict:
        encrypted_secret = credentials.get("encrypted_secret")
        code = credentials.get("code")

        if not encrypted_secret or not code:
            raise AuthenticationError("TOTP secret and code are required")

        if not self.verify_code(encrypted_secret, code):
            raise InvalidTokenError("Invalid or expired TOTP code")

        return {"verified": True, "strategy": self.name}

    async def validate(self, token: str) -> dict:
        raise NotImplementedError("TOTP strategy does not support token validation")
