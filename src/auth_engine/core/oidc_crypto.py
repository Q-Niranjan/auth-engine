import logging

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from jose import jwk

from auth_engine.core.config import settings

logger = logging.getLogger(__name__)

OIDC_RSA_PRIVATE_KEY: str | None = None
OIDC_RSA_PUBLIC_KEY: str | None = None
OIDC_JWK: dict | None = None

PEM_FILE_PATH = settings.OIDC_PRIVATE_KEY_PATH


def _load_oidc_keys() -> None:
    global OIDC_RSA_PRIVATE_KEY, OIDC_RSA_PUBLIC_KEY, OIDC_JWK

    try:
        with open(PEM_FILE_PATH, "rb") as key_file:
            _private_key = serialization.load_pem_private_key(
                key_file.read(), password=None, backend=default_backend()
            )

        OIDC_RSA_PRIVATE_KEY = _private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        _public_key = _private_key.public_key()
        OIDC_RSA_PUBLIC_KEY = _public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        jwk_dict = jwk.construct(OIDC_RSA_PUBLIC_KEY, algorithm="RS256").to_dict()
        jwk_dict.update({"use": "sig", "kid": "rsa1", "alg": "RS256"})
        OIDC_JWK = jwk_dict
    except FileNotFoundError:
        OIDC_RSA_PRIVATE_KEY = None
        OIDC_RSA_PUBLIC_KEY = None
        OIDC_JWK = None
        logger.warning(
            "OIDC RS256 key not found at %s — RS256 signing disabled (HS256 fallback).",
            PEM_FILE_PATH,
        )
    except PermissionError:
        OIDC_RSA_PRIVATE_KEY = None
        OIDC_RSA_PUBLIC_KEY = None
        OIDC_JWK = None
        logger.warning(
            "Cannot read OIDC key at %s (permission denied). "
            "Ensure the file is mounted and readable by the container's authengine user.",
            PEM_FILE_PATH,
        )


_load_oidc_keys()


def get_pairwise_sub(sector_identifier: str, local_sub: str, salt: str = "default_salt") -> str:
    import base64
    import hashlib

    msg = f"{sector_identifier}|{local_sub}|{salt}"
    digest = hashlib.sha256(msg.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
