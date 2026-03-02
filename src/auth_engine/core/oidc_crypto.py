import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from jose import jwk

# Load private key
PEM_FILE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))), "oidc_private.pem")

try:
    with open(PEM_FILE_PATH, "rb") as key_file:
        _private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
        
    OIDC_RSA_PRIVATE_KEY = _private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")
    
    _public_key = _private_key.public_key()
    OIDC_RSA_PUBLIC_KEY = _public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    # Generate JWK from RSA public key
    jwk_dict = jwk.construct(OIDC_RSA_PUBLIC_KEY, algorithm="RS256").to_dict()
    jwk_dict.update({
        "use": "sig",
        "kid": "rsa1",
        "alg": "RS256"
    })
    OIDC_JWK = jwk_dict

except FileNotFoundError:
    OIDC_RSA_PRIVATE_KEY = None
    OIDC_RSA_PUBLIC_KEY = None
    OIDC_JWK = None
    print(f"Warning: {PEM_FILE_PATH} not found. RS256 signing will be disabled.")


def get_pairwise_sub(sector_identifier: str, local_sub: str, salt: str = "default_salt") -> str:
    import hashlib
    import base64
    msg = f"{sector_identifier}|{local_sub}|{salt}"
    digest = hashlib.sha256(msg.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
