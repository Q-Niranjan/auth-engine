"""
WebAuthnStrategy
================

Implements the WebAuthn registration (attestation) and authentication
(assertion) ceremonies using the ``webauthn`` (py_webauthn) library.

Design decisions
----------------
* Pure strategy — no DB or Redis access. The service layer owns those.
* All byte ↔ base64url conversions happen here so callers work with plain dicts.
* ``rp_id``   defaults to the host portion of ``APP_URL`` (e.g. "example.com").
* ``rp_name`` defaults to ``APP_NAME`` from settings.

Install dependency
------------------
    pip install webauthn
"""

import base64
import json
import os
from typing import Any
from urllib.parse import urlparse

import webauthn
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from auth_engine.core.config import settings


def _rp_id() -> str:
    """Relying Party ID. Prefers WEBAUTHN_RP_ID; falls back to the APP_URL host."""
    configured = getattr(settings, "WEBAUTHN_RP_ID", "")
    if configured:
        return configured

    url = getattr(settings, "APP_URL", "http://localhost:8000")
    host = urlparse(url).hostname or "localhost"
    return host


def _rp_name() -> str:
    return getattr(settings, "APP_NAME", "AuthEngine")


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    # Pad to multiple of 4
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


class WebAuthnStrategy:
    """
    Stateless helper that wraps py_webauthn for registration and authentication.

    The service layer calls these methods and handles all persistence (Redis
    for challenges, PostgreSQL for credentials).
    """

    # ── Registration ──────────────────────────────────────────────────────────

    @staticmethod
    def generate_registration_options(
        user_id: str,
        user_email: str,
        user_display_name: str,
        existing_credential_ids: list[bytes] | None = None,
    ) -> tuple[dict, bytes]:
        """
        Build PublicKeyCredentialCreationOptions.

        Returns
        -------
        options_json : dict
            JSON-serialisable options to send to the browser.
        challenge : bytes
            Raw challenge bytes — caller must store these in Redis.
        """
        challenge = os.urandom(32)

        exclude_credentials = [
            PublicKeyCredentialDescriptor(id=cred_id) for cred_id in (existing_credential_ids or [])
        ]

        options = webauthn.generate_registration_options(
            rp_id=_rp_id(),
            rp_name=_rp_name(),
            user_id=user_id.encode(),
            user_name=user_email,
            user_display_name=user_display_name or user_email,
            challenge=challenge,
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
            exclude_credentials=exclude_credentials,
            timeout=60_000,
        )

        # py_webauthn returns a dataclass — convert to dict for JSON transport
        options_dict = webauthn.options_to_json(options)

        return json.loads(options_dict), challenge

    @staticmethod
    def verify_registration_response(
        credential_json: dict,
        expected_challenge: bytes,
    ) -> dict[str, Any]:
        """
        Verify the attestation response from the browser.

        Returns a dict with:
            credential_id  : bytes
            public_key     : bytes  (CBOR-encoded)
            sign_count     : int
            aaguid         : str
            uv_flag        : bool
        """

        verified = webauthn.verify_registration_response(
            credential=json.dumps(credential_json),
            expected_challenge=expected_challenge,
            expected_rp_id=_rp_id(),
            expected_origin=_get_expected_origin(),
            require_user_verification=False,
        )

        aaguid = str(verified.aaguid) if verified.aaguid else ""

        return {
            "credential_id": verified.credential_id,
            "public_key": verified.credential_public_key,
            "sign_count": verified.sign_count,
            "aaguid": aaguid,
            "uv_flag": verified.user_verified,
        }

    # ── Authentication ────────────────────────────────────────────────────────

    @staticmethod
    def generate_authentication_options(
        allowed_credential_ids: list[bytes] | None = None,
    ) -> tuple[dict, bytes]:
        """
        Build PublicKeyCredentialRequestOptions.

        Returns
        -------
        options_json : dict
        challenge    : bytes  — store in Redis keyed by hex(challenge)
        """
        challenge = os.urandom(32)

        allow_credentials = [
            PublicKeyCredentialDescriptor(id=cred_id) for cred_id in (allowed_credential_ids or [])
        ]

        options = webauthn.generate_authentication_options(
            rp_id=_rp_id(),
            challenge=challenge,
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
            timeout=60_000,
        )

        options_dict = webauthn.options_to_json(options)
        return json.loads(options_dict), challenge

    @staticmethod
    def verify_authentication_response(
        credential_json: dict,
        expected_challenge: bytes,
        credential_id: bytes,
        public_key: bytes,
        current_sign_count: int,
    ) -> dict[str, Any]:
        """
        Verify the assertion response from the browser.

        Returns a dict with:
            sign_count : int   — new value to persist
            uv_flag    : bool
        """

        verified = webauthn.verify_authentication_response(
            credential=json.dumps(credential_json),
            expected_challenge=expected_challenge,
            expected_rp_id=_rp_id(),
            expected_origin=_get_expected_origin(),
            credential_public_key=public_key,
            credential_current_sign_count=current_sign_count,
            require_user_verification=False,
        )

        return {
            "sign_count": verified.new_sign_count,
            "uv_flag": verified.user_verified,
        }


def _get_expected_origin() -> str:
    """Expected ceremony origin — the frontend where passkeys are used.

    Uses APP_URL as the origin.
    """
    url_str = str(getattr(settings, "APP_URL", "http://localhost:8000"))

    p = urlparse(url_str)
    scheme = str(p.scheme)
    hostname = str(p.hostname)

    origin = f"{scheme}://{hostname}"
    if p.port and p.port not in (80, 443):
        origin += f":{p.port}"
    return origin
