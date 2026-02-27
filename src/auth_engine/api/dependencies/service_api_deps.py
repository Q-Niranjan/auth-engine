import hashlib

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.deps import get_db
from auth_engine.models.service_api_key import ServiceApiKeyORM
from auth_engine.repositories.service_api_key_repo import ServiceApiKeyRepository


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


async def get_verified_api_key(
    x_api_key: str = Header(..., alias="X-API-Key", description="Service API key"),
    db: AsyncSession = Depends(get_db),
) -> ServiceApiKeyORM:
    """
    Dependency that validates the X-API-Key header.
    Raises 401 if the key is missing, invalid, inactive, or expired.
    """
    key_hash = _hash_key(x_api_key)
    repo = ServiceApiKeyRepository(db)
    api_key = await repo.get_by_key_hash(key_hash)

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    await repo.touch_last_used(api_key.id)

    return api_key
