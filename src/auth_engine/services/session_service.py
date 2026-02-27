import uuid
from datetime import datetime, timedelta

import redis.asyncio as redis

from auth_engine.schemas.user import UserSession


class SessionService:
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client

    async def create_session(
        self,
        user_id: uuid.UUID,
        expires_in_seconds: int,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> str:
        session_id = str(uuid.uuid4())
        session_key = f"session:{user_id}:{session_id}"

        expires_at = datetime.utcnow() + timedelta(seconds=expires_in_seconds)

        session_data = UserSession(
            session_id=session_id,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            created_at=datetime.utcnow(),
            expires_at=expires_at,
        )

        await self.redis.setex(session_key, expires_in_seconds, session_data.model_dump_json())
        return session_id

    async def list_sessions(self, user_id: uuid.UUID) -> list[UserSession]:
        pattern = f"session:{user_id}:*"
        keys = await self.redis.keys(pattern)

        sessions = []
        for key in keys:
            data = await self.redis.get(key)
            if data:
                sessions.append(UserSession.model_validate_json(data))

        # Sort by created_at descending
        sessions.sort(key=lambda x: x.created_at, reverse=True)
        return sessions

    async def delete_session(self, user_id: uuid.UUID, session_id: str) -> bool:
        session_key = f"session:{user_id}:{session_id}"
        result = await self.redis.delete(session_key)
        return result > 0

    async def delete_all_sessions(self, user_id: uuid.UUID) -> None:
        pattern = f"session:{user_id}:*"
        keys = await self.redis.keys(pattern)
        if keys:
            await self.redis.delete(*keys)

    async def blacklist_token(self, jti: str, expires_in_seconds: int) -> None:
        await self.redis.setex(f"blacklist:{jti}", expires_in_seconds, "1")

    async def is_token_blacklisted(self, jti: str) -> bool:
        return await self.redis.exists(f"blacklist:{jti}") > 0

    async def is_session_active(self, user_id: uuid.UUID | str, session_id: str) -> bool:
        session_key = f"session:{user_id}:{session_id}"
        return await self.redis.exists(session_key) > 0
