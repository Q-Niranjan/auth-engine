import uuid

from auth_engine.repositories.user_repo import UserRepository


class UserService:
    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo

    async def delete_user(self, user_id: uuid.UUID) -> bool:
        deleted = await self.user_repo.delete(user_id)
        if deleted:
            await self.user_repo.session.commit()
        return deleted
