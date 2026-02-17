import uuid

from auth_engine.models import UserORM
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.services.permission_service import PermissionService


class UserService:
    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo

    async def delete_user(self, user_id: uuid.UUID, actor: UserORM) -> bool:
        if not await PermissionService.has_permission(
            self.user_repo.session, actor, "platform.users.manage"
        ):
            raise ValueError("Insufficient permissions: Missing 'platform.users.manage'")

        deleted = await self.user_repo.delete(user_id)
        if deleted:
            await self.user_repo.session.commit()
        return deleted
