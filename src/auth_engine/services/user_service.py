import uuid

from auth_engine.models import UserORM
from auth_engine.models.user import UserStatus
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.services.audit_service import AuditService
from auth_engine.services.permission_service import PermissionService


class UserService:
    def __init__(self, user_repo: UserRepository, audit_service: AuditService | None = None):
        self.user_repo = user_repo
        self.audit_service = audit_service

    async def delete_user(self, user_id: uuid.UUID, actor: UserORM) -> bool:
        if not await PermissionService.has_permission(
            self.user_repo.session, actor, "platform.users.manage"
        ):
            raise ValueError("Insufficient permissions: Missing 'platform.users.manage'")

        deleted = await self.user_repo.delete(user_id)
        if deleted:
            await self.user_repo.session.commit()

            # Audit Log
            if self.audit_service:
                await self.audit_service.log(
                    action="USER_DELETED",
                    resource="User",
                    resource_id=str(user_id),
                    actor_id=actor.id,
                    metadata={"deleted_by": str(actor.id)},
                )

        return deleted

    async def update_user_status(
        self, user_id: uuid.UUID, status: str, actor: UserORM
    ) -> UserORM | None:
        if not await PermissionService.has_permission(
            self.user_repo.session, actor, "platform.users.manage"
        ):
            raise ValueError("Insufficient permissions: Missing 'platform.users.manage'")

        user = await self.user_repo.get(user_id)
        if not user:
            return None

        old_status = user.status
        user.status = UserStatus(status)
        await self.user_repo.session.commit()

        # Audit Log
        if self.audit_service:
            await self.audit_service.log(
                action="USER_STATUS_UPDATED",
                resource="User",
                resource_id=str(user_id),
                actor_id=actor.id,
                metadata={
                    "old_status": old_status,
                    "new_status": status,
                    "updated_by": str(actor.id),
                },
            )

        return user
