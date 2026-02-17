import uuid

from auth_engine.models import UserORM
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
