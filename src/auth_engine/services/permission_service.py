import uuid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from auth_engine.models import RoleORM, UserORM, UserRoleORM, PermissionORM, RolePermissionORM

class PermissionService:
    @staticmethod
    async def has_permission(
        db: AsyncSession,
        user: UserORM,
        permission_name: str,
        tenant_id: uuid.UUID | None = None,
    ) -> bool:
        """
        Check if a user has a specific permission in a given tenant context.
        If tenant_id is None, it checks for Platform-level permissions.
        """
        # If no tenant context is provided, we check against the Platform tenant
        # Special case: if we are checking "platform.*" permissions, we should probably check Platform context anyway.
        
        query = (
            select(PermissionORM)
            .join(RolePermissionORM)
            .join(RoleORM)
            .join(UserRoleORM)
            .where(
                UserRoleORM.user_id == user.id,
                PermissionORM.name == permission_name,
            )
        )

        if tenant_id:
            # Check for permission in the specific tenant
            # OR check if the user has the permission via a PLATFORM role
            from auth_engine.models.role import RoleScope
            
            query = query.where(
                (UserRoleORM.tenant_id == tenant_id) | 
                (RoleORM.scope == RoleScope.PLATFORM)
            )
        else:
            # Platform level check - only check roles assigned to the Platform tenant (implicit or explicit)
            # Actually, if tenant_id is None, we should probably find the platform tenant ID.
            from auth_engine.models.tenant import TenantORM, TenantType
            
            platform_subquery = select(TenantORM.id).where(TenantORM.type == TenantType.PLATFORM).scalar_subquery()
            query = query.where(UserRoleORM.tenant_id == platform_subquery)

        result = await db.execute(query)
        return result.scalar_one_or_none() is not None
