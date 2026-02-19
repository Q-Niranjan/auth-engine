import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.deps import get_audit_service, get_db
from auth_engine.api.dependencies.rbac import check_platform_permission
from auth_engine.models import RoleORM, TenantORM, UserORM
from auth_engine.models.role import RoleScope
from auth_engine.models.tenant import TenantType
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.services.audit_service import AuditService
from auth_engine.services.role_service import RoleService

router = APIRouter()


@router.get("/")
async def list_roles(
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_platform_permission("platform.roles.assign")),
) -> list[RoleORM]:
    """
    List roles applicable to the platform management context.
    """
    query = select(RoleORM).where(RoleORM.scope == RoleScope.PLATFORM)
    result = await db.execute(query)
    return list(result.scalars().all())


@router.post("/users/{user_id}/roles")
async def assign_role_to_user(
    user_id: uuid.UUID,
    role_name: str,
    db: AsyncSession = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service),
    current_user: UserORM = Depends(check_platform_permission("platform.roles.assign")),
) -> dict:
    """
    Assign a platform-level role (SUPER_ADMIN or PLATFORM_ADMIN) to a user.
    """
    # 1. Find the Platform Tenant
    platform_query = select(TenantORM.id).where(TenantORM.type == TenantType.PLATFORM).limit(1)
    platform_result = await db.execute(platform_query)
    platform_id = platform_result.scalar()

    if not platform_id:
        raise HTTPException(status_code=500, detail="Platform tenant not found")

    user_repo = UserRepository(db)
    role_service = RoleService(user_repo, audit_service=audit_service)

    try:
        await role_service.assign_role(
            actor=current_user, target_user_id=user_id, role_name=role_name, tenant_id=platform_id
        )
        return {"status": "success"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.delete("/users/{user_id}/roles/{role_name}")
async def remove_role_from_user(
    user_id: uuid.UUID,
    role_name: str,
    db: AsyncSession = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service),
    current_user: UserORM = Depends(check_platform_permission("platform.roles.assign")),
) -> dict:
    """
    Remove a platform-level role from a user.
    """
    # 1. Find the Platform Tenant
    platform_query = select(TenantORM.id).where(TenantORM.type == TenantType.PLATFORM).limit(1)
    platform_result = await db.execute(platform_query)
    platform_id = platform_result.scalar()

    if not platform_id:
        raise HTTPException(status_code=500, detail="Platform tenant not found")

    user_repo = UserRepository(db)
    role_service = RoleService(user_repo, audit_service=audit_service)

    try:
        success = await role_service.remove_role(
            actor=current_user, target_user_id=user_id, role_name=role_name, tenant_id=platform_id
        )
        if not success:
            raise HTTPException(status_code=404, detail="Role assignment not found")
        return {"status": "success"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
