import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.deps import get_audit_service, get_db
from auth_engine.api.dependencies.rbac import check_platform_permission
from auth_engine.models import RoleORM, TenantORM, UserORM
from auth_engine.models.role import RoleScope
from auth_engine.models.tenant import TenantType
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.schemas.rbac import (
    RoleAssignment,
    RoleCreateRequest,
    RoleResponse,
    RoleUpdateRequest,
)
from auth_engine.services.audit_service import AuditService
from auth_engine.services.role_service import RoleService

router = APIRouter()


def serialize_role(r: RoleORM) -> RoleResponse:
    return RoleResponse.model_validate(r)


@router.get("/roles")
async def list_roles(
    scope: RoleScope | None = None,
    templates: bool | None = Query(None, description="Filter tenant role templates"),
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_platform_permission("platform.roles.assign")),
) -> list[RoleResponse]:
    """
    List platform roles and/or tenant role templates (not per-organization instances).
    """
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo)

    if templates is True:
        roles = await role_service.list_role_templates()
    elif scope == RoleScope.PLATFORM:
        roles = await role_service.list_platform_roles()
    elif scope == RoleScope.TENANT:
        roles = await role_service.list_role_templates()
    else:
        platform_roles = await role_service.list_platform_roles()
        templates_list = await role_service.list_role_templates()
        roles = platform_roles + templates_list

    return [serialize_role(role) for role in roles]


@router.get("/roles/permissions")
async def list_permissions(
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_platform_permission("platform.roles.assign")),
) -> list[dict]:
    """Retrieve all permissions available to build roles upon."""
    from sqlalchemy import select

    from auth_engine.models import PermissionORM

    res = await db.execute(select(PermissionORM))
    perms = res.scalars().all()
    return [{"id": str(p.id), "name": p.name, "description": p.description} for p in perms]


@router.post("/roles")
async def create_role(
    data: RoleCreateRequest,
    db: AsyncSession = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service),
    current_user: UserORM = Depends(check_platform_permission("platform.roles.assign")),
) -> RoleResponse:
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo, audit_service=audit_service)

    try:
        new_role = await role_service.create_role(data)
        return serialize_role(new_role)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.put("/roles/{role_id}")
async def update_role(
    role_id: uuid.UUID,
    data: RoleUpdateRequest,
    db: AsyncSession = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service),
    current_user: UserORM = Depends(check_platform_permission("platform.roles.assign")),
) -> RoleResponse:
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo, audit_service=audit_service)

    try:
        role = await role_service.update_role(role_id, data)
        return serialize_role(role)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.delete("/roles/{role_id}")
async def delete_role(
    role_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service),
    current_user: UserORM = Depends(check_platform_permission("platform.roles.assign")),
) -> dict:
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo, audit_service=audit_service)

    try:
        await role_service.delete_role(role_id)
        return {"status": "success"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/users/{user_id}/roles")
async def assign_role_to_user(
    user_id: uuid.UUID,
    assignment: RoleAssignment,
    db: AsyncSession = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service),
    current_user: UserORM = Depends(check_platform_permission("platform.roles.assign")),
) -> dict:
    """
    Assign a platform-level role to a user.
    """
    from sqlalchemy import select

    platform_query = select(TenantORM.id).where(TenantORM.type == TenantType.PLATFORM).limit(1)
    platform_result = await db.execute(platform_query)
    platform_id = platform_result.scalar()

    if not platform_id:
        raise HTTPException(status_code=500, detail="Platform tenant not found")

    user_repo = UserRepository(db)
    role_service = RoleService(user_repo, audit_service=audit_service)

    try:
        await role_service.assign_role(
            actor=current_user,
            target_user_id=user_id,
            tenant_id=platform_id,
            role_name=assignment.role_name,
            role_id=assignment.role_id,
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
    from sqlalchemy import select

    platform_query = select(TenantORM.id).where(TenantORM.type == TenantType.PLATFORM).limit(1)
    platform_result = await db.execute(platform_query)
    platform_id = platform_result.scalar()

    if not platform_id:
        raise HTTPException(status_code=500, detail="Platform tenant not found")

    user_repo = UserRepository(db)
    role_service = RoleService(user_repo, audit_service=audit_service)

    try:
        success = await role_service.remove_role(
            actor=current_user,
            target_user_id=user_id,
            tenant_id=platform_id,
            role_name=role_name,
        )
        if not success:
            raise HTTPException(status_code=404, detail="Role assignment not found")
        return {"status": "success"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
