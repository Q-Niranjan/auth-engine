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
from auth_engine.schemas.rbac import RoleAssignment, RoleResponse, RoleCreateRequest, RoleUpdateRequest
from auth_engine.services.audit_service import AuditService
from auth_engine.services.role_service import RoleService

router = APIRouter()


@router.get("/roles")
async def list_roles(
    scope: RoleScope | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_platform_permission("platform.roles.assign")),
) -> list[RoleResponse]:
    """
    List roles applicable to the platform management context.
    """
    query = select(RoleORM)
    if scope:
        query = query.where(RoleORM.scope == scope)
        
    result = await db.execute(query)
    roles = result.scalars().all()

    def serialize_role(r: RoleORM) -> RoleResponse:
        resp = RoleResponse.model_validate(r)
        resp.permissions = [rp.permission.name for rp in r.permissions if rp.permission]
        resp.permission_ids = [rp.permission.id for rp in r.permissions if rp.permission]
        return resp

    return [serialize_role(role) for role in roles]


@router.get("/roles/permissions")
async def list_permissions(
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_platform_permission("platform.roles.assign")),
) -> list[dict]:
    """Retrieve all the valid roles/permissions available to build roles upon."""
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
        resp = RoleResponse.model_validate(new_role)
        resp.permissions = []
        resp.permission_ids = [p for p in data.permissions]
        return resp
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
        resp = RoleResponse.model_validate(role)
        if hasattr(role, "permissions"):
            resp.permissions = [rp.permission.name for rp in role.permissions if rp.permission]
            resp.permission_ids = [rp.permission.id for rp in role.permissions if rp.permission]
        else:
            resp.permissions = []
            resp.permission_ids = []
            
        return resp
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
    Assign a platform-level role (SUPER_ADMIN or PLATFORM_ADMIN) to a user.
    """
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
            role_name=assignment.role_name,
            tenant_id=platform_id,
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
