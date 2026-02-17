import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.auth_deps import get_current_active_user
from auth_engine.api.deps import get_db
from auth_engine.api.rbac import enforce_tenant_isolation, require_permission
from auth_engine.models import RoleORM, TenantORM, UserORM, UserRoleORM
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.schemas.rbac import RoleAssignment, RoleResponse, UserRoleResponse
from auth_engine.schemas.tenant import TenantCreate, TenantResponse, TenantUpdate
from auth_engine.schemas.user import UserResponse
from auth_engine.services.role_service import RoleService
from auth_engine.services.tenant_service import TenantService

router = APIRouter()


@router.post("/", response_model=TenantResponse, status_code=status.HTTP_201_CREATED)
async def create_tenant(
    tenant_in: TenantCreate,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_active_user),
) -> TenantORM:
    """
    Create a new tenant. Automatically assigns the creator as TENANT_OWNER.
    """
    user_repo = UserRepository(db)
    tenant_service = TenantService(user_repo)
    return await tenant_service.create_tenant(
        name=tenant_in.name, user_id=current_user.id, description=tenant_in.description
    )


@router.get("/my", response_model=list[TenantResponse])
async def list_my_tenants(
    db: AsyncSession = Depends(get_db), current_user: UserORM = Depends(get_current_active_user)
) -> list[TenantORM]:
    """
    List all tenants where the current user has assigned roles.
    """
    user_repo = UserRepository(db)
    tenant_service = TenantService(user_repo)
    return await tenant_service.list_my_tenants(current_user.id)


@router.get("/{tenant_id}", response_model=TenantResponse)
async def get_tenant_details(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.view")),
) -> TenantORM:
    """
    Get detailed information about a specific tenant.
    Scoping handled by permission check.
    """
    user_repo = UserRepository(db)
    tenant_service = TenantService(user_repo)
    try:
        tenant = await tenant_service.get_tenant(tenant_id, actor=current_user)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e)) from e

    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant


@router.put("/{tenant_id}", response_model=TenantResponse)
async def update_tenant(
    tenant_id: uuid.UUID,
    tenant_in: TenantUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.update")),
) -> TenantORM:
    """
    Update tenant information.
    Requires tenant.update permission.
    """
    user_repo = UserRepository(db)
    tenant_service = TenantService(user_repo)
    try:
        updated = await tenant_service.update_tenant(
            tenant_id, actor=current_user, **tenant_in.model_dump(exclude_unset=True)
        )
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e)) from e
    if not updated:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return updated


@router.delete("/{tenant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tenant(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.delete")),
) -> None:
    """
    Delete a tenant.
    Requires tenant.delete permission.
    """
    user_repo = UserRepository(db)
    tenant_service = TenantService(user_repo)
    try:
        success = await tenant_service.delete_tenant(tenant_id, actor=current_user)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e)) from e
    if not success:
        raise HTTPException(status_code=404, detail="Tenant not found")


@router.get("/{tenant_id}/roles", response_model=list[RoleResponse])
async def list_tenant_roles(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.roles.view")),
) -> list[RoleORM]:
    """
    List all available roles that can be assigned within this tenant.
    """
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo)
    return await role_service.list_tenant_roles()


# --- Tenant User Management ---


@router.get("/{tenant_id}/users", response_model=list[UserResponse])
async def list_tenant_users(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.users.view")),
) -> list[UserORM]:
    """
    List all users belonging to a tenant.
    """
    user_repo = UserRepository(db)
    tenant_service = TenantService(user_repo)
    try:
        return await tenant_service.list_tenant_users(tenant_id, actor=current_user)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e)) from e


@router.post("/{tenant_id}/users", status_code=status.HTTP_201_CREATED)
async def invite_user_to_tenant(
    tenant_id: uuid.UUID,
    email: str,  # Simplified for demo
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.users.manage")),
) -> dict[str, str]:
    """
    Invite a user to a tenant. Placeholder for email invitation logic.
    For now, just logs the invitation.
    """
    await (enforce_tenant_isolation(str(tenant_id)))(current_user)

    # Logic to generate invite token, send email, etc.
    import logging

    logger = logging.getLogger(__name__)
    logger.info(f"Inviting {email} to tenant {tenant_id}")

    return {"message": f"Invitation sent to {email}"}


@router.delete("/{tenant_id}/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_user_from_tenant(
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.users.manage")),
) -> None:
    """
    Remove a user from a tenant (removes all roles in this tenant).
    """
    user_repo = UserRepository(db)
    tenant_service = TenantService(user_repo)
    try:
        success = await tenant_service.remove_user_from_tenant(
            tenant_id, user_id, actor=current_user
        )
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e)) from e
    if not success:
        raise HTTPException(status_code=404, detail="User not found in tenant")


@router.get("/{tenant_id}/users/{user_id}/roles", response_model=list[UserRoleResponse])
async def get_user_tenant_roles(
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.roles.view")),
) -> list[UserRoleORM]:
    """
    Get all roles a specific user has within a tenant.
    """
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo)
    return await role_service.get_user_roles_in_tenant(user_id, tenant_id)


@router.post("/{tenant_id}/users/{user_id}/roles", status_code=status.HTTP_200_OK)
async def assign_user_role(
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    assignment: RoleAssignment,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.roles.assign")),
) -> dict[str, str]:
    """
    Assign a role to a user within a tenant.
    Enforces RBAC hierarchy.
    """
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo)

    try:
        await role_service.assign_role(
            actor=current_user,
            target_user_id=user_id,
            role_name=assignment.role_name,
            tenant_id=tenant_id,
        )
        return {"message": f"Role '{assignment.role_name}' assigned successfully"}
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e)) from e


@router.delete(
    "/{tenant_id}/users/{user_id}/roles/{role_name}", status_code=status.HTTP_204_NO_CONTENT
)
async def remove_user_role(
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    role_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.roles.assign")),
) -> None:
    """
    Remove a specific role from a user within a tenant.
    Enforces RBAC hierarchy.
    """
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo)

    try:
        success = await role_service.remove_role(
            actor=current_user, target_user_id=user_id, role_name=role_name, tenant_id=tenant_id
        )
        if not success:
            raise HTTPException(status_code=404, detail="Role assignment not found")
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e)) from e
