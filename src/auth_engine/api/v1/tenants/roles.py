import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from auth_engine.api.dependencies.deps import get_audit_service, get_db
from auth_engine.api.dependencies.rbac import require_permission
from auth_engine.models import RoleORM, UserORM, UserRoleORM
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.schemas.rbac import RoleAssignment, RoleResponse, UserRoleResponse
from auth_engine.services.audit_service import AuditService
from auth_engine.services.role_service import RoleService

router = APIRouter()


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
    audit_service: AuditService = Depends(get_audit_service),
) -> dict[str, str]:
    """
    Assign a role to a user within a tenant.
    Enforces RBAC hierarchy.
    """
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo, audit_service)

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
    audit_service: AuditService = Depends(get_audit_service),
) -> None:
    """
    Remove a specific role from a user within a tenant.
    Enforces RBAC hierarchy.
    """
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo, audit_service)

    try:
        success = await role_service.remove_role(
            actor=current_user, target_user_id=user_id, role_name=role_name, tenant_id=tenant_id
        )
        if not success:
            raise HTTPException(status_code=404, detail="Role assignment not found")
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e)) from e
