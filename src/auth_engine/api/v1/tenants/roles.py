import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.deps import get_audit_service, get_db
from auth_engine.api.dependencies.rbac import check_tenant_permission
from auth_engine.models import UserORM
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.schemas.rbac import (
    RoleAssignment,
    RoleResponse,
    UserRoleResponse,
)
from auth_engine.services.audit_service import AuditService
from auth_engine.services.role_service import RoleService

router = APIRouter()


@router.get("/{tenant_id}/roles", response_model=list[RoleResponse])
async def list_tenant_roles(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_tenant_permission("tenant.roles.assign")),
) -> list[RoleResponse]:
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo)

    roles = await role_service.list_tenant_roles()
    return [RoleResponse.model_validate(r) for r in roles]


@router.get(
    "/{tenant_id}/users/{user_id}/roles",
    response_model=list[UserRoleResponse],
)
async def get_user_tenant_roles(
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_tenant_permission("tenant.roles.assign")),
) -> list[UserRoleResponse]:
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo)

    assignments = await role_service.get_user_roles_in_tenant(
        user_id=user_id,
        tenant_id=tenant_id,
    )
    return [UserRoleResponse.model_validate(a) for a in assignments]


@router.post(
    "/{tenant_id}/users/{user_id}/roles",
    status_code=status.HTTP_200_OK,
)
async def assign_user_role(
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    assignment: RoleAssignment,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_tenant_permission("tenant.roles.assign")),
    audit_service: AuditService = Depends(get_audit_service),
) -> dict[str, str]:
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
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc


@router.delete(
    "/{tenant_id}/users/{user_id}/roles/{role_name}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def remove_user_role(
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    role_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_tenant_permission("tenant.roles.assign")),
    audit_service: AuditService = Depends(get_audit_service),
) -> None:
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo, audit_service)

    try:
        success = await role_service.remove_role(
            actor=current_user,
            target_user_id=user_id,
            role_name=role_name,
            tenant_id=tenant_id,
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role assignment not found",
            )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc
