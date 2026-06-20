import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from auth_engine.api.dependencies.deps import get_audit_service, get_db
from auth_engine.api.dependencies.rbac import check_platform_permission
from auth_engine.models import UserORM, UserRoleORM
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.schemas.rbac import TenantRoleAssignment
from auth_engine.schemas.user import UserResponse, UserStatusUpdate
from auth_engine.services.audit_service import AuditService
from auth_engine.services.role_service import RoleService
from auth_engine.services.user_service import UserService

router = APIRouter()


@router.get("/users", response_model=list[UserResponse])
async def list_all_users(
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_platform_permission("platform.users.manage")),
) -> list[UserResponse]:
    """
    List all users globally across the platform.
    """
    query = select(UserORM).options(joinedload(UserORM.roles).joinedload(UserRoleORM.role))
    result = await db.execute(query)
    users = list(result.unique().scalars().all())
    return [UserResponse.model_validate(u) for u in users]


@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_platform_permission("platform.users.manage")),
) -> UserResponse:
    """
    Get a specific user's details.
    """
    query = (
        select(UserORM)
        .where(UserORM.id == user_id)
        .options(joinedload(UserORM.roles).joinedload(UserRoleORM.role))
    )
    result = await db.execute(query)
    user = result.unique().scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse.model_validate(user)


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_global_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_platform_permission("platform.users.manage")),
) -> None:
    """
    Delete a user globally from the platform.
    """
    user_repo = UserRepository(db)
    user_service = UserService(user_repo)

    try:
        success = await user_service.delete_user(user_id, actor=current_user)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e)) from e

    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")


@router.patch("/users/{user_id}", response_model=UserResponse)
async def update_user_status(
    user_id: uuid.UUID,
    status_update: UserStatusUpdate,
    db: AsyncSession = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service),
    current_user: UserORM = Depends(check_platform_permission("platform.users.manage")),
) -> UserResponse:
    """
    Suspend / activate user.
    """
    user_repo = UserRepository(db)
    user_service = UserService(user_repo, audit_service=audit_service)

    try:
        user = await user_service.update_user_status(
            user_id=user_id, status=status_update.status, actor=current_user
        )
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        return UserResponse.model_validate(user)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e


@router.post("/users/{user_id}/tenant-roles", status_code=status.HTTP_200_OK)
async def assign_tenant_role_to_user(
    user_id: uuid.UUID,
    assignment: TenantRoleAssignment,
    db: AsyncSession = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service),
    current_user: UserORM = Depends(check_platform_permission("platform.users.manage")),
) -> dict[str, str]:
    """Assign an organization role to a user in a specific tenant."""
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo, audit_service=audit_service)

    try:
        await role_service.assign_role(
            actor=current_user,
            target_user_id=user_id,
            tenant_id=assignment.tenant_id,
            role_id=assignment.role_id,
            as_platform_admin=True,
        )
        return {"status": "success"}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.delete("/users/{user_id}/tenant-roles", status_code=status.HTTP_204_NO_CONTENT)
async def remove_tenant_role_from_user(
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    role_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service),
    current_user: UserORM = Depends(check_platform_permission("platform.users.manage")),
) -> None:
    """Remove an organization role from a user in a specific tenant."""
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo, audit_service=audit_service)

    try:
        success = await role_service.remove_role(
            actor=current_user,
            target_user_id=user_id,
            tenant_id=tenant_id,
            role_id=role_id,
            as_platform_admin=True,
        )
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Role assignment not found"
            )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
