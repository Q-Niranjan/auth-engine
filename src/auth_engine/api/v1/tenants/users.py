import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from auth_engine.api.dependencies.deps import get_audit_service, get_db
from auth_engine.api.dependencies.rbac import enforce_tenant_isolation, require_permission
from auth_engine.models import UserORM
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.schemas.user import UserResponse
from auth_engine.services.audit_service import AuditService
from auth_engine.services.tenant_service import TenantService

router = APIRouter()


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
    audit_service: AuditService = Depends(get_audit_service),
) -> None:
    """
    Remove a user from a tenant (removes all roles in this tenant).
    """
    user_repo = UserRepository(db)
    tenant_service = TenantService(user_repo, audit_service)
    try:
        success = await tenant_service.remove_user_from_tenant(
            tenant_id, user_id, actor=current_user
        )
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e)) from e
    if not success:
        raise HTTPException(status_code=404, detail="User not found in tenant")
