import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from auth_engine.api.dependencies.deps import get_audit_service, get_db
from auth_engine.api.dependencies.rbac import check_tenant_permission
from auth_engine.models import UserORM, UserRoleORM
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.schemas.user import UserResponse
from auth_engine.services.audit_service import AuditService
from auth_engine.services.auth_service import AuthService
from auth_engine.services.email.resolver import EmailServiceResolver
from auth_engine.services.role_service import RoleService
from auth_engine.services.tenant_service import TenantService

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/{tenant_id}/", response_model=list[UserResponse])
async def list_tenant_users(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_tenant_permission("tenant.users.manage")),
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


@router.post("/{tenant_id}/", status_code=status.HTTP_201_CREATED)
async def invite_user_to_tenant(
    tenant_id: uuid.UUID,
    email: str,
    role_name: str = "TENANT_USER",
    request: Request = None,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_tenant_permission("tenant.users.manage")),
    audit_service: AuditService = Depends(get_audit_service),
) -> dict:
    """
    Invite a user to a tenant with a specific role.
    If user doesn't exist, creates account with PENDING_VERIFICATION status.
    Sends invitation email in both cases.
    """
    user_repo = UserRepository(db)

    # Create service instances
    session_service = None  # Optional - not needed for this flow
    auth_service = AuthService(user_repo, session_service=session_service)
    role_service = RoleService(user_repo, audit_service)

    # Email resolver - get tenant-specific or default email config
    from auth_engine.repositories.email_config_repo import TenantEmailConfigRepository

    email_config_repo = TenantEmailConfigRepository(db)
    email_service_resolver = EmailServiceResolver(email_config_repo)

    tenant_service = TenantService(user_repo, audit_service)

    try:
        result = await tenant_service.invite_user_to_tenant(
            tenant_id=tenant_id,
            email=email,
            role_name=role_name,
            actor=current_user,
            auth_service=auth_service,
            role_service=role_service,
            email_service_resolver=email_service_resolver,
            ip_address=request.client.host if request and request.client else None,
            user_agent=request.headers.get("user-agent") if request else None,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Error inviting user {email} to tenant {tenant_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to invite user") from e


@router.get("/{tenant_id}/{user_id}", response_model=UserResponse)
async def get_tenant_user(
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_tenant_permission("tenant.users.manage")),
) -> UserORM:
    """
    Get tenant user.
    """
    query = (
        select(UserORM)
        .join(UserRoleORM)
        .where(UserORM.id == user_id, UserRoleORM.tenant_id == tenant_id)
        .options(joinedload(UserORM.roles).joinedload(UserRoleORM.role))
    )
    result = await db.execute(query)
    user = result.unique().scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found in tenant")
    return user


@router.delete("/{tenant_id}/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_user_from_tenant(
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_tenant_permission("tenant.users.manage")),
    audit_service: AuditService = Depends(get_audit_service),
) -> None:
    """
    Remove a user from a tenant.
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
