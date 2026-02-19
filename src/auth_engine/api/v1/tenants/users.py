import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.deps import get_audit_service, get_db
from auth_engine.api.dependencies.rbac import check_tenant_permission
from auth_engine.models import UserORM
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.schemas.tenant import TenantInviteRequest
from auth_engine.schemas.user import UserResponse
from auth_engine.services.audit_service import AuditService
from auth_engine.services.auth_service import AuthService
from auth_engine.services.email.resolver import EmailServiceResolver
from auth_engine.services.role_service import RoleService
from auth_engine.services.tenant_service import TenantService

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/{tenant_id}/users", response_model=list[UserResponse])
async def list_tenant_users(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_tenant_permission("tenant.users.manage")),
) -> list[UserResponse]:
    user_repo = UserRepository(db)
    tenant_service = TenantService(user_repo)

    try:
        users = await tenant_service.list_tenant_users(
            tenant_id=tenant_id,
            actor=current_user,
        )

        return [UserResponse.model_validate(user) for user in users]

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc


@router.get("/{tenant_id}/users/{user_id}", response_model=UserResponse)
async def get_tenant_user(
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_tenant_permission("tenant.users.manage")),
) -> UserResponse:
    user_repo = UserRepository(db)
    tenant_service = TenantService(user_repo)

    user = await tenant_service.get_user_in_tenant(
        tenant_id=tenant_id,
        user_id=user_id,
        actor=current_user,
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found in tenant",
        )

    return UserResponse.model_validate(user)


@router.post("/{tenant_id}/users", status_code=status.HTTP_201_CREATED)
async def invite_user_to_tenant(
    tenant_id: uuid.UUID,
    payload: TenantInviteRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_tenant_permission("tenant.users.manage")),
    audit_service: AuditService = Depends(get_audit_service),
) -> dict[str, str]:
    user_repo = UserRepository(db)

    auth_service = AuthService(user_repo, session_service=None)
    role_service = RoleService(user_repo, audit_service)

    from auth_engine.repositories.email_config_repo import (
        TenantEmailConfigRepository,
    )

    email_config_repo = TenantEmailConfigRepository(db)
    email_service_resolver = EmailServiceResolver(email_config_repo)

    tenant_service = TenantService(user_repo, audit_service)

    try:
        return await tenant_service.invite_user_to_tenant(
            tenant_id=tenant_id,
            email=payload.email,
            role_name=payload.role_name,
            actor=current_user,
            auth_service=auth_service,
            role_service=role_service,
            email_service_resolver=email_service_resolver,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        logger.error(
            "Error inviting user %s to tenant %s: %s",
            payload.email,
            tenant_id,
            exc,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to invite user",
        ) from exc


@router.delete(
    "/{tenant_id}/users/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def remove_user_from_tenant(
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_tenant_permission("tenant.users.manage")),
    audit_service: AuditService = Depends(get_audit_service),
) -> None:
    user_repo = UserRepository(db)
    tenant_service = TenantService(user_repo, audit_service)

    try:
        success = await tenant_service.remove_user_from_tenant(
            tenant_id=tenant_id,
            user_id=user_id,
            actor=current_user,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found in tenant",
        )
