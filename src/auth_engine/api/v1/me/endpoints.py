import uuid

from fastapi import APIRouter, Depends, HTTPException, status

from auth_engine.api.dependencies.auth_deps import get_current_active_user
from auth_engine.models import UserORM
from auth_engine.schemas.tenant import TenantResponse
from auth_engine.schemas.user import UserResponse
from auth_engine.schemas.user import UserUpdate
from sqlalchemy.ext.asyncio import AsyncSession
from auth_engine.api.dependencies.deps import get_db
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError

router = APIRouter()


@router.get("/", response_model=UserResponse)
async def get_me(
    current_user: UserORM = Depends(get_current_active_user),
) -> UserResponse:
    """
    Get current user information.
    """
    return UserResponse.model_validate(current_user)


@router.get("/tenants", response_model=list[TenantResponse])
async def get_my_tenants(
    current_user: UserORM = Depends(get_current_active_user),
) -> list[TenantResponse]:
    """
    List all tenants the current user belongs to.
    """
    # Collect unique tenant IDs from the user's role assignments
    seen_tenant_ids: set[uuid.UUID] = set()
    response_tenants: list[TenantResponse] = []

    for ur in current_user.roles:
        tenant = ur.tenant
        if not tenant:
            continue

        if tenant.id in seen_tenant_ids:
            continue
        seen_tenant_ids.add(tenant.id)

        # Build the response object explicitly using scalar fields only to
        # avoid lazy-loading async relationships like `creator`/`owner`,
        # which can trigger MissingGreenlet errors during serialization.
        response_tenants.append(
            TenantResponse(
                id=tenant.id,
                name=tenant.name,
                description=tenant.description,
                type=tenant.type,
                owner_id=tenant.owner_id,
                created_by=tenant.created_by,
                created_at=tenant.created_at,
                updated_at=tenant.updated_at,
                owner=None,
                creator=None,
            )
        )

    return response_tenants


@router.get("/tenants/{tenant_id}/permissions")
async def get_my_tenant_permissions(
    tenant_id: uuid.UUID, current_user: UserORM = Depends(get_current_active_user)
) -> dict:
    """
    Get permissions for the current user in a specific tenant.
    """
    permissions = set()
    for ur in current_user.roles:
        if ur.tenant_id == tenant_id:
            for rp in ur.role.permissions:
                permissions.add(rp.permission.name)

    return {"tenant_id": tenant_id, "permissions": list(permissions)}

@router.put("/", response_model=UserResponse)
async def update_me(
    update_data: UserUpdate,
    current_user: UserORM = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """
    Update current user information.
    """
    data = update_data.model_dump(exclude_unset=True)
    if not data:
        return UserResponse.model_validate(current_user)

    query = update(UserORM).where(UserORM.id == current_user.id).values(**data)
    try:
        await db.execute(query)
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        detail = str(exc)
        if hasattr(exc, "orig"):
            detail = getattr(exc.orig, "detail", str(exc.orig))
        
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail,
        ) from exc
    except Exception as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc

    await db.refresh(current_user)
    return UserResponse.model_validate(current_user)
