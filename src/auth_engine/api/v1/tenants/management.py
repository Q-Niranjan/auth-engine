import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from auth_engine.api.dependencies.auth_deps import get_current_active_user
from auth_engine.api.dependencies.deps import get_audit_service, get_db
from auth_engine.api.dependencies.rbac import require_permission
from auth_engine.models import TenantORM, UserORM
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.schemas.tenant import TenantCreate, TenantResponse, TenantUpdate
from auth_engine.services.audit_service import AuditService
from auth_engine.services.tenant_service import TenantService

router = APIRouter()


@router.post("/", response_model=TenantResponse, status_code=status.HTTP_201_CREATED)
async def create_tenant(
    tenant_in: TenantCreate,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_active_user),
    audit_service: AuditService = Depends(get_audit_service),
) -> TenantORM:
    """
    Create a new tenant. Automatically assigns the creator as TENANT_OWNER.
    """
    user_repo = UserRepository(db)
    tenant_service = TenantService(user_repo, audit_service)
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
    audit_service: AuditService = Depends(get_audit_service),
) -> TenantORM:
    """
    Update tenant information.
    Requires tenant.update permission.
    """
    user_repo = UserRepository(db)
    tenant_service = TenantService(user_repo, audit_service)
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
    audit_service: AuditService = Depends(get_audit_service),
) -> None:
    """
    Delete a tenant.
    Requires tenant.delete permission.
    """
    user_repo = UserRepository(db)
    tenant_service = TenantService(user_repo, audit_service)
    try:
        success = await tenant_service.delete_tenant(tenant_id, actor=current_user)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e)) from e
    if not success:
        raise HTTPException(status_code=404, detail="Tenant not found")
