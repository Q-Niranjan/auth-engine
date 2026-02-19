import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.deps import get_audit_service, get_db
from auth_engine.api.dependencies.rbac import check_platform_permission
from auth_engine.models import TenantORM, UserORM
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.schemas.tenant import TenantCreate, TenantResponse, TenantUpdate
from auth_engine.services.audit_service import AuditService
from auth_engine.services.tenant_service import TenantService

router = APIRouter()


@router.post("/", response_model=TenantResponse, status_code=status.HTTP_201_CREATED)
async def create_tenant(
    tenant_in: TenantCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service),
    current_user: UserORM = Depends(check_platform_permission("platform.tenants.manage")),
) -> TenantResponse:
    """
    Create a new tenant.
    """
    user_repo = UserRepository(db)
    tenant_service = TenantService(user_repo, audit_service=audit_service)

    tenant = await tenant_service.create_tenant(
        name=tenant_in.name,
        owner_id=tenant_in.owner_id,
        created_by=current_user.id,
        description=tenant_in.description,
        type=tenant_in.type.value if tenant_in.type else "CUSTOMER",
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    return TenantResponse.model_validate(tenant)


@router.get("/", response_model=list[TenantResponse])
async def list_all_tenants(
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_platform_permission("platform.tenants.manage")),
) -> list[TenantResponse]:
    """
    List all tenants globally.
    """
    query = select(TenantORM)
    result = await db.execute(query)
    tenants = list(result.scalars().all())
    return [TenantResponse.model_validate(t) for t in tenants]


@router.get("/{tenant_id}", response_model=TenantResponse)
async def get_tenant(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_platform_permission("platform.tenants.manage")),
) -> TenantResponse:
    """
    View tenant details.
    """
    query = select(TenantORM).where(TenantORM.id == tenant_id)
    result = await db.execute(query)
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return TenantResponse.model_validate(tenant)


@router.put("/{tenant_id}", response_model=TenantResponse)
async def update_tenant(
    tenant_id: uuid.UUID,
    tenant_in: TenantUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service),
    current_user: UserORM = Depends(check_platform_permission("platform.tenants.manage")),
) -> TenantResponse:
    """
    Update tenant details.
    """
    user_repo = UserRepository(db)
    tenant_service = TenantService(user_repo, audit_service=audit_service)

    tenant = await tenant_service.update_tenant(
        tenant_id=tenant_id,
        actor=current_user,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        **tenant_in.model_dump(exclude_unset=True),
    )
    if not tenant:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    return TenantResponse.model_validate(tenant)


@router.delete("/{tenant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tenant(
    tenant_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service),
    current_user: UserORM = Depends(check_platform_permission("platform.tenants.manage")),
) -> None:
    """
    Delete tenant.
    """
    user_repo = UserRepository(db)
    tenant_service = TenantService(user_repo, audit_service=audit_service)

    success = await tenant_service.delete_tenant(
        tenant_id=tenant_id,
        actor=current_user,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
