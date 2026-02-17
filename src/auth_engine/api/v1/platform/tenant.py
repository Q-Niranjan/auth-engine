from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.deps import get_db
from auth_engine.api.dependencies.rbac import require_permission
from auth_engine.models import TenantORM, UserORM
from auth_engine.schemas.tenant import TenantResponse

router = APIRouter()


@router.get("/", response_model=list[TenantResponse])
async def list_all_tenants(
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("platform.tenants.view")),
) -> list[TenantORM]:
    """
    List all tenants globally.
    Requires platform admin privileges.
    """
    query = select(TenantORM)
    result = await db.execute(query)
    return list(result.scalars().all())
