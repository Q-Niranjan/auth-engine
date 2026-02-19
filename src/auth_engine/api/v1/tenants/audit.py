import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.deps import get_audit_service, get_db
from auth_engine.api.dependencies.rbac import check_tenant_permission
from auth_engine.models import UserORM
from auth_engine.schemas.audit_log import AuditLog
from auth_engine.services.audit_service import AuditService

router = APIRouter()


@router.get("/{tenant_id}/audit-logs", response_model=list[AuditLog])
async def get_tenant_audit_logs(
    tenant_id: uuid.UUID,
    user_id: uuid.UUID | None = Query(None),
    action: str | None = Query(None),
    limit: int = Query(50, ge=1, le=100),
    skip: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service),
    current_user: UserORM = Depends(check_tenant_permission("tenant.users.manage")),
) -> list[AuditLog]:
    """
    Get audit logs for a specific tenant.
    """
    query = {"tenant_id": str(tenant_id)}
    if user_id:
        query["actor_id"] = str(user_id)
    if action:
        query["action"] = action

    cursor = audit_service.collection.find(query).sort("created_at", -1).skip(skip).limit(limit)
    logs = await cursor.to_list(length=limit)
    return logs
