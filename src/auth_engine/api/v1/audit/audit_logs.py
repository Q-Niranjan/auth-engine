from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from auth_engine.api.dependencies.auth_deps import get_current_active_superadmin
from auth_engine.schemas.audit_log import AuditLog
from auth_engine.services.audit_service import AuditService
from auth_engine.api.dependencies.deps import get_audit_service

router = APIRouter()


@router.get(
    "/",
    response_model=List[AuditLog],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(get_current_active_superadmin)],
)
async def get_audit_logs(
    user_id: Optional[UUID] = Query(None, description="Filter by User ID"),
    action: Optional[str] = Query(None, description="Filter by Action"),
    resource: Optional[str] = Query(None, description="Filter by Resource"),
    limit: int = Query(50, ge=1, le=100),
    skip: int = Query(0, ge=0),
    audit_service: AuditService = Depends(get_audit_service),
) -> List[AuditLog]:
    """
    Get audit logs. Only accessible by Super Admins.
    """
    query = {}
    if user_id:
        query["actor_id"] = str(user_id)
    if action:
        query["action"] = action
    if resource:
        query["resource"] = resource

    cursor = audit_service.collection.find(query).sort("created_at", -1).skip(skip).limit(limit)
    logs = await cursor.to_list(length=limit)
    return logs
