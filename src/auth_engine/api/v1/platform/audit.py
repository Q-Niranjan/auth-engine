from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from auth_engine.api.dependencies.deps import get_audit_service
from auth_engine.api.dependencies.rbac import check_platform_permission
from auth_engine.models import UserORM
from auth_engine.schemas.audit_log import AuditLog
from auth_engine.services.audit_service import AuditService

router = APIRouter()


@router.get(
    "/audit-logs",
    response_model=list[AuditLog],
    status_code=status.HTTP_200_OK,
)
async def get_platform_audit_logs(
    actor_id: UUID | None = Query(None, description="Filter by Actor ID"),
    target_user_id: UUID | None = Query(None, description="Filter by Target User ID"),
    tenant_id: str | None = Query(None, description="Filter by Tenant ID"),
    action: str | None = Query(None, description="Filter by Action"),
    resource: str | None = Query(None, description="Filter by Resource"),
    limit: int = Query(50, ge=1, le=100),
    skip: int = Query(0, ge=0),
    audit_service: AuditService = Depends(get_audit_service),
    current_user: UserORM = Depends(check_platform_permission("platform.audit.view")),
) -> list[AuditLog]:
    """
    Get global platform audit logs.
    """
    query = {}
    if actor_id:
        query["actor_id"] = str(actor_id)
    if target_user_id:
        query["target_user_id"] = str(target_user_id)
    if tenant_id:
        query["tenant_id"] = tenant_id
    if action:
        query["action"] = action
    if resource:
        query["resource"] = resource

    try:
        cursor = audit_service.collection.find(query).sort("created_at", -1).skip(skip).limit(limit)
        logs = await cursor.to_list(length=limit)
        return logs
    except Exception as e:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving audit logs: {str(e)}",
        ) from e


@router.get(
    "/{tenant_id}/audit-logs",
    response_model=list[AuditLog],
    status_code=status.HTTP_200_OK,
)
async def get_tenant_audit_logs(
    tenant_id: UUID,
    actor_id: UUID | None = Query(None, description="Filter by Actor ID"),
    action: str | None = Query(None, description="Filter by Action"),
    resource: str | None = Query(None, description="Filter by Resource"),
    limit: int = Query(50, ge=1, le=100),
    skip: int = Query(0, ge=0),
    audit_service: AuditService = Depends(get_audit_service),
    current_user: UserORM = Depends(check_platform_permission("platform.audit.view")),
) -> list[AuditLog]:
    """
    Get audit logs for a specific tenant.

    Includes both tenant-scoped actions and platform actions affecting it.

    Returns:
    - Logs with tenant_id = {tenant_id} (actions within this tenant)
    - Logs with tenant_id = null AND resource_id = {tenant_id}
      (platform actions affecting this tenant)
    """
    tenant_id_str = str(tenant_id)

    # Build base query for tenant-specific and platform-level actions affecting this tenant
    or_conditions: list[dict[str, str | None]] = [
        {"tenant_id": tenant_id_str},  # Tenant-scoped actions
        {"tenant_id": None, "resource_id": tenant_id_str},  # Platform actions affecting this tenant
    ]

    # Apply additional filters to both OR conditions
    if actor_id:
        or_conditions = [{**cond, "actor_id": str(actor_id)} for cond in or_conditions]
    if action:
        or_conditions = [{**cond, "action": action} for cond in or_conditions]
    if resource:
        or_conditions = [{**cond, "resource": resource} for cond in or_conditions]

    query = {"$or": or_conditions}

    try:
        cursor = audit_service.collection.find(query).sort("created_at", -1).skip(skip).limit(limit)
        logs = await cursor.to_list(length=limit)
        return logs
    except Exception as e:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving audit logs: {str(e)}",
        ) from e
