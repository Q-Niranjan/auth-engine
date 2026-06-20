import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.deps import get_audit_service, get_db
from auth_engine.api.dependencies.rbac import check_tenant_permission
from auth_engine.models import UserORM
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.schemas.rbac import (
    CloneFromTemplateRequest,
    PermissionResponse,
    RoleAssignment,
    RoleResponse,
    RoleUpdateRequest,
    TenantRoleCreateRequest,
    UserRoleResponse,
)
from auth_engine.services.audit_service import AuditService
from auth_engine.services.role_service import RoleService

router = APIRouter()


@router.get("/{tenant_id}/roles", response_model=list[RoleResponse])
async def list_tenant_roles(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_tenant_permission("tenant.roles.view")),
) -> list[RoleResponse]:
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo)

    roles = await role_service.list_tenant_roles(tenant_id)
    return [RoleResponse.model_validate(r) for r in roles]


@router.get("/{tenant_id}/roles/templates", response_model=list[RoleResponse])
async def list_available_templates(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_tenant_permission("tenant.roles.view")),
) -> list[RoleResponse]:
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo)

    templates = await role_service.list_role_templates()
    return [RoleResponse.model_validate(r) for r in templates]


@router.get("/{tenant_id}/roles/permissions", response_model=list[PermissionResponse])
async def list_tenant_role_permissions(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_tenant_permission("tenant.roles.view")),
) -> list[PermissionResponse]:
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo)

    perms = await role_service.list_tenant_assignable_permissions()
    return [PermissionResponse.model_validate(p) for p in perms]


@router.post(
    "/{tenant_id}/roles",
    response_model=RoleResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_tenant_role(
    tenant_id: uuid.UUID,
    data: TenantRoleCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_tenant_permission("tenant.roles.manage")),
) -> RoleResponse:
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo)

    try:
        role = await role_service.create_tenant_role(tenant_id, data)
        return RoleResponse.model_validate(role)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post(
    "/{tenant_id}/roles/from-template",
    response_model=RoleResponse,
    status_code=status.HTTP_201_CREATED,
)
async def clone_role_from_template(
    tenant_id: uuid.UUID,
    data: CloneFromTemplateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_tenant_permission("tenant.roles.manage")),
) -> RoleResponse:
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo)

    try:
        role = await role_service.clone_template_to_tenant(
            tenant_id,
            data.template_role_id,
            name=data.name,
        )
        return RoleResponse.model_validate(role)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.put("/{tenant_id}/roles/{role_id}", response_model=RoleResponse)
async def update_tenant_role(
    tenant_id: uuid.UUID,
    role_id: uuid.UUID,
    data: RoleUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_tenant_permission("tenant.roles.manage")),
) -> RoleResponse:
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo)

    try:
        role = await role_service.update_tenant_role(tenant_id, role_id, data)
        return RoleResponse.model_validate(role)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.delete("/{tenant_id}/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tenant_role(
    tenant_id: uuid.UUID,
    role_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_tenant_permission("tenant.roles.manage")),
) -> None:
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo)

    try:
        await role_service.delete_tenant_role(tenant_id, role_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get(
    "/{tenant_id}/users/{user_id}/roles",
    response_model=list[UserRoleResponse],
)
async def get_user_tenant_roles(
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_tenant_permission("tenant.roles.view")),
) -> list[UserRoleResponse]:
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo)

    assignments = await role_service.get_user_roles_in_tenant(
        user_id=user_id,
        tenant_id=tenant_id,
    )
    return [UserRoleResponse.model_validate(a) for a in assignments]


@router.post(
    "/{tenant_id}/users/{user_id}/roles",
    status_code=status.HTTP_200_OK,
)
async def assign_user_role(
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    assignment: RoleAssignment,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_tenant_permission("tenant.roles.assign")),
    audit_service: AuditService = Depends(get_audit_service),
) -> dict[str, str]:
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo, audit_service)

    try:
        await role_service.assign_role(
            actor=current_user,
            target_user_id=user_id,
            tenant_id=tenant_id,
            role_name=assignment.role_name,
            role_id=assignment.role_id,
        )
        label = assignment.role_name or str(assignment.role_id)
        return {"message": f"Role '{label}' assigned successfully"}
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc


@router.delete(
    "/{tenant_id}/users/{user_id}/roles/{role_name}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def remove_user_role(
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    role_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_tenant_permission("tenant.roles.assign")),
    audit_service: AuditService = Depends(get_audit_service),
) -> None:
    user_repo = UserRepository(db)
    role_service = RoleService(user_repo, audit_service)

    try:
        success = await role_service.remove_role(
            actor=current_user,
            target_user_id=user_id,
            tenant_id=tenant_id,
            role_name=role_name,
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role assignment not found",
            )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc
