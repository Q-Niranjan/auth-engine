import logging
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import joinedload

from auth_engine.models import RoleORM, TenantORM, UserORM, UserRoleORM
from auth_engine.models.tenant import TenantType
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.services.audit_service import AuditService
from auth_engine.services.permission_service import PermissionService

logger = logging.getLogger(__name__)


class TenantService:
    def __init__(self, user_repo: UserRepository, audit_service: AuditService | None = None):
        self.user_repo = user_repo
        self.audit_service = audit_service

    async def _get_platform_tenant_id(self) -> uuid.UUID | None:
        """Get the platform tenant ID for logging platform-level actions.

        Platforms actions are logged to the platform tenant's own trail.
        """
        query = select(TenantORM).where(TenantORM.type == TenantType.PLATFORM)
        result = await self.user_repo.session.execute(query)
        platform_tenant = result.scalar_one_or_none()
        return platform_tenant.id if platform_tenant else None

    async def create_tenant(
        self,
        name: str,
        owner_id: uuid.UUID,
        created_by: uuid.UUID,
        description: str | None = None,
        type: str = "CUSTOMER",
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> TenantORM:
        tenant = TenantORM(
            name=name, description=description, owner_id=owner_id, created_by=created_by, type=type
        )
        self.user_repo.session.add(tenant)
        await self.user_repo.session.flush()

        # Automatically assign TENANT_OWNER role to the owner_id
        role_query = select(RoleORM).where(RoleORM.name == "TENANT_OWNER")
        role_result = await self.user_repo.session.execute(role_query)
        owner_role = role_result.scalar_one_or_none()

        if owner_role:
            user_role = UserRoleORM(user_id=owner_id, role_id=owner_role.id, tenant_id=tenant.id)
            self.user_repo.session.add(user_role)

        await self.user_repo.session.commit()
        await self.user_repo.session.refresh(tenant)

        if self.audit_service:
            metadata = {
                "name": name,
                "owner_id": str(owner_id),
                "created_by": str(created_by),
                "type": type,
            }
            # Log globally (platform-level action)
            await self.audit_service.log(
                action="TENANT_CREATED",
                resource="Tenant",
                resource_id=str(tenant.id),
                actor_id=created_by,
                metadata=metadata,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            # Also log to platform tenant's own audit trail
            platform_tenant_id = await self._get_platform_tenant_id()
            if platform_tenant_id:
                await self.audit_service.log(
                    action="TENANT_CREATED",
                    resource="Tenant",
                    resource_id=str(tenant.id),
                    actor_id=created_by,
                    tenant_id=str(platform_tenant_id),
                    metadata=metadata,
                    ip_address=ip_address,
                    user_agent=user_agent,
                )

        return tenant

    async def list_my_tenants(self, user_id: uuid.UUID) -> list[TenantORM]:
        query = (
            select(TenantORM)
            .join(UserRoleORM, UserRoleORM.tenant_id == TenantORM.id)
            .where(UserRoleORM.user_id == user_id)
            .distinct()
        )
        result = await self.user_repo.session.execute(query)
        return list(result.scalars().all())

    async def get_tenant(
        self, tenant_id: uuid.UUID, actor: UserORM | None = None
    ) -> TenantORM | None:
        if actor and not await PermissionService.has_permission(
            self.user_repo.session, actor, "tenant.view", tenant_id
        ):
            raise ValueError("Insufficient permissions: Missing 'tenant.view'")

        query = select(TenantORM).where(TenantORM.id == tenant_id)
        result = await self.user_repo.session.execute(query)
        return result.scalar_one_or_none()

    async def update_tenant(
        self,
        tenant_id: uuid.UUID,
        actor: UserORM,
        ip_address: str | None = None,
        user_agent: str | None = None,
        **kwargs: Any,
    ) -> TenantORM | None:
        if not await PermissionService.has_permission(
            self.user_repo.session, actor, "tenant.update", tenant_id
        ):
            raise ValueError("Insufficient permissions: Missing 'tenant.update'")

        tenant = await self.get_tenant(tenant_id)
        if not tenant:
            return None

        for key, value in kwargs.items():
            if value is not None and hasattr(tenant, key):
                setattr(tenant, key, value)

        await self.user_repo.session.commit()
        await self.user_repo.session.refresh(tenant)

        # Audit Log
        if self.audit_service:
            metadata = {"updates": kwargs}
            # Log globally (platform-level action)
            await self.audit_service.log(
                action="TENANT_UPDATED",
                resource="Tenant",
                resource_id=str(tenant_id),
                actor_id=actor.id,
                metadata=metadata,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            # Also log to platform tenant's own audit trail
            platform_tenant_id = await self._get_platform_tenant_id()
            if platform_tenant_id:
                await self.audit_service.log(
                    action="TENANT_UPDATED",
                    resource="Tenant",
                    resource_id=str(tenant_id),
                    actor_id=actor.id,
                    tenant_id=str(platform_tenant_id),
                    metadata=metadata,
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
        return tenant

    async def delete_tenant(
        self,
        tenant_id: uuid.UUID,
        actor: UserORM,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> bool:
        if not await PermissionService.has_permission(
            self.user_repo.session, actor, "tenant.delete", tenant_id
        ):
            raise ValueError("Insufficient permissions: Missing 'tenant.delete'")

        tenant = await self.get_tenant(tenant_id)
        if not tenant:
            return False

        await self.user_repo.session.delete(tenant)
        await self.user_repo.session.commit()

        if self.audit_service:
            # Log globally (platform-level action)
            await self.audit_service.log(
                action="TENANT_DELETED",
                resource="Tenant",
                resource_id=str(tenant_id),
                actor_id=actor.id,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            # Also log to platform tenant's own audit trail
            platform_tenant_id = await self._get_platform_tenant_id()
            if platform_tenant_id:
                await self.audit_service.log(
                    action="TENANT_DELETED",
                    resource="Tenant",
                    resource_id=str(tenant_id),
                    actor_id=actor.id,
                    tenant_id=str(platform_tenant_id),
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
        return True

    async def list_tenant_users(self, tenant_id: uuid.UUID, actor: UserORM) -> list[UserORM]:
        if not await PermissionService.has_permission(
            self.user_repo.session, actor, "tenant.users.view", tenant_id
        ):
            raise ValueError("Insufficient permissions: Missing 'tenant.users.view'")

        query = (
            select(UserORM)
            .join(UserRoleORM, UserRoleORM.user_id == UserORM.id)
            .where(UserRoleORM.tenant_id == tenant_id)
            .options(joinedload(UserORM.roles).joinedload(UserRoleORM.role))
        )
        result = await self.user_repo.session.execute(query)
        return list(result.unique().scalars().all())

    async def remove_user_from_tenant(
        self, tenant_id: uuid.UUID, user_id: uuid.UUID, actor: UserORM
    ) -> bool:
        """
        Removes all role mappings for a user in a specific tenant (not deleting user globally).
        """
        if not await PermissionService.has_permission(
            self.user_repo.session, actor, "tenant.users.manage", tenant_id
        ):
            raise ValueError("Insufficient permissions: Missing 'tenant.users.manage'")

        query = select(UserRoleORM).where(
            UserRoleORM.tenant_id == tenant_id, UserRoleORM.user_id == user_id
        )
        result = await self.user_repo.session.execute(query)
        mappings = result.scalars().all()

        if not mappings:
            return False

        for mapping in mappings:
            await self.user_repo.session.delete(mapping)

        await self.user_repo.session.commit()

        if self.audit_service:
            await self.audit_service.log(
                action="TENANT_USER_REMOVED",
                resource="Tenant",
                resource_id=str(tenant_id),
                actor_id=actor.id,
                metadata={"removed_user_id": str(user_id)},
            )
        return True

    async def invite_user_to_tenant(
        self,
        tenant_id: uuid.UUID,
        email: str,
        role_name: str,
        actor: UserORM,
        auth_service: Any,
        role_service: Any,
        email_service_resolver: Any,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict[str, str]:
        """
        Invite a user to a tenant with a specific role.
        If user doesn't exist, register them with PENDING_VERIFICATION status.
        Sends invitation email in both cases.
        """
        # 1. Verify actor has permission
        if not await PermissionService.has_permission(
            self.user_repo.session, actor, "tenant.users.manage", tenant_id
        ):
            raise ValueError("Insufficient permissions: Missing 'tenant.users.manage'")

        # 2. Verify tenant exists
        tenant = await self.get_tenant(tenant_id)
        if not tenant:
            raise ValueError("Tenant not found")

        # 3. Check if user exists
        existing_user = await self.user_repo.get_by_email(email)
        action_desc = ""

        if existing_user:
            # User exists - assign role and send welcome email
            user = existing_user
            try:
                await role_service.assign_role(
                    actor=actor,
                    target_user_id=user.id,
                    role_name=role_name,
                    tenant_id=tenant_id,
                )
            except ValueError as e:
                raise e

            # Send "added to tenant" email
            try:
                email_service = await email_service_resolver.resolve(tenant_id)
                subject = f"You've been added to {tenant.name}"
                html_content = f"""
                <html>
                    <body>
                        <h1>Welcome to {tenant.name}</h1>
                        <p>Hello {user.first_name or 'User'},</p>
                        <p>You've been added to <strong>{tenant.name}</strong>
                        with the role: <strong>{role_name}</strong></p>
                        <p>Log in to get started:</p>
                        <p><a href="https://app.example.com">Open Dashboard</a></p>
                    </body>
                </html>
                """
                await email_service.send_email([email], subject, html_content)
            except Exception as e:
                logger.error(f"Failed to send invitation email to {email}: {e}")

            action_desc = f"added to {tenant.name} with role {role_name}"

        else:
            # User doesn't exist - register them, assign role, send verification + invitation
            from auth_engine.schemas.user import AuthStrategy, UserCreate

            user_create = UserCreate(
                email=email,
                username=email.split("@")[0],  # Use email prefix as username
                password="TempPass@123",  # pragma: allowlist secret
                first_name="",
                last_name="",
                auth_strategy=AuthStrategy.EMAIL_PASSWORD,
            )

            try:
                user = await auth_service.register_user(user_create)
            except ValueError as e:
                raise e

            # Assign role
            try:
                await role_service.assign_role(
                    actor=actor,
                    target_user_id=user.id,
                    role_name=role_name,
                    tenant_id=tenant_id,
                )
            except ValueError as e:
                raise e

            # Send invitation + verification email
            try:
                email_service = await email_service_resolver.resolve(tenant_id)
                subject = f"Invitation to {tenant.name} - Complete Your Registration"
                html_content = f"""
                <html>
                    <body>
                        <h1>Invitation to {tenant.name}</h1>
                        <p>You've been invited to join <strong>{tenant.name}</strong>!</p>
                        <p>Role: <strong>{role_name}</strong></p>
                        <p>To get started, please complete your registration by
                        verifying your email address.</p>
                        <p>Check your inbox for a verification email with further
                        instructions.</p>
                    </body>
                </html>
                """
                await email_service.send_email([email], subject, html_content)
            except Exception as e:
                logger.error(f"Failed to send invitation email to {email}: {e}")

            action_desc = f"invited to {tenant.name} (account created) with role {role_name}"

        # 4. Audit log
        if self.audit_service:
            await self.audit_service.log(
                action="USER_INVITED_TO_TENANT",
                resource="Tenant",
                resource_id=str(tenant_id),
                actor_id=actor.id,
                target_user_id=user.id,
                tenant_id=str(tenant_id),
                metadata={
                    "email": email,
                    "role_name": role_name,
                    "user_status": "existing" if existing_user else "newly_registered",
                },
                ip_address=ip_address,
                user_agent=user_agent,
            )

        return {
            "message": f"User {email} {action_desc}",
            "user_id": str(user.id),
            "status": "existing" if existing_user else "newly_registered",
        }

    async def get_user_in_tenant(
        self,
        tenant_id: uuid.UUID,
        user_id: uuid.UUID,
        actor: UserORM,
    ) -> UserORM | None:
        # Permission check
        if not await PermissionService.has_permission(
            self.user_repo.session, actor, "tenant.users.view", tenant_id
        ):
            raise ValueError("Insufficient permissions: Missing 'tenant.users.view'")

        query = (
            select(UserORM)
            .join(UserRoleORM, UserRoleORM.user_id == UserORM.id)
            .where(
                UserORM.id == user_id,
                UserRoleORM.tenant_id == tenant_id,
            )
            .options(joinedload(UserORM.roles).joinedload(UserRoleORM.role))
        )

        result = await self.user_repo.session.execute(query)
        return result.unique().scalar_one_or_none()
