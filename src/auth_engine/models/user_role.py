from sqlalchemy import Column, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from auth_engine.core.postgres import Base


class UserRoleORM(Base):
    __tablename__ = "user_roles"

    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), primary_key=True)
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id"), primary_key=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), primary_key=True)

    user = relationship("UserORM", back_populates="roles")
    role = relationship("RoleORM", back_populates="users", lazy="selectin")
    tenant = relationship("TenantORM", back_populates="users", lazy="selectin")
