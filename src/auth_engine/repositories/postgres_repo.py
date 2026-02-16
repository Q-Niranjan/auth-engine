from collections.abc import Sequence
from typing import Any, Generic, TypeVar

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.core.postgres import Base

T = TypeVar("T", bound=Base)


class PostgresRepository(Generic[T]):
    def __init__(self, model: type[T], session: AsyncSession):
        self.model = model
        self.session = session

    async def get(self, id: Any) -> T | None:
        query = select(self.model).where(self.model.id == id)  # type: ignore[attr-defined]
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_all(self, skip: int = 0, limit: int = 100) -> Sequence[T]:
        query = select(self.model).offset(skip).limit(limit)
        result = await self.session.execute(query)
        return result.scalars().all()

    async def create(self, obj_in: Any) -> T:
        db_obj = self.model(**obj_in)
        self.session.add(db_obj)
        await self.session.flush()
        await self.session.refresh(db_obj)
        return db_obj

    async def update(self, id: Any, obj_in: Any) -> T | None:
        query = update(self.model).where(self.model.id == id).values(**obj_in).returning(self.model)  # type: ignore[attr-defined]
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def delete(self, id: Any) -> bool:
        query = delete(self.model).where(self.model.id == id)  # type: ignore[attr-defined]
        result = await self.session.execute(query)
        return result.rowcount > 0  # type: ignore[attr-defined]
