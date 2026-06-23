from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from auth_engine.core.config import settings

_connect_args: dict[str, str] = {}
if settings.POSTGRES_SSL:
    _connect_args["ssl"] = "require"

engine = create_async_engine(
    settings.POSTGRES_URL,
    pool_size=settings.POSTGRES_POOL_SIZE,
    max_overflow=settings.POSTGRES_MAX_OVERFLOW,
    pool_pre_ping=True,  # detect stale connections (important for hosted DBs)
    pool_recycle=300,  # recycle connections every 5 min
    connect_args=_connect_args,
    future=True,
    echo=settings.DEBUG,
)
# Async session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    pass


async def check_db_connection() -> None:
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))


async def init_db() -> None:
    """Create tables from models — local dev / auth-engine-data --create-tables only."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncSession:  # type: ignore[misc]
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
