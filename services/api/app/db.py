from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from shared.config import settings

engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,
    pool_size=5,
    max_overflow=5,
    pool_pre_ping=True,
    pool_use_lifo=True,
)

async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


import logging

logger = logging.getLogger(__name__)


async def get_db() -> AsyncSession:
    session = async_session()
    try:
        yield session
        await session.commit()
    except Exception as e:
        logger.warning("DB error: %s", e)
        await session.rollback()
        raise
    finally:
        await session.close()
