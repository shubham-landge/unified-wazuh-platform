"""Seed the SOC platform with an admin user."""
import asyncio
import logging
import os
import uuid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from shared.config import settings
from shared.auth import hash_password
from shared.models.user import User, ROLES

logger = logging.getLogger(__name__)

DEFAULT_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
ADMIN_EMAIL = os.environ.get("SEED_ADMIN_EMAIL", "admin@company.com")
ADMIN_PASSWORD = os.environ.get("SEED_ADMIN_PASSWORD", "")


async def seed():
    engine = create_async_engine(settings.database_url, pool_size=1)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with session_factory() as session:
        result = await session.execute(
            select(User).where(User.email == ADMIN_EMAIL)
        )
        existing = result.scalar_one_or_none()
        if existing:
            logger.info("Admin user '%s' already exists (id=%s). Skipping.", ADMIN_EMAIL, existing.id)
            return

        user = User(
            email=ADMIN_EMAIL,
            password_hash=hash_password(ADMIN_PASSWORD),
            role="admin",
            permissions=ROLES["admin"]["permissions"],
            is_active=True,
            tenant_id=DEFAULT_TENANT_ID,
        )
        session.add(user)
        await session.commit()
        logger.info("Created admin user: %s (role=admin, tenant=%s)", ADMIN_EMAIL, DEFAULT_TENANT_ID)

    await engine.dispose()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    asyncio.run(seed())
