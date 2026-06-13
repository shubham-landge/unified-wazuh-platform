import os
import sys
import pytest
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

ROOT = Path(__file__).parent.parent.resolve()
API_DIR = ROOT / "services" / "api"

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(API_DIR))

os.environ.setdefault("API_KEYS", "soc-test-key-001")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-testing-only")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://user:pass@localhost:5432/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("WAZUH_API_VERIFY_SSL", "false")
os.environ.setdefault("WAZUH_INDEXER_VERIFY_SSL", "false")
os.environ.setdefault("DASHBOARD_ALLOWED_CIDRS", "0.0.0.0/0")

mock_db_module = MagicMock()
mock_async_session = AsyncMock()
mock_async_session.__aenter__.return_value = mock_async_session
mock_async_session.__aexit__ = AsyncMock()

async def mock_get_db():
    yield mock_async_session

mock_db_module.get_db = mock_get_db
mock_db_module.async_session = mock_async_session
mock_db_module.engine = MagicMock()

sys.modules["app.db"] = mock_db_module


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()
