import pytest
import asyncio
import os
import sys
from pathlib import Path


os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("API_KEYS", "soc-key-001")

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "services" / "worker", ROOT / "services" / "api"):
    extra_str = str(extra)
    if extra_str not in sys.path:
        sys.path.insert(0, extra_str)


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the entire test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()
