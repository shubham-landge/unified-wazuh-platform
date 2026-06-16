import os
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

os.environ.setdefault("API_KEYS", "soc-test-key-001")
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://user:pass@localhost:5432/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("WAZUH_API_VERIFY_SSL", "false")
os.environ.setdefault("WAZUH_INDEXER_VERIFY_SSL", "false")


@pytest.fixture(autouse=True)
def reset_settings():
    from shared.config import settings
    settings.api_keys = ["soc-test-key-001"]
    settings.api_rate_limit = 100
    settings.dashboard_allowed_cidrs = "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
    yield


@pytest.mark.asyncio
async def test_rate_limit_middleware():
    from shared.config import settings
    from collections import defaultdict
    from fastapi import Request, HTTPException
    from unittest.mock import AsyncMock, MagicMock

    settings.api_rate_limit = 3

    # Test the middleware logic directly
    from app.middleware.rate_limit import RateLimitMiddleware
    mock_app = AsyncMock()
    middleware = RateLimitMiddleware(mock_app)
    middleware.requests = defaultdict(list)

    from starlette.responses import Response
    mock_call_next = AsyncMock(return_value=Response("OK", status_code=200))

    for i in range(3):
        mock_req = MagicMock(spec=Request)
        mock_req.headers = {"X-API-Key": "test-rate-key"}
        result = await middleware.dispatch(mock_req, mock_call_next)
        assert result.status_code == 200

    mock_req = MagicMock(spec=Request)
    mock_req.headers = {"X-API-Key": "test-rate-key"}
    try:
        await middleware.dispatch(mock_req, mock_call_next)
        assert False, "Expected 429"
    except HTTPException as e:
        assert e.status_code == 429

    settings.api_rate_limit = 100


@pytest.mark.asyncio
async def test_dashboard_access_middleware_logic():
    from app.middleware.dashboard_access import DashboardAccessMiddleware
    from fastapi import Request
    from starlette.responses import JSONResponse
    from unittest.mock import AsyncMock, MagicMock

    mock_app = AsyncMock()
    middleware = DashboardAccessMiddleware(mock_app)

    def make_request(path, ip):
        req = MagicMock(spec=Request)
        req.url.path = path
        req.client = MagicMock()
        req.client.host = ip
        return req

    mock_request_exempt = make_request("/docs", "203.0.113.5")
    result = await middleware.dispatch(mock_request_exempt, AsyncMock())
    assert result is not None

    # Starlette BaseHTTPMiddleware cannot reliably raise HTTPException from
    # dispatch(), so a denied request returns a 403 JSONResponse instead.
    mock_request_denied = make_request("/alerts/recent", "203.0.113.5")
    denied = await middleware.dispatch(mock_request_denied, AsyncMock())
    assert isinstance(denied, JSONResponse)
    assert denied.status_code == 403

    mock_request_allowed = make_request("/alerts/recent", "10.0.0.5")
    mock_call_next = AsyncMock(return_value="passed")
    result = await middleware.dispatch(mock_request_allowed, mock_call_next)
    assert result == "passed"


@pytest.mark.asyncio
async def test_api_docs_exempt_from_cidr():
    from httpx import ASGITransport, AsyncClient
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/docs")
        assert resp.status_code in (200, 307)


@pytest.mark.asyncio
async def test_auth_sha256_hash_comparison():
    from app.middleware.auth import _hash_key

    hashed = _hash_key("soc-test-key-001")
    assert len(hashed) == 64
    assert isinstance(hashed, str)


@pytest.mark.asyncio
async def test_audit_middleware_logs_key_prefix():
    from app.middleware.audit import _key_prefix
    from unittest.mock import MagicMock

    request = MagicMock()
    request.headers = {"X-API-Key": "soc-test-key-001"}
    prefix = _key_prefix(request)
    assert len(prefix) == 12
    assert isinstance(prefix, str)


@pytest.mark.asyncio
async def test_audit_middleware_anon_key():
    from app.middleware.audit import _key_prefix
    from unittest.mock import MagicMock

    request = MagicMock()
    request.headers = {}
    prefix = _key_prefix(request)
    assert prefix == "anon"


@pytest.mark.asyncio
async def test_auth_validates_hashed_key():
    from app.middleware.auth import _hash_key, validate_api_key
    from fastapi import HTTPException

    assert _hash_key("test") == _hash_key("test")
    assert _hash_key("test") != _hash_key("different")


@pytest.mark.asyncio
async def test_dashboard_middleware_exempt_paths():
    from app.middleware.dashboard_access import DashboardAccessMiddleware
    from unittest.mock import AsyncMock, MagicMock

    mock_app = AsyncMock()
    middleware = DashboardAccessMiddleware(mock_app)

    for path in ["/docs", "/redoc", "/openapi.json"]:
        mock_req = MagicMock()
        mock_req.url.path = path
        mock_call_next = AsyncMock(return_value="passed")
        result = await middleware.dispatch(mock_req, mock_call_next)
        assert result == "passed", f"Path {path} should be exempt"
