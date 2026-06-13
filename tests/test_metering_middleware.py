"""Tests for the usage metering middleware."""
import pytest
from unittest.mock import AsyncMock, MagicMock
from fastapi import Request
from starlette.responses import Response

from app.middleware.metering import UsageMeteringMiddleware, get_metering_snapshot, reset_metering


@pytest.fixture(autouse=True)
def reset_counters():
    reset_metering()
    yield
    reset_metering()


@pytest.mark.asyncio
async def test_metering_counts_api_calls():
    reset_metering()
    mock_app = AsyncMock()
    middleware = UsageMeteringMiddleware(mock_app)
    mock_call_next = AsyncMock(return_value=Response("OK", status_code=200))

    req1 = MagicMock(spec=Request)
    req1.url.path = "/alerts/recent"
    req1.method = "GET"
    req1.state.tenant_id = "tenant-1"

    req2 = MagicMock(spec=Request)
    req2.url.path = "/cases"
    req2.method = "POST"
    req2.state.tenant_id = "tenant-1"

    req3 = MagicMock(spec=Request)
    req3.url.path = "/vulnerabilities"
    req3.method = "GET"
    req3.state.tenant_id = "tenant-2"

    await middleware.dispatch(req1, mock_call_next)
    await middleware.dispatch(req2, mock_call_next)
    await middleware.dispatch(req3, mock_call_next)

    snapshot = get_metering_snapshot()
    assert snapshot["tenant-1"]["api_calls"] == 2
    assert snapshot["tenant-1"]["GET_calls"] == 1
    assert snapshot["tenant-1"]["POST_calls"] == 1
    assert snapshot["tenant-2"]["api_calls"] == 1
    assert snapshot["tenant-2"]["GET_calls"] == 1


@pytest.mark.asyncio
async def test_metering_exempt_paths():
    reset_metering()
    mock_app = AsyncMock()
    middleware = UsageMeteringMiddleware(mock_app)
    mock_call_next = AsyncMock(return_value=Response("OK", status_code=200))

    req = MagicMock(spec=Request)
    req.url.path = "/health"
    req.method = "GET"
    req.state.tenant_id = "tenant-1"

    await middleware.dispatch(req, mock_call_next)

    snapshot = get_metering_snapshot()
    assert "tenant-1" not in snapshot


@pytest.mark.asyncio
async def test_metering_system_fallback():
    reset_metering()
    mock_app = AsyncMock()
    middleware = UsageMeteringMiddleware(mock_app)
    mock_call_next = AsyncMock(return_value=Response("OK", status_code=200))

    req = MagicMock(spec=Request)
    req.url.path = "/alerts/recent"
    req.method = "GET"
    req.state = MagicMock()
    req.state.tenant_id = None

    await middleware.dispatch(req, mock_call_next)

    snapshot = get_metering_snapshot()
    assert "system" in snapshot
    assert snapshot["system"]["api_calls"] == 1


@pytest.mark.asyncio
async def test_get_metering_snapshot():
    reset_metering()
    assert get_metering_snapshot() == {}
