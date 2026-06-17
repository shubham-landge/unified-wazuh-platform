import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient

os.environ.setdefault("SECRET_KEY", "test-secret-key")


@pytest.fixture
def mcp_app():
    from services.mcp.server import app
    return app


@pytest.mark.asyncio
async def test_list_tools_returns_definitions(mcp_app):
    async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as client:
        response = await client.get("/tools")

    assert response.status_code == 200
    data = response.json()
    assert "tools" in data
    names = {t["name"] for t in data["tools"]}
    assert "list_alerts" in names
    assert "get_triage" in names
    assert "create_case" in names
    assert "run_playbook" in names


@pytest.mark.asyncio
async def test_call_unknown_tool_returns_400(mcp_app):
    async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as client:
        response = await client.post("/tools/call", json={"tool": "no_such_tool", "params": {}})

    assert response.status_code == 400


@pytest.mark.asyncio
async def test_call_list_alerts_forwards_to_api(mcp_app):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"alerts": [{"id": "1", "title": "test"}]}

    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch("services.mcp.server.httpx.AsyncClient", return_value=mock_client), \
         patch("services.mcp.server.settings.api_keys", "soc-key-001,soc-key-002"):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as client:
            response = await client.post(
                "/tools/call",
                json={"tool": "list_alerts", "params": {"limit": 5, "severity": "high"}},
            )

    assert response.status_code == 200
    assert response.json()["alerts"][0]["title"] == "test"
    mock_client.get.assert_awaited_once()
    call_args = mock_client.get.call_args
    assert call_args.kwargs["headers"] == {"X-API-Key": "soc-key-001"}
    assert call_args.kwargs["params"] == {"limit": 5, "severity": "high"}


@pytest.mark.asyncio
async def test_call_create_case_forwards_post(mcp_app):
    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.json.return_value = {"id": "case-1", "title": "Phishing"}

    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_response)

    with patch("services.mcp.server.httpx.AsyncClient", return_value=mock_client), \
         patch("services.mcp.server.settings.api_keys", "soc-key-001"):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as client:
            response = await client.post(
                "/tools/call",
                json={
                    "tool": "create_case",
                    "params": {"title": "Phishing", "severity": "high"},
                },
            )

    assert response.status_code == 200
    assert response.json()["id"] == "case-1"
    mock_client.post.assert_awaited_once()
    call_args = mock_client.post.call_args
    assert call_args.kwargs["headers"] == {"X-API-Key": "soc-key-001"}
    assert call_args.kwargs["json"]["title"] == "Phishing"


@pytest.mark.asyncio
async def test_call_tool_api_error_propagates(mcp_app):
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "internal error"

    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch("services.mcp.server.httpx.AsyncClient", return_value=mock_client), \
         patch("services.mcp.server.settings.api_keys", "soc-key-001"):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as client:
            response = await client.post(
                "/tools/call",
                json={"tool": "get_stats", "params": {}},
            )

    assert response.status_code == 500
    assert "internal error" in response.text


@pytest.mark.asyncio
async def test_call_get_triage_requires_alert_id(mcp_app):
    async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as client:
        response = await client.post(
            "/tools/call",
            json={"tool": "get_triage", "params": {}},
        )

    assert response.status_code == 400


@pytest.mark.asyncio
async def test_call_tool_returns_502_when_api_unreachable(mcp_app):
    import httpx

    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(side_effect=httpx.ConnectError("connection refused"))

    with patch("services.mcp.server.httpx.AsyncClient", return_value=mock_client), \
         patch("services.mcp.server.settings.api_keys", "soc-key-001"):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as client:
            response = await client.post(
                "/tools/call",
                json={"tool": "get_stats", "params": {}},
            )

    assert response.status_code == 502
    assert "Unable to reach SOC API" in response.text
