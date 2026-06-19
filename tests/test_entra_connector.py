from unittest.mock import AsyncMock, patch

import httpx
import pytest

from shared.connectors.entra import EntraConnector


def make_response(status_code=200, json_data=None, request_url=""):
    request = httpx.Request("GET", request_url or "https://graph.microsoft.com/v1.0/organization")
    return httpx.Response(status_code, request=request, json=json_data or {})


@pytest.mark.asyncio
@patch("httpx.AsyncClient")
async def test_entra_connector_health_not_configured(mock_client):
    connector = EntraConnector(tenant_id="tenant")
    result = await connector.health()
    assert result["connected"] is False
    assert "not configured" in result["error"]


@pytest.mark.asyncio
async def test_entra_connector_health_no_token():
    connector = EntraConnector(tenant_id="t", client_id="c", client_secret="s")
    connector._acquire_token = AsyncMock(return_value=None)
    result = await connector.health()
    assert result["connected"] is False
