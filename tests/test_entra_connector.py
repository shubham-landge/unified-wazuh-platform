from unittest.mock import AsyncMock, patch

import httpx
import pytest

from shared.connectors.entra import EntraConnector


def make_response(status_code=200, json_data=None, url="https://entra.example/health"):
    request = httpx.Request("GET", url)
    return httpx.Response(status_code, request=request, json=json_data or {})


@pytest.mark.asyncio
@patch("httpx.AsyncClient")
async def test_entra_connector_health(mock_client):
    client = AsyncMock()
    client.get.return_value = make_response(200, url="https://entra.example/health")
    client.__aenter__.return_value = client
    client.__aexit__.return_value = False
    mock_client.return_value = client
    connector = EntraConnector("https://entra.example", "tenant")
    result = await connector.health()
    assert result["connected"] is True


@pytest.mark.asyncio
@patch("httpx.AsyncClient")
async def test_entra_connector_get_signins(mock_client):
    client = AsyncMock()
    client.get.return_value = make_response(200, {"value": [{"userPrincipalName": "alice@example.com"}]}, url="https://entra.example/auditLogs/signIns")
    client.__aenter__.return_value = client
    client.__aexit__.return_value = False
    mock_client.return_value = client
    connector = EntraConnector("https://entra.example", "tenant")
    rows = await connector.get_signins()
    assert rows[0]["userPrincipalName"] == "alice@example.com"
