from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shared.connectors.jira import JiraConnector


@pytest.mark.asyncio
async def test_create_ticket(monkeypatch):
    response = MagicMock()
    response.status_code = 201
    response.json.return_value = {"key": "SOC-1"}
    response.text = ""
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = False
    client.post = AsyncMock(return_value=response)
    monkeypatch.setattr("shared.connectors.jira.httpx.AsyncClient", MagicMock(return_value=client))
    connector = JiraConnector(url="https://jira.example.com", email="user@example.com", api_token="token")
    result = await connector.create_ticket({"title": "Case", "description": "desc", "severity": "high"})
    assert result["success"] is True
    assert result["remote_id"] == "SOC-1"


@pytest.mark.asyncio
async def test_health(monkeypatch):
    response = MagicMock()
    response.status_code = 200
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = False
    client.get = AsyncMock(return_value=response)
    monkeypatch.setattr("shared.connectors.jira.httpx.AsyncClient", MagicMock(return_value=client))
    connector = JiraConnector(url="https://jira.example.com", email="user@example.com", api_token="token")
    result = await connector.health()
    assert result["connected"] is True
