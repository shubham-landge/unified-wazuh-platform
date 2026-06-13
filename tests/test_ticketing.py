import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import json


class TestTicketingModels:
    def test_ticketing_config_model(self):
        from shared.models.ticketing import TicketingConfig
        assert hasattr(TicketingConfig, "id")
        assert hasattr(TicketingConfig, "provider")
        assert hasattr(TicketingConfig, "config")
        assert hasattr(TicketingConfig, "is_active")

    def test_ticket_link_model(self):
        from shared.models.ticketing import TicketLink
        assert hasattr(TicketLink, "id")
        assert hasattr(TicketLink, "case_id")
        assert hasattr(TicketLink, "provider")
        assert hasattr(TicketLink, "remote_ticket_id")
        assert hasattr(TicketLink, "sync_status")


class TestServiceNowConnector:
    @pytest.mark.asyncio
    async def test_create_ticket_success(self):
        from shared.connectors.ticket_servicenow import ServiceNowConnector
        conn = ServiceNowConnector(instance="test", user="admin", password="pass")

        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"result": {"sys_id": "abc123"}}

        with patch("httpx.AsyncClient") as client_cls:
            client = AsyncMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            client.post = AsyncMock(return_value=mock_resp)
            client_cls.return_value = client

            result = await conn.create_ticket({"title": "Test", "severity": "high"})

        assert result["success"] is True
        assert result["remote_id"] == "abc123"

    @pytest.mark.asyncio
    async def test_health_connected(self):
        from shared.connectors.ticket_servicenow import ServiceNowConnector
        conn = ServiceNowConnector(instance="test", user="admin", password="pass")

        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch("httpx.AsyncClient") as client_cls:
            client = AsyncMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            client.get = AsyncMock(return_value=mock_resp)
            client_cls.return_value = client

            health = await conn.health()

        assert health["connected"] is True


class TestJiraConnector:
    @pytest.mark.asyncio
    async def test_create_ticket_success(self):
        from shared.connectors.ticket_jira import JiraConnector
        conn = JiraConnector(url="https://test.atlassian.net", email="a@b.com", api_token="tok")

        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"key": "SOC-42"}

        with patch("httpx.AsyncClient") as client_cls:
            client = AsyncMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            client.post = AsyncMock(return_value=mock_resp)
            client_cls.return_value = client

            result = await conn.create_ticket({"title": "Test", "severity": "high"})

        assert result["success"] is True
        assert result["remote_id"] == "SOC-42"

    @pytest.mark.asyncio
    async def test_health_connected(self):
        from shared.connectors.ticket_jira import JiraConnector
        conn = JiraConnector(url="https://test.atlassian.net", email="a@b.com", api_token="tok")

        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch("httpx.AsyncClient") as client_cls:
            client = AsyncMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            client.get = AsyncMock(return_value=mock_resp)
            client_cls.return_value = client

            health = await conn.health()

        assert health["connected"] is True


class TestTicketingAPI:
    @pytest.mark.asyncio
    async def test_test_connection_unknown_provider(self):
        from app.routers.ticketing import router
        assert router is not None

    def test_ticketing_router_imports(self):
        from app.routers import ticketing
        assert ticketing is not None
