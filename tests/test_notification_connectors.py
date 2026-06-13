"""Tests for notification connectors — Slack, Teams, PagerDuty, Email."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx


@pytest.fixture
def slack_connector():
    from shared.connectors.notify_slack import SlackConnector
    return SlackConnector(webhook_url="https://hooks.slack.com/test/webhook")


@pytest.fixture
def teams_connector():
    from shared.connectors.notify_teams import TeamsConnector
    return TeamsConnector(webhook_url="https://outlook.office.com/webhook/test")


@pytest.fixture
def pagerduty_connector():
    from shared.connectors.notify_pagerduty import PagerDutyConnector
    return PagerDutyConnector(routing_key="test_routing_key_abc123")


class TestSlackConnector:
    async def test_send_success(self, slack_connector):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            result = await slack_connector.send(text="Test alert", blocks=None)

        assert result["success"] is True

    async def test_send_no_webhook(self):
        from shared.connectors.notify_slack import SlackConnector
        connector = SlackConnector(webhook_url="")
        result = await connector.send(text="test")
        assert result["success"] is False
        assert "not configured" in result["error"]

    def test_build_alert_blocks_critical(self, slack_connector):
        alert = {"rule_description": "Brute force login", "agent_name": "server01", "source_ip": "1.2.3.4", "rule_level": 12}
        triage = {"severity": "critical", "summary": "Brute force detected from external IP"}
        blocks = slack_connector.build_alert_blocks(alert, triage)
        assert len(blocks) >= 2
        # Header should contain the 🔴 icon for critical
        header_text = blocks[0]["text"]["text"]
        assert "🔴" in header_text

    def test_build_alert_blocks_no_triage(self, slack_connector):
        alert = {"rule_description": "Test", "agent_name": "host1", "source_ip": "10.0.0.1", "rule_level": 5}
        blocks = slack_connector.build_alert_blocks(alert, None)
        assert isinstance(blocks, list)

    async def test_health_with_webhook(self, slack_connector):
        result = await slack_connector.health()
        assert result["connected"] is True

    async def test_health_without_webhook(self):
        from shared.connectors.notify_slack import SlackConnector
        result = await SlackConnector(webhook_url="").health()
        assert result["connected"] is False


class TestTeamsConnector:
    async def test_send_success(self, teams_connector):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            result = await teams_connector.send(title="SOC Alert", summary="Test", facts=[{"title": "Severity", "value": "HIGH"}])

        assert result["success"] is True

    def test_build_alert_facts_critical(self, teams_connector):
        alert = {"rule_description": "Malware", "agent_name": "ws01", "source_ip": "5.6.7.8", "rule_level": 14}
        triage = {"severity": "critical", "escalation_required": True}
        color, facts = teams_connector.build_alert_facts(alert, triage)
        assert color == "FF0000"
        titles = [f["title"] for f in facts]
        assert "Escalation" in titles

    def test_adaptive_card_structure(self, teams_connector):
        card = teams_connector._build_adaptive_card("Title", "Summary", [{"title": "K", "value": "V"}], "FF0000")
        assert card["type"] == "AdaptiveCard"
        assert any(b["type"] == "FactSet" for b in card["body"])


class TestPagerDutyConnector:
    async def test_trigger_success(self, pagerduty_connector):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json = MagicMock(return_value={"status": "success", "dedup_key": "abc123"})

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            result = await pagerduty_connector.trigger(
                summary="Critical: brute force",
                source="wazuh",
                severity="critical",
                dedup_key="alert-123",
            )

        assert result["success"] is True
        assert result["dedup_key"] == "abc123"

    async def test_trigger_no_routing_key(self):
        from shared.connectors.notify_pagerduty import PagerDutyConnector
        connector = PagerDutyConnector(routing_key="")
        result = await connector.trigger(summary="test", source="wazuh")
        assert result["success"] is False

    async def test_resolve_success(self, pagerduty_connector):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json = MagicMock(return_value={"status": "success"})

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            result = await pagerduty_connector.resolve("alert-123")

        assert result["success"] is True

    async def test_severity_mapping(self, pagerduty_connector):
        """Verify that platform severities map to PD severities correctly."""
        from shared.connectors.notify_pagerduty import _SEVERITY_MAP
        assert _SEVERITY_MAP["critical"] == "critical"
        assert _SEVERITY_MAP["high"] == "error"
        assert _SEVERITY_MAP["medium"] == "warning"
        assert _SEVERITY_MAP["low"] == "info"
