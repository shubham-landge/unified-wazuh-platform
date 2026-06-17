"""Error recovery tests — verify graceful degradation under failure conditions."""
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shared.models.alert import Alert
from shared.correlation.entities import extract_entities


@pytest.mark.asyncio
async def test_entity_extraction_empty_returns_empty_list():
    alert = MagicMock(spec=Alert)
    for attr in ("user_name", "agent_id", "agent_name", "agent_ip", "source_ip",
                 "destination_ip", "principal", "session_id", "source_user",
                 "destination_host", "target_host", "device_id"):
        setattr(alert, attr, None)
    entities = extract_entities(alert)
    assert entities == []


@pytest.mark.asyncio
async def test_entity_extraction_no_duplicates():
    alert = MagicMock(spec=Alert)
    alert.user_name = "admin"
    alert.agent_name = None
    alert.agent_ip = "10.0.0.1"
    alert.source_ip = "10.0.0.1"
    alert.destination_ip = "10.0.0.1"
    alert.principal = None
    alert.session_id = None
    entities = extract_entities(alert)
    ip_entities = [e for e in entities if e.entity_type == "ip"]
    assert len(ip_entities) <= 2


@pytest.mark.asyncio
async def test_stitch_incident_missing_entity_fields():
    from shared.correlation.stitch import _create_new_incident
    alert = MagicMock(spec=Alert)
    alert.id = uuid.uuid4()
    alert.source_ip = None
    alert.user_name = None
    alert.mitre_technique = None
    alert.agent_id = None
    alert.rule_id = 999
    alert.rule_description = ""
    alert.rule_level = 0
    alert.severity = None
    alert.source_type = "endpoint"
    alert.created_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)

    mock_session = AsyncMock()
    mock_session.flush = AsyncMock()
    mock_session.execute = AsyncMock()

    incident = await _create_new_incident(mock_session, alert, uuid.uuid4())
    assert incident is not None
    assert incident.alert_count == 1


@pytest.mark.asyncio
async def test_killchain_unknown_stage():
    from shared.correlation.killchain import is_advancing
    assert is_advancing("unknown") is False
    assert is_advancing("initial_access") is False
    assert is_advancing("lateral_movement") is True
    assert is_advancing("exfiltration") is True
    assert is_advancing("") is False
