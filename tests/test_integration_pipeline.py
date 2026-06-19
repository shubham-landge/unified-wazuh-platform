"""Integration smoke test for the core Phase 9 pipeline.

Tests that entities, stitching, killchain, and enrichment work together
without requiring external dependencies (Wazuh, Ollama, etc.).
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shared.models.alert import Alert
from shared.models.alert_dedup import AlertIncident
from shared.correlation.entities import extract_entities, ExtractedEntity
from shared.correlation.stitch import stitch_incident


@pytest.mark.asyncio
async def test_extract_entities_from_endpoint_alert():
    alert = MagicMock(spec=Alert)
    alert.user_name = "alice@example.com"
    alert.agent_id = "agent-001"
    alert.agent_name = "laptop-1"
    alert.agent_ip = "10.0.0.1"
    alert.source_ip = "10.0.0.1"
    alert.destination_ip = "203.0.113.5"
    alert.principal = ""
    alert.session_id = ""

    entities = extract_entities(alert)

    assert len(entities) >= 2
    types = {e.entity_type for e in entities}
    assert ExtractedEntity("user", "alice@example.com", "actor").entity_type in types
    assert ExtractedEntity("host", "laptop-1", "source").entity_type in types


@pytest.mark.asyncio
async def test_extract_entities_with_empty_alert():
    alert = MagicMock(spec=Alert)
    alert.user_name = None
    alert.agent_id = None
    alert.agent_name = None
    alert.agent_ip = None
    alert.source_ip = None
    alert.destination_ip = None
    alert.principal = None
    alert.session_id = None

    entities = extract_entities(alert)
    assert entities == []


@pytest.mark.asyncio
async def test_extract_entities_dedup():
    alert = MagicMock(spec=Alert)
    alert.user_name = "admin"
    alert.agent_name = "server-1"
    alert.agent_ip = "10.0.0.1"
    alert.source_ip = "10.0.0.1"
    alert.destination_ip = None
    alert.principal = None
    alert.session_id = None

    entities = extract_entities(alert)
    ip_count = sum(1 for e in entities if e.entity_type == "ip")
    assert ip_count == 1


@pytest.mark.asyncio
async def test_stitch_incident_creates_new():
    alert = MagicMock(spec=Alert)
    alert.id = uuid.uuid4()
    alert.user_name = "alice"
    alert.agent_id = None
    alert.agent_name = "laptop"
    alert.agent_ip = "10.0.0.1"
    alert.source_ip = "10.0.0.1"
    alert.destination_ip = None
    alert.principal = None
    alert.session_id = None
    alert.rule_id = 123
    alert.rule_description = "Test alert"
    alert.rule_level = 10
    alert.mitre_technique = "T1078"
    alert.severity = "high"
    alert.source_type = "endpoint"
    alert.created_at = datetime.now(timezone.utc)

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock()
    mock_session.execute.return_value = MagicMock()
    mock_session.execute.return_value.scalar_one_or_none = MagicMock(return_value=None)
    mock_session.execute.return_value.all = MagicMock(return_value=[])
    mock_session.flush = AsyncMock()

    tenant_id = uuid.uuid4()
    incident = await stitch_incident(mock_session, alert, tenant_id)

    assert incident is not None
    assert incident.tenant_id == tenant_id
    assert incident.alert_count == 1
    assert incident.cross_domain is False


@pytest.mark.asyncio
async def test_killchain_stage_ordering():
    from shared.correlation.killchain import _stage_index, _is_advancement

    assert _stage_index("initial_access") < _stage_index("exfiltration")
    assert _is_advancement("initial_access", "lateral_movement") is True
    assert _is_advancement("exfiltration", "initial_access") is False


@pytest.mark.asyncio
async def test_enrichment_fanout_partial_failure():
    from shared.orchestrator.enrichment import enrich_incident

    incident = MagicMock(spec=AlertIncident)
    incident.id = uuid.uuid4()
    incident.stage_history = []
    incident.source_domains = []

    mock_session = AsyncMock()

    # The refactored enrich_incident delegates per-alert work to
    # shared.enrichment.pipeline.enrich_alert.  Patch it to simulate a
    # partial failure (one alert raises, another returns empty).
    with patch("shared.orchestrator.enrichment.enrich_alert", side_effect=Exception("API down")) as m_enrich:
        with patch("shared.orchestrator.enrichment._enrich_few_shot", return_value=[]):
            with patch("shared.orchestrator.enrichment._enrich_related_incidents", return_value=[]):
                pack = await enrich_incident(mock_session, incident)

    assert pack.enriched_at is not None
    assert pack.threat_intel == []
    assert pack.asset_criticality == []
    assert pack.user_risk == []
