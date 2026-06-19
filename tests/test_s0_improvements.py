"""Tests for S0 (Pre-LLM Enrichment & Risk-Based Correlation) improvements.

Covers:
- alert_dedup.py reconciliation to entity-based stitch_incident
- triage_worker.py enrichment wiring (enrich_alert, compute_risk_score, decide)
- triage_worker.py cumulative incident risk tracking and auto-case threshold
"""

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.worker.app.triage_worker import TriageWorker
from shared.models.alert import Alert
from shared.models.alert_dedup import AlertIncident
from shared.models.case import Case
from shared.models.case_event import CaseEvent


# ────────────────────────────────
# Alert dedup reconciliation
# ────────────────────────────────

@pytest.mark.asyncio
async def test_alert_dedup_uses_stitch_incident_when_tenant_present():
    """alert_dedup.get_or_create_incident should delegate to stitch_incident."""
    from shared.alert_dedup import get_or_create_incident

    alert = Alert(
        id=uuid.uuid4(),
        rule_id=1001,
        rule_description="Test",
        rule_level=8,
        source_ip="192.168.1.1",
        agent_id="agent-01",
    )
    tenant_id = str(uuid.uuid4())

    mock_incident = AlertIncident(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        group_key="test-key",
        rule_id=1001,
        alert_count=3,
        severity="high",
    )

    with patch("shared.alert_dedup.stitch_incident", new_callable=AsyncMock) as mock_stitch:
        mock_stitch.return_value = mock_incident
        result = await get_or_create_incident(AsyncMock(), alert, tenant_id)

    mock_stitch.assert_awaited_once()
    assert result == mock_incident
    assert result.correlation_window_minutes == 120  # default


@pytest.mark.asyncio
async def test_alert_dedup_fallback_when_stitch_fails():
    """When stitch_incident raises, alert_dedup should create a single-alert incident."""
    from shared.alert_dedup import dedup_alert_before_triage

    alert = Alert(
        id=uuid.uuid4(),
        rule_id=1001,
        rule_description="Test",
        rule_level=8,
        source_ip="192.168.1.1",
        agent_id="agent-01",
    )
    tenant_id = str(uuid.uuid4())

    session = AsyncMock()
    session.add = MagicMock()
    session.flush = AsyncMock()

    with patch("shared.alert_dedup.stitch_incident", side_effect=RuntimeError("DB error")):
        with patch("shared.alert_dedup.settings.alert_dedup_enabled", True):
            result = await dedup_alert_before_triage(session, alert, tenant_id)

    assert result.alert_count == 1
    assert result.group_key.startswith("single:")
    session.add.assert_called_once()
    session.flush.assert_awaited_once()


@pytest.mark.asyncio
async def test_alert_dedup_disabled_creates_single_alert_incident():
    """When dedup is disabled, create a standalone incident."""
    from shared.alert_dedup import dedup_alert_before_triage

    alert = Alert(
        id=uuid.uuid4(),
        rule_id=1001,
        rule_description="Test",
        rule_level=8,
        source_ip="192.168.1.1",
        agent_id="agent-01",
    )

    session = AsyncMock()
    session.add = MagicMock()
    session.flush = AsyncMock()

    with patch("shared.alert_dedup.settings.alert_dedup_enabled", False):
        result = await dedup_alert_before_triage(session, alert, None)

    assert result.alert_count == 1
    assert result.group_key.startswith("single:")


# ────────────────────────────────
# Triage worker enrichment wiring
# ────────────────────────────────

@pytest.mark.asyncio
async def test_triage_worker_enrichment_is_invoked():
    """Enrichment should run after noise reduction and before LLM."""
    worker = TriageWorker()
    worker._shutdown = True
    worker.redis_client = AsyncMock()

    alert = Alert(
        id=uuid.uuid4(),
        rule_id=5712,  # ssh brute force
        rule_description="sshd: brute force",
        rule_level=10,
        source_ip="10.0.0.5",
        agent_id="agent-01",
        agent_name="web-01",
        agent_ip="192.168.1.10",
        tenant_id=uuid.uuid4(),
    )

    class _Session:
        def __init__(self, alert):
            self._alert = alert
            self.committed = False
            self.flushed = False

        async def execute(self, stmt):
            _alert = self._alert
            class Result:
                def scalar_one_or_none(self):
                    return _alert
            return Result()

        async def flush(self):
            self.flushed = True

        async def commit(self):
            self.committed = True

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def get(self, model, id):
            return None

        def add(self, obj):
            pass

    worker.session_factory = lambda: _Session(alert)

    with patch("services.worker.app.triage_worker.noise_reduction.evaluate", new_callable=AsyncMock) as m_noise, \
         patch("services.worker.app.triage_worker.enrich_alert", new_callable=AsyncMock) as m_enrich, \
         patch("services.worker.app.triage_worker.compute_risk_score") as m_risk, \
         patch("services.worker.app.triage_worker.decide") as m_decide, \
         patch("services.worker.app.triage_worker.TieredRouter") as m_router, \
         patch("services.worker.app.triage_worker.triage_cache.lookup", new_callable=AsyncMock) as m_cache:

        m_noise.return_value = MagicMock(
            should_triage=True,
            action="keep",
            force_fast_tier=False,
            incident=None,
            reason="kept",
        )
        m_enrich.return_value = MagicMock(
            enriched=True,
            ti=[{"ioc": "10.0.0.5"}],
            asset=[{"agent_id": "agent-01", "name": "web-01", "criticality": 5}],
            user=[],
            ueba=[],
            geoip=None,
            vuln=[],
            watchlist=[],
            errors=[],
            to_dict=lambda: {},
        )
        m_risk.return_value = {"score": 65, "breakdown": {"ti": {"contribution": 20}}}
        m_decide.return_value = MagicMock(
            level=3,
            enforced=False,
            reason="shadow mode",
        )
        mock_provider = MagicMock()
        mock_provider.name.return_value = "qwen2.5-coder:3b"
        mock_provider.analyze = AsyncMock(return_value={
            "success": True,
            "summary": "Brute force attempt",
            "category": "attack",
            "severity": "high",
            "confidence": 0.8,
            "false_positive_likelihood": 0.1,
            "escalation_required": False,
        })
        m_router.return_value.get_provider = AsyncMock(return_value=mock_provider)
        m_cache.return_value = None

        await worker.process_message({"alert_id": str(alert.id)})

    m_enrich.assert_awaited_once()
    m_risk.assert_called_once()
    m_decide.assert_called_once()


@pytest.mark.asyncio
async def test_triage_worker_enrichment_context_in_prompt():
    """Enrichment data should be included in the LLM prompt."""
    worker = TriageWorker()
    worker._shutdown = True
    worker.redis_client = AsyncMock()

    alert = Alert(
        id=uuid.uuid4(),
        rule_id=5712,
        rule_description="sshd: brute force",
        rule_level=10,
        source_ip="10.0.0.5",
        agent_id="agent-01",
        agent_name="web-01",
        agent_ip="192.168.1.10",
        tenant_id=uuid.uuid4(),
    )

    captured_prompt = None

    class _Session:
        def __init__(self, alert):
            self._alert = alert

        async def execute(self, stmt):
            _alert = self._alert
            class Result:
                def scalar_one_or_none(self):
                    return _alert
            return Result()

        async def flush(self):
            pass

        async def commit(self):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def get(self, model, id):
            return None

        def add(self, obj):
            pass

    worker.session_factory = lambda: _Session(alert)

    mock_provider = MagicMock()
    mock_provider.name.return_value = "qwen2.5-coder:3b"

    async def capture_analyze(*, system_prompt, user_prompt):
        nonlocal captured_prompt
        captured_prompt = user_prompt
        return {
            "success": True,
            "summary": "Brute force attempt",
            "category": "attack",
            "severity": "high",
            "confidence": 0.8,
            "false_positive_likelihood": 0.1,
            "escalation_required": False,
        }

    mock_provider.analyze = capture_analyze

    with patch("services.worker.app.triage_worker.noise_reduction.evaluate", new_callable=AsyncMock) as m_noise, \
         patch("services.worker.app.triage_worker.enrich_alert", new_callable=AsyncMock) as m_enrich, \
         patch("services.worker.app.triage_worker.compute_risk_score") as m_risk, \
         patch("services.worker.app.triage_worker.decide") as m_decide, \
         patch("services.worker.app.triage_worker.TieredRouter") as m_router, \
         patch("services.worker.app.triage_worker.triage_cache.lookup", new_callable=AsyncMock) as m_cache:

        m_noise.return_value = MagicMock(
            should_triage=True,
            action="keep",
            force_fast_tier=False,
            incident=None,
            reason="kept",
        )
        m_enrich.return_value = MagicMock(
            enriched=True,
            ti=[{"ioc": "10.0.0.5"}],
            asset=[{"agent_id": "agent-01", "name": "web-01", "criticality": 5}],
            user=[{"email": "admin@corp.com", "is_active": True}],
            ueba=[{"anomaly_type": "login_burst", "zscore": 3.5}],
            geoip={"country": "RU"},
            vuln=[{"cve": "CVE-2024-0001"}],
            watchlist=[{"list": "blocklist"}],
            errors=[],
            to_dict=lambda: {},
        )
        m_risk.return_value = {"score": 65, "breakdown": {}}
        m_decide.return_value = MagicMock(level=3, enforced=False, reason="shadow")
        m_router.return_value.get_provider = AsyncMock(return_value=mock_provider)
        m_cache.return_value = None

        await worker.process_message({"alert_id": str(alert.id)})

    assert captured_prompt is not None
    assert "Enrichment:" in captured_prompt
    assert "Threat Intel: 1 IOC hit(s)" in captured_prompt
    assert "Asset: web-01" in captured_prompt
    assert "User: admin@corp.com" in captured_prompt
    assert "UEBA: 1 anomaly(s) detected" in captured_prompt
    assert "GeoIP: RU" in captured_prompt
    assert "Vulnerabilities: 1 CVE(s)" in captured_prompt
    assert "Watchlist: 1 hit(s)" in captured_prompt


# ────────────────────────────────
# Cumulative incident risk
# ────────────────────────────────

@pytest.mark.asyncio
async def test_triage_worker_updates_cumulative_incident_risk():
    """When an alert is part of an incident, cumulative risk should increase."""
    worker = TriageWorker()
    worker._shutdown = True
    worker.redis_client = AsyncMock()

    alert = Alert(
        id=uuid.uuid4(),
        rule_id=5712,
        rule_description="sshd: brute force",
        rule_level=10,
        source_ip="10.0.0.5",
        agent_id="agent-01",
        agent_name="web-01",
        agent_ip="192.168.1.10",
        tenant_id=uuid.uuid4(),
    )

    incident = AlertIncident(
        id=uuid.uuid4(),
        tenant_id=str(alert.tenant_id),
        group_key="test-key",
        rule_id=5712,
        alert_count=2,
        cumulative_risk_score=50,
        severity="high",
    )

    class _Session:
        def __init__(self, alert, incident):
            self._alert = alert
            self._incident = incident
            self.committed = False
            self.flushed = False

        async def execute(self, stmt):
            _alert = self._alert
            class Result:
                def scalar_one_or_none(self):
                    return _alert
            return Result()

        async def flush(self):
            self.flushed = True

        async def commit(self):
            self.committed = True

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def get(self, model, id):
            return None

        def add(self, obj):
            pass

    worker.session_factory = lambda: _Session(alert, incident)

    with patch("services.worker.app.triage_worker.noise_reduction.evaluate", new_callable=AsyncMock) as m_noise, \
         patch("services.worker.app.triage_worker.enrich_alert", new_callable=AsyncMock) as m_enrich, \
         patch("services.worker.app.triage_worker.compute_risk_score") as m_risk, \
         patch("services.worker.app.triage_worker.decide") as m_decide, \
         patch("services.worker.app.triage_worker.TieredRouter") as m_router, \
         patch("services.worker.app.triage_worker.triage_cache.lookup", new_callable=AsyncMock) as m_cache, \
         patch("services.worker.app.triage_worker.settings") as mock_settings:

        mock_settings.incident_risk_enabled = True
        mock_settings.incident_auto_case_threshold = 200.0

        m_noise.return_value = MagicMock(
            should_triage=True,
            action="keep",
            force_fast_tier=False,
            incident=incident,
            reason="kept",
        )
        m_enrich.return_value = MagicMock(
            enriched=True,
            ti=[],
            asset=[],
            user=[],
            ueba=[],
            geoip=None,
            vuln=[],
            watchlist=[],
            errors=[],
            to_dict=lambda: {},
        )
        m_risk.return_value = {"score": 65, "breakdown": {}}
        m_decide.return_value = MagicMock(level=3, enforced=False, reason="shadow")
        mock_provider = MagicMock()
        mock_provider.name.return_value = "qwen2.5-coder:3b"
        mock_provider.analyze = AsyncMock(return_value={
            "success": True,
            "summary": "Brute force attempt",
            "category": "attack",
            "severity": "high",
            "confidence": 0.8,
            "false_positive_likelihood": 0.1,
            "escalation_required": False,
        })
        m_router.return_value.get_provider = AsyncMock(return_value=mock_provider)
        m_cache.return_value = None

        await worker.process_message({"alert_id": str(alert.id)})

    assert incident.cumulative_risk_score == 115  # 50 + 65


@pytest.mark.asyncio
async def test_triage_worker_auto_case_when_cumulative_risk_exceeds_threshold():
    """When cumulative risk exceeds threshold, auto-create a case."""
    worker = TriageWorker()
    worker._shutdown = True
    worker.redis_client = AsyncMock()

    alert = Alert(
        id=uuid.uuid4(),
        rule_id=5712,
        rule_description="sshd: brute force",
        rule_level=10,
        source_ip="10.0.0.5",
        agent_id="agent-01",
        agent_name="web-01",
        agent_ip="192.168.1.10",
        tenant_id=uuid.uuid4(),
    )

    incident = AlertIncident(
        id=uuid.uuid4(),
        tenant_id=str(alert.tenant_id),
        group_key="test-key",
        rule_id=5712,
        alert_count=5,
        cumulative_risk_score=100,
        severity="critical",
    )

    added_cases = []
    added_events = []

    class _Session:
        def __init__(self, alert, incident):
            self._alert = alert
            self._incident = incident
            self.committed = False
            self.flushed = False
            self._call_count = 0

        async def execute(self, stmt):
            self._call_count += 1
            _alert = self._alert
            _count = self._call_count
            class Result:
                def scalar_one_or_none(self):
                    # First call is Alert lookup, subsequent calls should return None
                    return _alert if _count == 1 else None
            return Result()

        async def flush(self):
            self.flushed = True

        async def commit(self):
            self.committed = True

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def get(self, model, id):
            return None

        def add(self, obj):
            if isinstance(obj, Case):
                obj.id = uuid.uuid4()
                added_cases.append(obj)
            elif isinstance(obj, CaseEvent):
                added_events.append(obj)

    worker.session_factory = lambda: _Session(alert, incident)

    with patch("services.worker.app.triage_worker.noise_reduction.evaluate", new_callable=AsyncMock) as m_noise, \
         patch("services.worker.app.triage_worker.enrich_alert", new_callable=AsyncMock) as m_enrich, \
         patch("services.worker.app.triage_worker.compute_risk_score") as m_risk, \
         patch("services.worker.app.triage_worker.decide") as m_decide, \
         patch("services.worker.app.triage_worker.TieredRouter") as m_router, \
         patch("services.worker.app.triage_worker.triage_cache.lookup", new_callable=AsyncMock) as m_cache, \
         patch("services.worker.app.triage_worker.settings") as mock_settings:

        mock_settings.incident_risk_enabled = True
        mock_settings.incident_auto_case_threshold = 150.0

        m_noise.return_value = MagicMock(
            should_triage=True,
            action="keep",
            force_fast_tier=False,
            incident=incident,
            reason="kept",
        )
        m_enrich.return_value = MagicMock(
            enriched=True,
            ti=[],
            asset=[],
            user=[],
            ueba=[],
            geoip=None,
            vuln=[],
            watchlist=[],
            errors=[],
            to_dict=lambda: {},
        )
        # Score of 60 pushes cumulative from 100 to 160, exceeding threshold of 150
        m_risk.return_value = {"score": 60, "breakdown": {}}
        m_decide.return_value = MagicMock(level=3, enforced=False, reason="shadow")
        mock_provider = MagicMock()
        mock_provider.name.return_value = "qwen2.5-coder:3b"
        mock_provider.analyze = AsyncMock(return_value={
            "success": True,
            "summary": "Brute force attempt",
            "category": "attack",
            "severity": "high",
            "confidence": 0.8,
            "false_positive_likelihood": 0.1,
            "escalation_required": False,
        })
        m_router.return_value.get_provider = AsyncMock(return_value=mock_provider)
        m_cache.return_value = None

        await worker.process_message({"alert_id": str(alert.id)})

    assert incident.cumulative_risk_score == 160  # 100 + 60
    assert len(added_cases) == 1
    assert added_cases[0].category == "auto_case"
    assert added_cases[0].risk_score == 160.0
    assert len(added_events) == 1
    assert added_events[0].event_type == "case_created"
    assert "cumulative incident risk" in added_events[0].description


@pytest.mark.asyncio
async def test_triage_worker_no_auto_case_when_below_threshold():
    """When cumulative risk stays below threshold, no auto-case should be created."""
    worker = TriageWorker()
    worker._shutdown = True
    worker.redis_client = AsyncMock()

    alert = Alert(
        id=uuid.uuid4(),
        rule_id=5712,
        rule_description="sshd: brute force",
        rule_level=10,
        source_ip="10.0.0.5",
        agent_id="agent-01",
        agent_name="web-01",
        agent_ip="192.168.1.10",
        tenant_id=uuid.uuid4(),
    )

    incident = AlertIncident(
        id=uuid.uuid4(),
        tenant_id=str(alert.tenant_id),
        group_key="test-key",
        rule_id=5712,
        alert_count=2,
        cumulative_risk_score=50,
        severity="medium",
    )

    added_cases = []

    class _Session:
        def __init__(self, alert, incident):
            self._alert = alert
            self._incident = incident

        async def execute(self, stmt):
            _alert = self._alert
            class Result:
                def scalar_one_or_none(self):
                    return _alert
            return Result()

        async def flush(self):
            pass

        async def commit(self):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def get(self, model, id):
            return None

        def add(self, obj):
            if isinstance(obj, Case):
                obj.id = uuid.uuid4()
                added_cases.append(obj)

    worker.session_factory = lambda: _Session(alert, incident)

    with patch("services.worker.app.triage_worker.noise_reduction.evaluate", new_callable=AsyncMock) as m_noise, \
         patch("services.worker.app.triage_worker.enrich_alert", new_callable=AsyncMock) as m_enrich, \
         patch("services.worker.app.triage_worker.compute_risk_score") as m_risk, \
         patch("services.worker.app.triage_worker.decide") as m_decide, \
         patch("services.worker.app.triage_worker.TieredRouter") as m_router, \
         patch("services.worker.app.triage_worker.triage_cache.lookup", new_callable=AsyncMock) as m_cache, \
         patch("services.worker.app.triage_worker.settings") as mock_settings:

        mock_settings.incident_risk_enabled = True
        mock_settings.incident_auto_case_threshold = 150.0

        m_noise.return_value = MagicMock(
            should_triage=True,
            action="keep",
            force_fast_tier=False,
            incident=incident,
            reason="kept",
        )
        m_enrich.return_value = MagicMock(
            enriched=True,
            ti=[],
            asset=[],
            user=[],
            ueba=[],
            geoip=None,
            vuln=[],
            watchlist=[],
            errors=[],
            to_dict=lambda: {},
        )
        # Score of 40 pushes cumulative from 50 to 90, below threshold of 150
        m_risk.return_value = {"score": 40, "breakdown": {}}
        m_decide.return_value = MagicMock(level=2, enforced=False, reason="shadow")
        mock_provider = MagicMock()
        mock_provider.name.return_value = "qwen2.5-coder:3b"
        mock_provider.analyze = AsyncMock(return_value={
            "success": True,
            "summary": "Brute force attempt",
            "category": "attack",
            "severity": "medium",
            "confidence": 0.7,
            "false_positive_likelihood": 0.2,
            "escalation_required": False,
        })
        m_router.return_value.get_provider = AsyncMock(return_value=mock_provider)
        m_cache.return_value = None

        await worker.process_message({"alert_id": str(alert.id)})

    assert incident.cumulative_risk_score == 90  # 50 + 40
    assert len(added_cases) == 0


@pytest.mark.asyncio
async def test_triage_worker_incident_risk_disabled():
    """When incident_risk_enabled is False, cumulative risk should not be updated."""
    worker = TriageWorker()
    worker._shutdown = True
    worker.redis_client = AsyncMock()

    alert = Alert(
        id=uuid.uuid4(),
        rule_id=5712,
        rule_description="sshd: brute force",
        rule_level=10,
        source_ip="10.0.0.5",
        agent_id="agent-01",
        agent_name="web-01",
        agent_ip="192.168.1.10",
        tenant_id=uuid.uuid4(),
    )

    incident = AlertIncident(
        id=uuid.uuid4(),
        tenant_id=str(alert.tenant_id),
        group_key="test-key",
        rule_id=5712,
        alert_count=2,
        cumulative_risk_score=50,
        severity="medium",
    )

    class _Session:
        def __init__(self, alert, incident):
            self._alert = alert
            self._incident = incident

        async def execute(self, stmt):
            _alert = self._alert
            class Result:
                def scalar_one_or_none(self):
                    return _alert
            return Result()

        async def flush(self):
            pass

        async def commit(self):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def get(self, model, id):
            return None

        def add(self, obj):
            pass

    worker.session_factory = lambda: _Session(alert, incident)

    with patch("services.worker.app.triage_worker.noise_reduction.evaluate", new_callable=AsyncMock) as m_noise, \
         patch("services.worker.app.triage_worker.enrich_alert", new_callable=AsyncMock) as m_enrich, \
         patch("services.worker.app.triage_worker.compute_risk_score") as m_risk, \
         patch("services.worker.app.triage_worker.decide") as m_decide, \
         patch("services.worker.app.triage_worker.TieredRouter") as m_router, \
         patch("services.worker.app.triage_worker.triage_cache.lookup", new_callable=AsyncMock) as m_cache, \
         patch("services.worker.app.triage_worker.settings") as mock_settings:

        mock_settings.incident_risk_enabled = False

        m_noise.return_value = MagicMock(
            should_triage=True,
            action="keep",
            force_fast_tier=False,
            incident=incident,
            reason="kept",
        )
        m_enrich.return_value = MagicMock(
            enriched=True,
            ti=[],
            asset=[],
            user=[],
            ueba=[],
            geoip=None,
            vuln=[],
            watchlist=[],
            errors=[],
            to_dict=lambda: {},
        )
        m_risk.return_value = {"score": 65, "breakdown": {}}
        m_decide.return_value = MagicMock(level=3, enforced=False, reason="shadow")
        mock_provider = MagicMock()
        mock_provider.name.return_value = "qwen2.5-coder:3b"
        mock_provider.analyze = AsyncMock(return_value={
            "success": True,
            "summary": "Brute force attempt",
            "category": "attack",
            "severity": "high",
            "confidence": 0.8,
            "false_positive_likelihood": 0.1,
            "escalation_required": False,
        })
        m_router.return_value.get_provider = AsyncMock(return_value=mock_provider)
        m_cache.return_value = None

        await worker.process_message({"alert_id": str(alert.id)})

    assert incident.cumulative_risk_score == 50  # unchanged
