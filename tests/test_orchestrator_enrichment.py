"""Tests for orchestrator enrichment refactoring — EvidencePack construction,
enrich_incident() delegation to shared/enrichment package, aggregation, and
deduplication of TI / asset / user / UEBA results.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shared.orchestrator.enrichment import (
    EvidencePack,
    enrich_incident,
    _deduplicate_dicts,
)
from shared.enrichment.risk_score import EnrichmentContext
from shared.models.alert_dedup import AlertIncident


# ─── EvidencePack ────────────────────────────────────────────────────────────

class TestEvidencePack:
    def test_default_constructor(self):
        pack = EvidencePack()
        assert pack.threat_intel == []
        assert pack.asset_criticality == []
        assert pack.user_risk == []
        assert pack.ueba_anomalies == []
        assert pack.few_shot_examples == []
        assert pack.related_incidents == []
        assert pack.enriched_at is None

    def test_to_dict_serializes_all_fields(self):
        pack = EvidencePack()
        pack.threat_intel = [{"ioc": "10.0.0.1"}]
        pack.asset_criticality = [{"agent_id": "agent-01", "criticality": 7}]
        pack.user_risk = [{"email": "admin@corp.com"}]
        pack.ueba_anomalies = [{"subject_id": "user-x", "z_score": 3.5}]
        pack.few_shot_examples = [{"technique": "T1486"}]
        pack.related_incidents = [{"incident_id": "inc-001"}]
        pack.enriched_at = "2025-01-01T00:00:00Z"

        d = pack.to_dict()
        assert d["threat_intel"] == pack.threat_intel
        assert d["asset_criticality"] == pack.asset_criticality
        assert d["user_risk"] == pack.user_risk
        assert d["ueba_anomalies"] == pack.ueba_anomalies
        assert d["few_shot_examples"] == pack.few_shot_examples
        assert d["related_incidents"] == pack.related_incidents
        assert d["enriched_at"] == pack.enriched_at


# ─── _deduplicate_dicts ─────────────────────────────────────────────────────

class TestDeduplicateDicts:
    def test_dedup_by_key(self):
        items = [
            {"id": 1, "val": "a"},
            {"id": 2, "val": "b"},
            {"id": 1, "val": "c"},  # duplicate id
            {"id": 3, "val": "d"},
        ]
        result = _deduplicate_dicts(items, lambda d: d["id"])
        assert len(result) == 3
        ids = [d["id"] for d in result]
        assert ids == [1, 2, 3]

    def test_preserves_first_occurrence(self):
        items = [
            {"id": 1, "val": "first"},
            {"id": 1, "val": "second"},
        ]
        result = _deduplicate_dicts(items, lambda d: d["id"])
        assert result[0]["val"] == "first"

    def test_empty_input(self):
        assert _deduplicate_dicts([], lambda d: d) == []

    def test_single_item(self):
        items = [{"id": 1}]
        result = _deduplicate_dicts(items, lambda d: d["id"])
        assert result == items

    def test_tuple_key(self):
        items = [
            {"subject_type": "agent", "subject_id": "a1"},
            {"subject_type": "user", "subject_id": "u1"},
            {"subject_type": "agent", "subject_id": "a1"},  # duplicate
        ]
        result = _deduplicate_dicts(
            items, lambda d: (d["subject_type"], d["subject_id"])
        )
        assert len(result) == 2


# ─── enrich_incident(): delegation to shared/enrichment/pipeline ─────────────

class TestEnrichIncidentDelegation:
    """Verify enrich_incident delegates per-alert enrichment to the shared
    enrichment pipeline and correctly aggregates raw results."""

    async def test_no_alerts_returns_empty_pack(self):
        """When no alerts are linked to the incident, returns empty pack."""
        mock_session = AsyncMock()
        incident = MagicMock(spec=AlertIncident)
        incident.id = uuid.uuid4()

        with patch(
            "shared.orchestrator.enrichment._alerts_for_incident",
            return_value=[],
        ):
            pack = await enrich_incident(mock_session, incident)

        assert pack.enriched_at is not None
        assert pack.threat_intel == []
        assert pack.asset_criticality == []
        assert pack.user_risk == []
        assert pack.ueba_anomalies == []
        assert pack.few_shot_examples == []
        assert pack.related_incidents == []

    async def test_aggregates_ti_results(self):
        """TI results from pipeline are aggregated into EvidencePack.threat_intel."""
        mock_session = AsyncMock()
        incident = MagicMock(spec=AlertIncident)
        incident.id = uuid.uuid4()

        # Simulate two alerts, each returning an EnrichmentContext with TI hits
        ctx1 = EnrichmentContext(rule_level=10)
        ctx1.ti = [{"ioc": "10.0.0.1", "is_known_bad": True, "confidence": 0.95, "is_kev": False}]

        ctx2 = EnrichmentContext(rule_level=12)
        ctx2.ti = [{"ioc": "203.0.113.5", "is_known_bad": False, "confidence": 0.6, "is_kev": True}]

        mock_alert1 = MagicMock()
        mock_alert2 = MagicMock()

        with patch(
            "shared.orchestrator.enrichment._alerts_for_incident",
            return_value=[mock_alert1, mock_alert2],
        ):
            with patch(
                "shared.orchestrator.enrichment.enrich_alert",
                side_effect=[ctx1, ctx2],
            ):
                with patch(
                    "shared.orchestrator.enrichment._enrich_few_shot",
                    return_value=[],
                ):
                    with patch(
                        "shared.orchestrator.enrichment._enrich_related_incidents",
                        return_value=[],
                    ):
                        pack = await enrich_incident(mock_session, incident)

        assert len(pack.threat_intel) == 2
        iocs = [d["ioc"] for d in pack.threat_intel]
        assert "10.0.0.1" in iocs
        assert "203.0.113.5" in iocs

    async def test_aggregates_asset_results(self):
        """Asset criticality from pipeline is aggregated into EvidencePack.asset_criticality."""
        mock_session = AsyncMock()
        incident = MagicMock(spec=AlertIncident)
        incident.id = uuid.uuid4()

        ctx = EnrichmentContext(rule_level=10)
        ctx.asset = [{"agent_id": "agent-01", "criticality": 7, "is_crown_jewel": False}]
        ctx.ti = []
        ctx.user = []
        ctx.ueba = []

        mock_alert = MagicMock()

        with patch(
            "shared.orchestrator.enrichment._alerts_for_incident",
            return_value=[mock_alert],
        ):
            with patch(
                "shared.orchestrator.enrichment.enrich_alert",
                return_value=ctx,
            ):
                with patch(
                    "shared.orchestrator.enrichment._enrich_few_shot",
                    return_value=[],
                ):
                    with patch(
                        "shared.orchestrator.enrichment._enrich_related_incidents",
                        return_value=[],
                    ):
                        pack = await enrich_incident(mock_session, incident)

        assert len(pack.asset_criticality) == 1
        assert pack.asset_criticality[0]["agent_id"] == "agent-01"
        assert pack.asset_criticality[0]["criticality"] == 7

    async def test_aggregates_user_results(self):
        """User risk factors from pipeline are aggregated into EvidencePack.user_risk."""
        mock_session = AsyncMock()
        incident = MagicMock(spec=AlertIncident)
        incident.id = uuid.uuid4()

        ctx = EnrichmentContext(rule_level=10)
        ctx.user = [{
            "user_name": "admin@corp.com",
            "is_privileged": True,
            "is_service_acct_interactive": False,
            "is_dormant_reactivated": False,
        }]
        ctx.ti = []
        ctx.asset = []
        ctx.ueba = []

        mock_alert = MagicMock()

        with patch(
            "shared.orchestrator.enrichment._alerts_for_incident",
            return_value=[mock_alert],
        ):
            with patch(
                "shared.orchestrator.enrichment.enrich_alert",
                return_value=ctx,
            ):
                with patch(
                    "shared.orchestrator.enrichment._enrich_few_shot",
                    return_value=[],
                ):
                    with patch(
                        "shared.orchestrator.enrichment._enrich_related_incidents",
                        return_value=[],
                    ):
                        pack = await enrich_incident(mock_session, incident)

        assert len(pack.user_risk) == 1
        assert pack.user_risk[0]["user_name"] == "admin@corp.com"
        assert pack.user_risk[0]["is_privileged"] is True

    async def test_aggregates_ueba_results(self):
        """UEBA anomalies from pipeline are aggregated into EvidencePack.ueba_anomalies."""
        mock_session = AsyncMock()
        incident = MagicMock(spec=AlertIncident)
        incident.id = uuid.uuid4()

        ctx = EnrichmentContext(rule_level=10)
        ctx.ueba = [
            {"subject_type": "agent", "subject_id": "agent-01", "z_score": 3.5, "anomaly_type": "spike"},
            {"subject_type": "user", "subject_id": "user-x", "z_score": 5.0, "anomaly_type": "outlier"},
        ]
        ctx.ti = []
        ctx.asset = []
        ctx.user = []

        mock_alert = MagicMock()

        with patch(
            "shared.orchestrator.enrichment._alerts_for_incident",
            return_value=[mock_alert],
        ):
            with patch(
                "shared.orchestrator.enrichment.enrich_alert",
                return_value=ctx,
            ):
                with patch(
                    "shared.orchestrator.enrichment._enrich_few_shot",
                    return_value=[],
                ):
                    with patch(
                        "shared.orchestrator.enrichment._enrich_related_incidents",
                        return_value=[],
                    ):
                        pack = await enrich_incident(mock_session, incident)

        assert len(pack.ueba_anomalies) == 2

    async def test_include_few_shot_and_related_incidents(self):
        """Incident-level enrichers populate few_shot_examples and related_incidents."""
        mock_session = AsyncMock()
        incident = MagicMock(spec=AlertIncident)
        incident.id = uuid.uuid4()

        few_shot = [{"technique": "T1486", "example": "ransomware pattern"}]
        related = [{"incident_id": "inc-002", "severity": "critical"}]

        mock_alert = MagicMock()

        # Need at least one alert for incident-level enrichers to run
        with patch(
            "shared.orchestrator.enrichment._alerts_for_incident",
            return_value=[mock_alert],
        ):
            with patch(
                "shared.orchestrator.enrichment.enrich_alert",
                return_value=EnrichmentContext(rule_level=10),
            ):
                with patch(
                    "shared.orchestrator.enrichment._enrich_few_shot",
                    return_value=few_shot,
                ):
                    with patch(
                        "shared.orchestrator.enrichment._enrich_related_incidents",
                        return_value=related,
                    ):
                        pack = await enrich_incident(mock_session, incident)

        assert pack.few_shot_examples == few_shot
        assert pack.related_incidents == related


# ─── enrich_incident(): error handling ──────────────────────────────────────

class TestEnrichIncidentErrors:
    """Verify graceful degradation when enrichers fail."""

    async def test_partial_enrich_alert_failure(self):
        """When one enrich_alert raises, it's caught and the rest succeed."""
        mock_session = AsyncMock()
        incident = MagicMock(spec=AlertIncident)
        incident.id = uuid.uuid4()

        ctx_good = EnrichmentContext(rule_level=10)
        ctx_good.ti = [{"ioc": "10.0.0.5", "is_known_bad": True, "confidence": 0.99, "is_kev": False}]
        ctx_good.asset = []
        ctx_good.user = []
        ctx_good.ueba = []

        mock_alert1 = MagicMock()
        mock_alert2 = MagicMock()
        mock_alert3 = MagicMock()

        with patch(
            "shared.orchestrator.enrichment._alerts_for_incident",
            return_value=[mock_alert1, mock_alert2, mock_alert3],
        ):
            with patch(
                "shared.orchestrator.enrichment.enrich_alert",
                side_effect=[ctx_good, Exception("TI API down"), ctx_good],
            ):
                with patch(
                    "shared.orchestrator.enrichment._enrich_few_shot",
                    return_value=[],
                ):
                    with patch(
                        "shared.orchestrator.enrichment._enrich_related_incidents",
                        return_value=[],
                    ):
                        pack = await enrich_incident(mock_session, incident)

        # Should have TI from 2 good alerts (both same IOC, dedup'd to 1)
        assert len(pack.threat_intel) == 1
        assert pack.threat_intel[0]["ioc"] == "10.0.0.5"

    async def test_all_alerts_raise(self):
        """When all enrich_alert calls raise, returns empty pack."""
        mock_session = AsyncMock()
        incident = MagicMock(spec=AlertIncident)
        incident.id = uuid.uuid4()

        mock_alert = MagicMock()

        with patch(
            "shared.orchestrator.enrichment._alerts_for_incident",
            return_value=[mock_alert, mock_alert],
        ):
            with patch(
                "shared.orchestrator.enrichment.enrich_alert",
                side_effect=Exception("API down"),
            ):
                with patch(
                    "shared.orchestrator.enrichment._enrich_few_shot",
                    return_value=[],
                ):
                    with patch(
                        "shared.orchestrator.enrichment._enrich_related_incidents",
                        return_value=[],
                    ):
                        pack = await enrich_incident(mock_session, incident)

        assert pack.enriched_at is not None
        assert pack.threat_intel == []
        assert pack.asset_criticality == []
        assert pack.user_risk == []
        assert pack.ueba_anomalies == []

    async def test_few_shot_failure_does_not_block_pack(self):
        """If few-shot enrichment fails, the rest of the pack is still returned."""
        mock_session = AsyncMock()
        incident = MagicMock(spec=AlertIncident)
        incident.id = uuid.uuid4()

        ctx = EnrichmentContext(rule_level=10)
        ctx.ti = [{"ioc": "10.0.0.1", "is_known_bad": False, "confidence": 0.3, "is_kev": False}]
        ctx.asset = []
        ctx.user = []
        ctx.ueba = []

        mock_alert = MagicMock()

        with patch(
            "shared.orchestrator.enrichment._alerts_for_incident",
            return_value=[mock_alert],
        ):
            with patch(
                "shared.orchestrator.enrichment.enrich_alert",
                return_value=ctx,
            ):
                with patch(
                    "shared.orchestrator.enrichment._enrich_few_shot",
                    side_effect=Exception("RAG unavailable"),
                ):
                    with patch(
                        "shared.orchestrator.enrichment._enrich_related_incidents",
                        return_value=[],
                    ):
                        pack = await enrich_incident(mock_session, incident)

        assert pack.few_shot_examples == []
        assert pack.threat_intel == ctx.ti  # TI still populated

    async def test_related_incidents_failure_does_not_block_pack(self):
        """If related incidents enrichment fails, the rest of the pack is still returned."""
        mock_session = AsyncMock()
        incident = MagicMock(spec=AlertIncident)
        incident.id = uuid.uuid4()

        ctx = EnrichmentContext(rule_level=10)
        ctx.ti = []
        ctx.asset = []
        ctx.user = []
        ctx.ueba = []

        mock_alert = MagicMock()

        with patch(
            "shared.orchestrator.enrichment._alerts_for_incident",
            return_value=[mock_alert],
        ):
            with patch(
                "shared.orchestrator.enrichment.enrich_alert",
                return_value=ctx,
            ):
                with patch(
                    "shared.orchestrator.enrichment._enrich_few_shot",
                    return_value=[],
                ):
                    with patch(
                        "shared.orchestrator.enrichment._enrich_related_incidents",
                        side_effect=Exception("DB query failed"),
                    ):
                        pack = await enrich_incident(mock_session, incident)

        assert pack.related_incidents == []


# ─── enrich_incident(): deduplication ───────────────────────────────────────

class TestEnrichIncidentDedup:
    """Verify that duplicate enrichment entries across alerts are deduplicated."""

    async def test_dedup_ti_by_ioc(self):
        """Duplicate IOC entries across alerts are collapsed to one."""
        mock_session = AsyncMock()
        incident = MagicMock(spec=AlertIncident)
        incident.id = uuid.uuid4()

        ctx1 = EnrichmentContext(rule_level=10)
        ctx1.ti = [{"ioc": "10.0.0.1", "is_known_bad": True, "confidence": 0.95, "is_kev": False}]
        ctx1.asset = []
        ctx1.user = []
        ctx1.ueba = []

        ctx2 = EnrichmentContext(rule_level=12)
        ctx2.ti = [{"ioc": "10.0.0.1", "is_known_bad": True, "confidence": 0.95, "is_kev": False}]
        ctx2.asset = []
        ctx2.user = []
        ctx2.ueba = []

        mock_alert1 = MagicMock()
        mock_alert2 = MagicMock()

        with patch(
            "shared.orchestrator.enrichment._alerts_for_incident",
            return_value=[mock_alert1, mock_alert2],
        ):
            with patch(
                "shared.orchestrator.enrichment.enrich_alert",
                side_effect=[ctx1, ctx2],
            ):
                with patch(
                    "shared.orchestrator.enrichment._enrich_few_shot",
                    return_value=[],
                ):
                    with patch(
                        "shared.orchestrator.enrichment._enrich_related_incidents",
                        return_value=[],
                    ):
                        pack = await enrich_incident(mock_session, incident)

        assert len(pack.threat_intel) == 1

    async def test_dedup_asset_by_agent_id(self):
        """Duplicate agent entries across alerts are collapsed to one."""
        mock_session = AsyncMock()
        incident = MagicMock(spec=AlertIncident)
        incident.id = uuid.uuid4()

        ctx1 = EnrichmentContext(rule_level=10)
        ctx1.asset = [{"agent_id": "agent-01", "criticality": 7, "is_crown_jewel": False}]
        ctx1.ti = []
        ctx1.user = []
        ctx1.ueba = []

        ctx2 = EnrichmentContext(rule_level=12)
        ctx2.asset = [{"agent_id": "agent-01", "criticality": 7, "is_crown_jewel": False}]
        ctx2.ti = []
        ctx2.user = []
        ctx2.ueba = []

        mock_alert1 = MagicMock()
        mock_alert2 = MagicMock()

        with patch(
            "shared.orchestrator.enrichment._alerts_for_incident",
            return_value=[mock_alert1, mock_alert2],
        ):
            with patch(
                "shared.orchestrator.enrichment.enrich_alert",
                side_effect=[ctx1, ctx2],
            ):
                with patch(
                    "shared.orchestrator.enrichment._enrich_few_shot",
                    return_value=[],
                ):
                    with patch(
                        "shared.orchestrator.enrichment._enrich_related_incidents",
                        return_value=[],
                    ):
                        pack = await enrich_incident(mock_session, incident)

        assert len(pack.asset_criticality) == 1

    async def test_dedup_user_by_email(self):
        """Duplicate user entries across alerts are collapsed to one."""
        mock_session = AsyncMock()
        incident = MagicMock(spec=AlertIncident)
        incident.id = uuid.uuid4()

        ctx1 = EnrichmentContext(rule_level=10)
        ctx1.user = [{"user_name": "admin@corp.com", "is_privileged": True, "is_service_acct_interactive": False, "is_dormant_reactivated": False}]
        ctx1.ti = []
        ctx1.asset = []
        ctx1.ueba = []

        ctx2 = EnrichmentContext(rule_level=12)
        ctx2.user = [{"user_name": "admin@corp.com", "is_privileged": True, "is_service_acct_interactive": False, "is_dormant_reactivated": False}]
        ctx2.ti = []
        ctx2.asset = []
        ctx2.ueba = []

        mock_alert1 = MagicMock()
        mock_alert2 = MagicMock()

        with patch(
            "shared.orchestrator.enrichment._alerts_for_incident",
            return_value=[mock_alert1, mock_alert2],
        ):
            with patch(
                "shared.orchestrator.enrichment.enrich_alert",
                side_effect=[ctx1, ctx2],
            ):
                with patch(
                    "shared.orchestrator.enrichment._enrich_few_shot",
                    return_value=[],
                ):
                    with patch(
                        "shared.orchestrator.enrichment._enrich_related_incidents",
                        return_value=[],
                    ):
                        pack = await enrich_incident(mock_session, incident)

        assert len(pack.user_risk) == 1

    async def test_dedup_ueba_by_subject_type_and_id(self):
        """Duplicate UEBA entries (same subject_type + subject_id) are collapsed."""
        mock_session = AsyncMock()
        incident = MagicMock(spec=AlertIncident)
        incident.id = uuid.uuid4()

        ctx1 = EnrichmentContext(rule_level=10)
        ctx1.ueba = [
            {"subject_type": "agent", "subject_id": "agent-01", "z_score": 3.5, "anomaly_type": "spike"},
            {"subject_type": "user", "subject_id": "user-x", "z_score": 2.0, "anomaly_type": "outlier"},
        ]
        ctx1.ti = []
        ctx1.asset = []
        ctx1.user = []

        ctx2 = EnrichmentContext(rule_level=12)
        ctx2.ueba = [
            {"subject_type": "agent", "subject_id": "agent-01", "z_score": 3.5, "anomaly_type": "spike"},
        ]
        ctx2.ti = []
        ctx2.asset = []
        ctx2.user = []

        mock_alert1 = MagicMock()
        mock_alert2 = MagicMock()

        with patch(
            "shared.orchestrator.enrichment._alerts_for_incident",
            return_value=[mock_alert1, mock_alert2],
        ):
            with patch(
                "shared.orchestrator.enrichment.enrich_alert",
                side_effect=[ctx1, ctx2],
            ):
                with patch(
                    "shared.orchestrator.enrichment._enrich_few_shot",
                    return_value=[],
                ):
                    with patch(
                        "shared.orchestrator.enrichment._enrich_related_incidents",
                        return_value=[],
                    ):
                        pack = await enrich_incident(mock_session, incident)

        assert len(pack.ueba_anomalies) == 2  # agent-01 + user-x, not 3


# ─── Import path verification ───────────────────────────────────────────────

class TestImportPaths:
    """Verify that the orchestrator correctly delegates to the shared package."""

    def test_orchestrator_imports_from_shared_enrichment(self):
        """enrich_incident imports enrich_alert from shared.enrichment.pipeline."""
        import shared.orchestrator.enrichment as mod
        assert hasattr(mod, "enrich_incident")
        # enrich_alert should be importable from the shared package path
        from shared.enrichment.pipeline import enrich_alert
        assert callable(enrich_alert)

    def test_evidence_pack_importable(self):
        """EvidencePack is importable from the orchestrator module."""
        from shared.orchestrator.enrichment import EvidencePack
        pack = EvidencePack()
        assert pack is not None

    def test_enrich_alert_backward_compat(self):
        """enrich_alert is the same as pipeline.run for backward compatibility."""
        from shared.enrichment.pipeline import run, enrich_alert
        assert enrich_alert is run

    def test_context_has_raw_list_fields(self):
        """EnrichmentContext has .ti, .asset, .user, .ueba list fields."""
        ctx = EnrichmentContext()
        assert ctx.ti == []
        assert ctx.asset == []
        assert ctx.user == []
        assert ctx.ueba == []

    def test_context_raw_fields_are_lists(self):
        """Raw result fields are instance lists, not shared across instances."""
        ctx1 = EnrichmentContext()
        ctx2 = EnrichmentContext()
        ctx1.ti.append({"ioc": "1.1.1.1"})
        assert ctx1.ti == [{"ioc": "1.1.1.1"}]
        assert ctx2.ti == []  # not contaminated


# ─── Integration: end-to-end flow ────────────────────────────────────────────

class TestOrchestratorEnrichmentIntegration:
    """End-to-end integration test mirroring the correlation handler flow."""

    async def test_full_flow_with_enriched_contexts(self):
        """Multiple enriched alerts → aggregated EvidencePack with all fields."""
        from shared.orchestrator.enrichment import enrich_incident

        mock_session = AsyncMock()
        incident = MagicMock(spec=AlertIncident)
        incident.id = uuid.uuid4()

        # Three alerts, each with different enrichment results
        ctx1 = EnrichmentContext(rule_level=10)
        ctx1.ti = [{"ioc": "10.0.0.1", "is_known_bad": True, "confidence": 0.95, "is_kev": False}]
        ctx1.asset = [{"agent_id": "agent-01", "criticality": 7, "is_crown_jewel": False}]
        ctx1.user = [{"user_name": "admin", "is_privileged": True, "is_service_acct_interactive": False, "is_dormant_reactivated": False}]
        ctx1.ueba = [{"subject_type": "agent", "subject_id": "agent-01", "z_score": 3.5, "anomaly_type": "spike"}]

        ctx2 = EnrichmentContext(rule_level=12)
        ctx2.ti = [{"ioc": "203.0.113.5", "is_known_bad": False, "confidence": 0.6, "is_kev": True}]
        ctx2.asset = [{"agent_id": "agent-02", "criticality": 9, "is_crown_jewel": True}]
        ctx2.user = [{"user_name": "svc-backup", "is_privileged": False, "is_service_acct_interactive": True, "is_dormant_reactivated": False}]
        ctx2.ueba = []

        ctx3 = EnrichmentContext(rule_level=8)
        ctx3.ti = []
        ctx3.asset = []
        ctx3.user = []
        ctx3.ueba = [{"subject_type": "user", "subject_id": "user-x", "z_score": 5.0, "anomaly_type": "outlier"}]

        mock_alerts = [MagicMock(), MagicMock(), MagicMock()]

        few_shot = [{"technique": "T1486", "verdict": "ransomware"}]
        related = [{"incident_id": "inc-010", "severity": "critical"}]

        with patch(
            "shared.orchestrator.enrichment._alerts_for_incident",
            return_value=mock_alerts,
        ):
            with patch(
                "shared.orchestrator.enrichment.enrich_alert",
                side_effect=[ctx1, ctx2, ctx3],
            ):
                with patch(
                    "shared.orchestrator.enrichment._enrich_few_shot",
                    return_value=few_shot,
                ):
                    with patch(
                        "shared.orchestrator.enrichment._enrich_related_incidents",
                        return_value=related,
                    ):
                        pack = await enrich_incident(mock_session, incident)

        assert pack.enriched_at is not None
        assert len(pack.threat_intel) == 2  # two distinct IOCs
        assert len(pack.asset_criticality) == 2  # two distinct agents
        assert len(pack.user_risk) == 2  # two distinct users
        assert len(pack.ueba_anomalies) == 2  # agent-01 + user-x (2 distinct)
        assert pack.few_shot_examples == few_shot
        assert pack.related_incidents == related

        # Verify to_dict()
        d = pack.to_dict()
        assert "threat_intel" in d
        assert "asset_criticality" in d
        assert "user_risk" in d
        assert "ueba_anomalies" in d
        assert "few_shot_examples" in d
        assert "related_incidents" in d
        assert "enriched_at" in d
