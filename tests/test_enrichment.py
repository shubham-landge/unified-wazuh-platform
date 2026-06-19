"""Tests for shared/enrichment/ package — pipeline, risk_score, decision, and stubs."""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_alert(**overrides):
    """Build a minimal Alert with sensible defaults for enrichment testing."""
    from shared.models.alert import Alert
    import uuid
    a = Alert(
        id=uuid.uuid4(),
        rule_id=1002,
        rule_description="Test alert",
        rule_level=10,
        source_ip="192.168.1.100",
        destination_ip="10.0.0.5",
        user_name="alice@example.com",
        agent_id="007",
        agent_name="web-server-01",
        file_hash="abc123",
    )
    for k, v in overrides.items():
        setattr(a, k, v)
    return a


# ---------------------------------------------------------------------------
# EnrichmentResult
# ---------------------------------------------------------------------------

class TestEnrichmentResult:
    def test_defaults_empty(self):
        from shared.enrichment.pipeline import EnrichmentResult
        r = EnrichmentResult()
        assert r.ti == []
        assert r.asset == []
        assert r.user == []
        assert r.ueba == []
        assert r.enriched is False

    def test_to_dict(self):
        from shared.enrichment.pipeline import EnrichmentResult
        r = EnrichmentResult(
            ti=[{"ioc": "1.2.3.4"}],
            asset=[{"agent_id": "007"}],
            errors=["ti: timeout"],
            enriched=True,
        )
        d = r.to_dict()
        assert len(d["ti"]) == 1
        assert len(d["errors"]) == 1
        assert d["enriched"] is True


# ---------------------------------------------------------------------------
# Pipeline — enrich_alert
# ---------------------------------------------------------------------------

class TestEnrichAlert:
    async def test_kill_switch_returns_empty(self):
        from shared.enrichment.pipeline import enrich_alert
        with patch("shared.enrichment.pipeline.settings") as mock_settings:
            mock_settings.enrichment_kill_switch = True
            result = await enrich_alert(AsyncMock(), _make_alert())
        assert result.enriched is False
        assert result.ti == []
        assert result.errors == []

    async def test_all_enrichers_invoked(self):
        from shared.enrichment.pipeline import enrich_alert
        alert = _make_alert()
        session = AsyncMock()

        with patch("shared.enrichment.pipeline.settings") as mock_settings:
            mock_settings.enrichment_kill_switch = False
            mock_settings.enrichment_timeout_seconds = 10
            mock_settings.enricher_geoip_enabled = True
            mock_settings.enricher_vuln_correlate_enabled = True
            mock_settings.enricher_watchlists_enabled = True

            with patch("shared.enrichment.pipeline._enrich_ti", new_callable=AsyncMock) as m_ti, \
                 patch("shared.enrichment.pipeline._enrich_asset", new_callable=AsyncMock) as m_asset, \
                 patch("shared.enrichment.pipeline._enrich_user", new_callable=AsyncMock) as m_user, \
                 patch("shared.enrichment.pipeline._enrich_ueba", new_callable=AsyncMock) as m_ueba, \
                 patch("shared.enrichment.pipeline._enrich_geoip", new_callable=AsyncMock) as m_geoip, \
                 patch("shared.enrichment.pipeline._enrich_vuln", new_callable=AsyncMock) as m_vuln, \
                 patch("shared.enrichment.pipeline._enrich_watchlists", new_callable=AsyncMock) as m_wl:
                m_ti.return_value = [{"ioc": "1.2.3.4", "type": "ip"}]
                m_asset.return_value = [{"agent_id": "007"}]
                m_user.return_value = [{"email": "alice@example.com"}]
                m_ueba.return_value = [{"anomaly_type": "test"}]
                m_geoip.return_value = {"country": "US"}
                m_vuln.return_value = [{"cve": "CVE-2024-0001"}]
                m_wl.return_value = [{"list": "blocklist"}]

                result = await enrich_alert(session, alert)

        assert result.enriched is True
        assert len(result.ti) == 1
        assert len(result.asset) == 1
        assert len(result.user) == 1
        assert result.geoip == {"country": "US"}
        assert len(result.vuln) == 1
        assert len(result.watchlist) == 1
        m_ti.assert_awaited_once()
        m_geoip.assert_awaited_once()

    async def test_timeout_graceful_degradation(self):
        from shared.enrichment.pipeline import enrich_alert
        alert = _make_alert()
        session = AsyncMock()

        async def slow_ti(*args, **kwargs):
            await asyncio.sleep(999)
            return []

        with patch("shared.enrichment.pipeline.settings") as mock_settings:
            mock_settings.enrichment_kill_switch = False
            mock_settings.enrichment_timeout_seconds = 1
            mock_settings.enricher_geoip_enabled = False
            mock_settings.enricher_vuln_correlate_enabled = False
            mock_settings.enricher_watchlists_enabled = False

            with patch("shared.enrichment.pipeline._enrich_ti", new=slow_ti), \
                 patch("shared.enrichment.pipeline._enrich_asset", new_callable=AsyncMock) as m_asset, \
                 patch("shared.enrichment.pipeline._enrich_user", new_callable=AsyncMock) as m_user, \
                 patch("shared.enrichment.pipeline._enrich_ueba", new_callable=AsyncMock) as m_ueba:
                m_asset.return_value = [{"agent_id": "007"}]
                m_user.return_value = [{"email": "alice@example.com"}]
                m_ueba.return_value = []

                result = await enrich_alert(session, alert)

        # TI timed out — others completed.
        assert result.enriched is True
        assert len(result.asset) == 1
        assert len(result.user) == 1
        # TI contributed nothing due to timeout.
        assert result.ti == []

    async def test_enricher_exception_captured(self):
        from shared.enrichment.pipeline import enrich_alert
        alert = _make_alert()
        session = AsyncMock()

        async def broken_ti(*args, **kwargs):
            raise RuntimeError("TI service unavailable")

        with patch("shared.enrichment.pipeline.settings") as mock_settings:
            mock_settings.enrichment_kill_switch = False
            mock_settings.enrichment_timeout_seconds = 10
            mock_settings.enricher_geoip_enabled = False
            mock_settings.enricher_vuln_correlate_enabled = False
            mock_settings.enricher_watchlists_enabled = False

            with patch("shared.enrichment.pipeline._enrich_ti", new=broken_ti), \
                 patch("shared.enrichment.pipeline._enrich_asset", new_callable=AsyncMock) as m_asset, \
                 patch("shared.enrichment.pipeline._enrich_user", new_callable=AsyncMock) as m_user, \
                 patch("shared.enrichment.pipeline._enrich_ueba", new_callable=AsyncMock) as m_ueba:
                m_asset.return_value = []
                m_user.return_value = []
                m_ueba.return_value = []

                result = await enrich_alert(session, alert)

        # Should not raise — fail-open.
        assert result.enriched is True
        assert result.ti == []

    async def test_optional_enrichers_disabled_by_default(self):
        from shared.enrichment.pipeline import enrich_alert
        alert = _make_alert()
        session = AsyncMock()

        with patch("shared.enrichment.pipeline.settings") as mock_settings:
            mock_settings.enrichment_kill_switch = False
            mock_settings.enrichment_timeout_seconds = 10
            mock_settings.enricher_geoip_enabled = False
            mock_settings.enricher_vuln_correlate_enabled = False
            mock_settings.enricher_watchlists_enabled = False

            with patch("shared.enrichment.pipeline._enrich_ti", new_callable=AsyncMock) as m_ti, \
                 patch("shared.enrichment.pipeline._enrich_asset", new_callable=AsyncMock) as m_a, \
                 patch("shared.enrichment.pipeline._enrich_user", new_callable=AsyncMock) as m_u, \
                 patch("shared.enrichment.pipeline._enrich_ueba", new_callable=AsyncMock) as m_ue, \
                 patch("shared.enrichment.pipeline._enrich_geoip", new_callable=AsyncMock) as m_geo, \
                 patch("shared.enrichment.pipeline._enrich_vuln", new_callable=AsyncMock) as m_vuln, \
                 patch("shared.enrichment.pipeline._enrich_watchlists", new_callable=AsyncMock) as m_wl:
                m_ti.return_value = []
                m_a.return_value = []
                m_u.return_value = []
                m_ue.return_value = []
                m_geo.return_value = None
                m_vuln.return_value = []
                m_wl.return_value = []

                await enrich_alert(session, alert)

        # Optional enrichers should NOT be called when disabled.
        m_geo.assert_not_awaited()
        m_vuln.assert_not_awaited()
        m_wl.assert_not_awaited()

    async def test_empty_alert_produces_empty_enrichment(self):
        from shared.enrichment.pipeline import enrich_alert
        alert = _make_alert(source_ip=None, user_name=None, agent_id=None, file_hash=None,
                            destination_ip=None)
        session = AsyncMock()

        with patch("shared.enrichment.pipeline.settings") as mock_settings:
            mock_settings.enrichment_kill_switch = False
            mock_settings.enrichment_timeout_seconds = 10
            mock_settings.enricher_geoip_enabled = False
            mock_settings.enricher_vuln_correlate_enabled = False
            mock_settings.enricher_watchlists_enabled = False

            result = await enrich_alert(session, alert)

        assert result.enriched is True
        assert result.ti == []
        assert result.asset == []
        assert result.user == []
        assert result.ueba == []


# ---------------------------------------------------------------------------
# Risk Score
# ---------------------------------------------------------------------------

class TestComputeRiskScore:
    def test_empty_enrichment_low_score(self):
        from shared.enrichment.pipeline import EnrichmentResult
        from shared.enrichment.risk_score import compute_risk_score
        alert = _make_alert()
        enrichment = EnrichmentResult()
        result = compute_risk_score(alert, enrichment)
        assert 0 <= result["score"] <= 100
        assert "breakdown" in result
        assert "rule_level" in result["breakdown"]

    def test_high_alert_with_anomalies(self):
        from shared.enrichment.pipeline import EnrichmentResult
        from shared.enrichment.risk_score import compute_risk_score
        alert = _make_alert(rule_level=14)
        enrichment = EnrichmentResult(
            ti=[{"ioc": "1.2.3.4", "found": True, "malware_families": ["Emotet"]}],
            ueba=[{"zscore": 5.5}, {"zscore": 3.2}],
            asset=[{"criticality": 8}],
        )
        result = compute_risk_score(alert, enrichment)
        assert result["score"] > 40
        assert result["breakdown"]["ti"]["contribution"] > 0
        assert result["breakdown"]["ueba"]["contribution"] > 0

    def test_score_capped_at_100(self):
        from shared.enrichment.pipeline import EnrichmentResult
        from shared.enrichment.risk_score import compute_risk_score
        alert = _make_alert(rule_level=15)
        enrichment = EnrichmentResult(
            ti=[{"ioc": f"10.0.0.{i}", "malware_families": ["Malware"]} for i in range(10)],
            ueba=[{"zscore": 6.0} for _ in range(5)],
            asset=[{"criticality": 10}],
            user=[{"is_active": False}],
        )
        result = compute_risk_score(alert, enrichment)
        assert result["score"] <= 100

    def test_weights_from_config(self):
        from shared.enrichment.pipeline import EnrichmentResult
        from shared.enrichment.risk_score import compute_risk_score
        alert = _make_alert(rule_level=10)
        enrichment = EnrichmentResult(
            ti=[{"ioc": "1.2.3.4", "malware_families": ["Trojan"]}],
        )

        with patch("shared.enrichment.risk_score.settings") as mock_settings:
            mock_settings.enrichment_risk_weight_ti = 50.0
            mock_settings.enrichment_risk_weight_asset = 0.0
            mock_settings.enrichment_risk_weight_user = 0.0
            mock_settings.enrichment_risk_weight_ueba = 0.0
            mock_settings.enrichment_risk_weight_rule_level = 0.0

            result = compute_risk_score(alert, enrichment)

        # One TI hit with malware_families → raw=5+5=10, contribution=(10/25)*50=20
        assert result["breakdown"]["ti"]["weight"] == 50.0
        assert result["breakdown"]["ti"]["contribution"] == 20.0

    def test_unknown_user_adds_risk(self):
        from shared.enrichment.pipeline import EnrichmentResult
        from shared.enrichment.risk_score import compute_risk_score
        alert = _make_alert(rule_level=5)
        # No user enrichment → unknown user penalty.
        enrichment = EnrichmentResult(user=[])
        result = compute_risk_score(alert, enrichment)
        assert result["breakdown"]["user"]["raw"] == 5.0  # unknown user = moderate

    def test_inactive_user_adds_risk(self):
        from shared.enrichment.pipeline import EnrichmentResult
        from shared.enrichment.risk_score import compute_risk_score
        alert = _make_alert(rule_level=5)
        enrichment = EnrichmentResult(
            user=[{"email": "alice@example.com", "is_active": False}]
        )
        result = compute_risk_score(alert, enrichment)
        assert result["breakdown"]["user"]["raw"] == 10.0

    def test_known_active_user_low_risk(self):
        from shared.enrichment.pipeline import EnrichmentResult
        from shared.enrichment.risk_score import compute_risk_score
        alert = _make_alert(rule_level=5)
        enrichment = EnrichmentResult(
            user=[{"email": "alice@example.com", "is_active": True, "last_login": "2024-01-01T00:00:00"}]
        )
        result = compute_risk_score(alert, enrichment)
        assert result["breakdown"]["user"]["raw"] == 2.0


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------

class TestDecide:
    def test_score_85_is_L4(self):
        from shared.enrichment.pipeline import EnrichmentResult
        from shared.enrichment.decision import decide, DecisionLevel
        decision = decide(85, _make_alert(), EnrichmentResult())
        assert decision.level == DecisionLevel.L4_CRITICAL

    def test_score_70_is_L3(self):
        from shared.enrichment.pipeline import EnrichmentResult
        from shared.enrichment.decision import decide, DecisionLevel
        decision = decide(70, _make_alert(), EnrichmentResult())
        assert decision.level == DecisionLevel.L3_HIGH

    def test_score_50_is_L2(self):
        from shared.enrichment.pipeline import EnrichmentResult
        from shared.enrichment.decision import decide, DecisionLevel
        decision = decide(50, _make_alert(), EnrichmentResult())
        assert decision.level == DecisionLevel.L2_MEDIUM

    def test_score_30_is_L1(self):
        from shared.enrichment.pipeline import EnrichmentResult
        from shared.enrichment.decision import decide, DecisionLevel
        decision = decide(30, _make_alert(), EnrichmentResult())
        assert decision.level == DecisionLevel.L1_LOW

    def test_score_5_is_L0(self):
        from shared.enrichment.pipeline import EnrichmentResult
        from shared.enrichment.decision import decide, DecisionLevel
        decision = decide(5, _make_alert(), EnrichmentResult())
        assert decision.level == DecisionLevel.L0_BENIGN

    def test_boundaries(self):
        from shared.enrichment.pipeline import EnrichmentResult
        from shared.enrichment.decision import decide, DecisionLevel
        alert = _make_alert()
        enrichment = EnrichmentResult()
        assert decide(100, alert, enrichment).level == DecisionLevel.L4_CRITICAL
        assert decide(81, alert, enrichment).level == DecisionLevel.L4_CRITICAL
        assert decide(80, alert, enrichment).level == DecisionLevel.L3_HIGH
        assert decide(61, alert, enrichment).level == DecisionLevel.L3_HIGH
        assert decide(60, alert, enrichment).level == DecisionLevel.L2_MEDIUM
        assert decide(41, alert, enrichment).level == DecisionLevel.L2_MEDIUM
        assert decide(40, alert, enrichment).level == DecisionLevel.L1_LOW
        assert decide(21, alert, enrichment).level == DecisionLevel.L1_LOW
        assert decide(20, alert, enrichment).level == DecisionLevel.L0_BENIGN
        assert decide(0, alert, enrichment).level == DecisionLevel.L0_BENIGN

    def test_shadow_mode_not_enforced(self):
        from shared.enrichment.pipeline import EnrichmentResult
        from shared.enrichment.decision import decide
        alert = _make_alert()

        with patch("shared.enrichment.decision.settings") as mock_settings:
            mock_settings.enrichment_kill_switch = False
            mock_settings.enrichment_decision_shadow_mode = True
            decision = decide(90, alert, EnrichmentResult())

        assert decision.enforced is False
        assert "shadow mode" in decision.reason.lower()

    def test_non_shadow_mode_enforced(self):
        from shared.enrichment.pipeline import EnrichmentResult
        from shared.enrichment.decision import decide
        alert = _make_alert()

        with patch("shared.enrichment.decision.settings") as mock_settings:
            mock_settings.enrichment_kill_switch = False
            mock_settings.enrichment_decision_shadow_mode = False
            decision = decide(90, alert, EnrichmentResult())

        assert decision.enforced is True

    def test_global_kill_switch_overrides(self):
        from shared.enrichment.pipeline import EnrichmentResult
        from shared.enrichment.decision import decide, DecisionLevel
        alert = _make_alert()

        with patch("shared.enrichment.decision.settings") as mock_settings:
            mock_settings.enrichment_kill_switch = True
            mock_settings.enrichment_decision_shadow_mode = False
            decision = decide(90, alert, EnrichmentResult())

        assert decision.level == DecisionLevel.L0_BENIGN
        assert decision.enforced is False
        assert "kill switch" in decision.reason.lower()


# ---------------------------------------------------------------------------
# Stubs — graceful degradation
# ---------------------------------------------------------------------------

class TestGeoIPStub:
    async def test_returns_none(self):
        from shared.enrichment.geoip import lookup
        result = await lookup("1.2.3.4")
        assert result is None

    async def test_never_raises(self):
        from shared.enrichment.geoip import lookup
        result = await lookup("")
        assert result is None


class TestVulnCorrelateStub:
    async def test_returns_empty_list(self):
        from shared.enrichment.vuln_correlate import correlate
        alert = _make_alert()
        result = await correlate(AsyncMock(), alert)
        assert result == []

    async def test_never_raises(self):
        from shared.enrichment.vuln_correlate import correlate
        result = await correlate(AsyncMock(), _make_alert(agent_id=None))
        assert result == []


class TestWatchlistsStub:
    async def test_returns_empty_list(self):
        from shared.enrichment.watchlists import check
        alert = _make_alert()
        result = await check(AsyncMock(), alert)
        assert result == []

    async def test_never_raises(self):
        from shared.enrichment.watchlists import check
        result = await check(AsyncMock(), _make_alert())
        assert result == []
