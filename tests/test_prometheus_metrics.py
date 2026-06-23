"""Tests for shared/metrics.py — Prometheus metric writers.

Verifies that the Redis-backed metric helpers correctly write the keys
that the API /metrics endpoint reads on scrape.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from shared.metrics import (
    record_triage_success,
    record_triage_fail,
    record_triage_latency,
    push_to_dlq,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def redis_mock():
    """Return an AsyncMock suitable for use as a redis.asyncio.Redis stand-in."""
    return AsyncMock()


# ── record_triage_success ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_record_triage_success(redis_mock):
    await record_triage_success(redis_mock)
    redis_mock.incr.assert_called_once_with("triage_success_total")


@pytest.mark.asyncio
async def test_record_triage_success_redis_error(redis_mock):
    """Redis errors must be swallowed — metrics are best-effort."""
    redis_mock.incr.side_effect = ConnectionError("redis down")
    # Should not raise
    await record_triage_success(redis_mock)
    redis_mock.incr.assert_called_once_with("triage_success_total")


# ── record_triage_fail ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_record_triage_fail(redis_mock):
    await record_triage_fail(redis_mock)
    redis_mock.incr.assert_called_once_with("triage_fail_total")


@pytest.mark.asyncio
async def test_record_triage_fail_redis_error(redis_mock):
    redis_mock.incr.side_effect = ConnectionError("redis down")
    await record_triage_fail(redis_mock)
    redis_mock.incr.assert_called_once_with("triage_fail_total")


# ── record_triage_latency ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_record_triage_latency(redis_mock):
    await record_triage_latency(redis_mock, 245.0)
    redis_mock.lpush.assert_called_once_with("triage_latency_samples", "245.0")
    redis_mock.ltrim.assert_called_once_with("triage_latency_samples", 0, 999)


@pytest.mark.asyncio
async def test_record_triage_latency_none_skipped(redis_mock):
    """latency_ms=None must be a no-op — no Redis calls."""
    await record_triage_latency(redis_mock, None)
    redis_mock.lpush.assert_not_called()
    redis_mock.ltrim.assert_not_called()


@pytest.mark.asyncio
async def test_record_triage_latency_zero(redis_mock):
    """latency_ms=0 is a valid sample (cache hit / fast path)."""
    await record_triage_latency(redis_mock, 0)
    redis_mock.lpush.assert_called_once_with("triage_latency_samples", "0")


@pytest.mark.asyncio
async def test_record_triage_latency_redis_error(redis_mock):
    redis_mock.lpush.side_effect = ConnectionError("redis down")
    await record_triage_latency(redis_mock, 100.0)
    redis_mock.lpush.assert_called_once()


# ── push_to_dlq ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_push_to_dlq(redis_mock):
    await push_to_dlq(redis_mock, "alert-123", "timeout")
    redis_mock.lpush.assert_called_once()
    call_args = redis_mock.lpush.call_args
    assert call_args[0][0] == "triage_dlq"
    payload = json.loads(call_args[0][1])
    assert payload == {"alert_id": "alert-123", "error": "timeout"}


@pytest.mark.asyncio
async def test_push_to_dlq_error_handling(redis_mock):
    redis_mock.lpush.side_effect = ConnectionError("redis down")
    await push_to_dlq(redis_mock, "alert-456", "boom")
    redis_mock.lpush.assert_called_once()


# ── Multiple calls ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_multiple_success_calls_increment(redis_mock):
    """Each call should result in one incr of the same key."""
    await record_triage_success(redis_mock)
    await record_triage_success(redis_mock)
    await record_triage_success(redis_mock)
    assert redis_mock.incr.call_count == 3
    redis_mock.incr.assert_has_calls([call("triage_success_total")] * 3)


@pytest.mark.asyncio
async def test_multiple_latency_samples_stack(redis_mock):
    await record_triage_latency(redis_mock, 100)
    await record_triage_latency(redis_mock, 200)
    await record_triage_latency(redis_mock, 300)
    assert redis_mock.lpush.call_count == 3
    # ltrim should also be called 3 times to cap the list
    assert redis_mock.ltrim.call_count == 3


# ── Integration: triage worker calls metrics helpers ───────────────────────────


class TestTriageWorkerMetricsIntegration:
    """Verify triage_worker.process_message writes metrics on success and failure."""

    @pytest.mark.asyncio
    async def test_process_message_writes_success_metrics(self):
        """A successful triage should call record_triage_success + record_triage_latency."""
        from services.worker.app.triage_worker import TriageWorker

        worker = TriageWorker()
        worker.redis_client = AsyncMock()
        worker.engine = AsyncMock()
        worker.session_factory = MagicMock()

        # Mock session
        session = AsyncMock()
        worker.session_factory.return_value.__aenter__.return_value = session

        # Mock alert query
        alert = MagicMock()
        alert.id = "alert-001"
        alert.rule_description = "Test rule"
        alert.rule_id = 1001
        alert.rule_level = 8
        alert.rule_groups = ["test"]
        alert.agent_name = "agent-1"
        alert.agent_ip = "10.0.0.1"
        alert.source_ip = "192.168.1.1"
        alert.user_name = "testuser"
        alert.process_name = "testproc"
        alert.mitre_tactic = "Execution"
        alert.mitre_technique = "T1059"
        alert.tenant_id = "tenant-1"
        alert.status = "open"

        result = MagicMock()
        result.scalar_one_or_none.return_value = alert
        session.execute.return_value = result

        # Mock LLM provider
        result_data = {
            "success": True,
            "latency_ms": 345.0,
            "summary": "Test summary",
            "category": "malicious",
            "severity": "high",
            "confidence": 0.9,
            "false_positive_likelihood": 0.1,
            "escalation_required": False,
        }

        # Patch everything the process_message method depends on
        with patch(
            "shared.enrichment.pipeline.enrich_alert",
            new_callable=AsyncMock,
        ) as mock_enrich, patch(
            "shared.enrichment.risk_score.compute_risk_score",
            return_value=25,
        ), patch(
            "shared.enrichment.decision.decide",
        ) as mock_decide, patch(
            "shared.connectors.llm_router.TieredRouter.get_provider",
            new_callable=AsyncMock,
        ) as mock_get_provider, patch(
            "services.worker.app.triage_worker.noise_reduction.evaluate",
            new_callable=AsyncMock,
        ) as mock_noise, patch(
            "services.worker.app.triage_worker.record_triage_success",
            new_callable=AsyncMock,
        ) as mock_success, patch(
            "services.worker.app.triage_worker.record_triage_fail",
            new_callable=AsyncMock,
        ) as mock_fail, patch(
            "services.worker.app.triage_worker.record_triage_latency",
            new_callable=AsyncMock,
        ) as mock_latency:

            from shared.enrichment.decision import Decision, DecisionLevel
            from shared.enrichment.risk_score import EnrichmentContext

            mock_decide.return_value = Decision(
                level=DecisionLevel.L2_TRIAGE,
                score=25,
                reason="test",
                skip_llm=False,
                fast_llm_only=False,
                auto_verdict="malicious",
            )
            mock_enrich.return_value = EnrichmentContext(rule_level=8)
            mock_noise.return_value = MagicMock(should_triage=True, incident=None, action=None, force_fast_tier=False)

            provider_mock = MagicMock()
            provider_mock.name.return_value = "ollama/qwen"
            provider_mock.analyze = AsyncMock(return_value=result_data)
            mock_get_provider.return_value = provider_mock

            with patch(
                "services.worker.app.triage_worker.validate_triage_output",
                return_value=result_data,
            ), patch(
                "services.worker.app.triage_worker.settings", create=True,
                triage_cache_enabled=False,
                triage_cache_ttl_seconds=1800,
                incident_risk_enabled=False,
                automation_mode="shadow",
            ):
                msg = {"alert_id": "alert-001"}
                await worker.process_message(msg)

            # Metrics helpers must have been called with the redis client
            mock_success.assert_called_once_with(worker.redis_client)
            mock_latency.assert_called_once_with(worker.redis_client, 345.0)
            mock_fail.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_message_exception_writes_fail_metric(self):
        """An exception during triage must call record_triage_fail."""
        from services.worker.app.triage_worker import TriageWorker

        worker = TriageWorker()
        worker.redis_client = AsyncMock()
        worker.engine = AsyncMock()
        worker.session_factory = MagicMock()

        session = AsyncMock()
        worker.session_factory.return_value.__aenter__.return_value = session

        alert = MagicMock()
        alert.id = "alert-002"
        alert.rule_description = "Test rule"
        alert.rule_id = 1001
        alert.rule_level = 8
        alert.rule_groups = ["test"]
        alert.agent_name = "agent-1"
        alert.agent_ip = "10.0.0.1"
        alert.source_ip = "192.168.1.1"
        alert.user_name = "testuser"
        alert.process_name = "testproc"
        alert.mitre_tactic = "Execution"
        alert.mitre_technique = "T1059"
        alert.tenant_id = "tenant-1"
        alert.status = "open"

        result = MagicMock()
        result.scalar_one_or_none.return_value = alert
        session.execute.return_value = result

        with patch(
            "shared.enrichment.pipeline.enrich_alert",
            new_callable=AsyncMock,
        ) as mock_enrich, patch(
            "shared.enrichment.risk_score.compute_risk_score",
            side_effect=RuntimeError("enrichment failure"),
        ), patch(
            "services.worker.app.triage_worker.noise_reduction.evaluate",
            new_callable=AsyncMock,
        ) as mock_noise, patch(
            "services.worker.app.triage_worker.record_triage_fail",
            new_callable=AsyncMock,
        ) as mock_fail, patch(
            "services.worker.app.triage_worker.record_triage_success",
            new_callable=AsyncMock,
        ) as mock_success:
            from shared.enrichment.risk_score import EnrichmentContext

            mock_enrich.return_value = EnrichmentContext(rule_level=8)
            mock_noise.return_value = MagicMock(should_triage=True, incident=None, action=None, force_fast_tier=False)

            with patch("services.worker.app.triage_worker.settings", create=True):
                msg = {"alert_id": "alert-002"}
                await worker.process_message(msg)

            mock_fail.assert_called_once_with(worker.redis_client)
            mock_success.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_message_failed_triage_writes_fail_metric(self):
        """When LLM returns success=False, record_triage_fail is called."""
        from services.worker.app.triage_worker import TriageWorker

        worker = TriageWorker()
        worker.redis_client = AsyncMock()
        worker.engine = AsyncMock()
        worker.session_factory = MagicMock()

        session = AsyncMock()
        worker.session_factory.return_value.__aenter__.return_value = session

        alert = MagicMock()
        alert.id = "alert-003"
        alert.rule_description = "Test rule"
        alert.rule_id = 1001
        alert.rule_level = 8
        alert.rule_groups = ["test"]
        alert.agent_name = "agent-1"
        alert.agent_ip = "10.0.0.1"
        alert.source_ip = "192.168.1.1"
        alert.user_name = "testuser"
        alert.process_name = "testproc"
        alert.mitre_tactic = "Execution"
        alert.mitre_technique = "T1059"
        alert.tenant_id = "tenant-1"
        alert.status = "open"

        result = MagicMock()
        result.scalar_one_or_none.return_value = alert
        session.execute.return_value = result

        # LLM returns success=False
        result_data = {
            "success": False,
            "latency_ms": 5000.0,
            "summary": "Failed triage",
            "category": "unknown",
            "severity": "medium",
            "confidence": 0.3,
            "false_positive_likelihood": 0.5,
            "escalation_required": False,
        }

        with patch(
            "shared.enrichment.pipeline.enrich_alert",
            new_callable=AsyncMock,
        ) as mock_enrich, patch(
            "shared.enrichment.risk_score.compute_risk_score",
            return_value=15,
        ), patch(
            "shared.enrichment.decision.decide",
        ) as mock_decide, patch(
            "shared.connectors.llm_router.TieredRouter.get_provider",
            new_callable=AsyncMock,
        ) as mock_get_provider, patch(
            "services.worker.app.triage_worker.noise_reduction.evaluate",
            new_callable=AsyncMock,
        ) as mock_noise, patch(
            "services.worker.app.triage_worker.record_triage_fail",
            new_callable=AsyncMock,
        ) as mock_fail, patch(
            "services.worker.app.triage_worker.record_triage_success",
            new_callable=AsyncMock,
        ) as mock_success, patch(
            "services.worker.app.triage_worker.record_triage_latency",
            new_callable=AsyncMock,
        ) as mock_latency:

            from shared.enrichment.decision import Decision, DecisionLevel
            from shared.enrichment.risk_score import EnrichmentContext

            mock_decide.return_value = Decision(
                level=DecisionLevel.L2_TRIAGE,
                score=15,
                reason="test",
                skip_llm=False,
                fast_llm_only=False,
                auto_verdict="benign",
            )
            mock_enrich.return_value = EnrichmentContext(rule_level=8)
            mock_noise.return_value = MagicMock(should_triage=True, incident=None, action=None, force_fast_tier=False)

            provider_mock = MagicMock()
            provider_mock.name.return_value = "ollama/qwen"
            provider_mock.analyze = AsyncMock(return_value=result_data)
            mock_get_provider.return_value = provider_mock

            with patch(
                "services.worker.app.triage_worker.validate_triage_output",
                return_value=result_data,
            ), patch(
                "services.worker.app.triage_worker.settings", create=True,
                triage_cache_enabled=False,
                triage_cache_ttl_seconds=1800,
                incident_risk_enabled=False,
                automation_mode="shadow",
            ):
                msg = {"alert_id": "alert-003"}
                await worker.process_message(msg)

            # Failed triage: fail counter called, success not called
            mock_fail.assert_called_once_with(worker.redis_client)
            mock_success.assert_not_called()
            # Latency is still recorded even for failures
            mock_latency.assert_called_once_with(worker.redis_client, 5000.0)
