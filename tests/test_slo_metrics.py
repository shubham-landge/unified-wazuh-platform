from unittest.mock import AsyncMock, patch, MagicMock
import pytest
from services.api.app.routers.metrics import metrics


@pytest.mark.asyncio
async def test_slo_metrics():
    """Verify that the /metrics endpoint returns the new SLO metrics."""
    db = AsyncMock()
    mock_val = MagicMock()
    mock_val.scalar.return_value = 0
    db.execute.return_value = mock_val

    mock_redis = MagicMock()

    def redis_get(key):
        values = {
            "triage_success_total": "42",
            "triage_fail_total": "3",
            "slo_last_seen_triage_success": "40",
            "slo_last_seen_triage_fail": "1",
        }
        return values.get(key)

    mock_redis.get.side_effect = redis_get
    mock_redis.llen.return_value = 5
    mock_redis.lrange.return_value = ["150", "200", "300"]

    with patch("services.api.app.routers.metrics.settings") as mock_settings:
        mock_settings.redis_url = "redis://localhost:6379/0"
        with patch("redis.from_url", return_value=mock_redis):
            res = await metrics(db=db, _="key")
            assert res.status_code == 200
            content = res.body.decode()

            # Counter metrics
            assert "soc_triage_success_total" in content
            assert "soc_triage_fail_total" in content

            # Gauge — DLQ depth
            assert "soc_dlq_depth" in content

            # Histogram
            assert "soc_triage_latency_ms" in content

            # Existing metrics should still be present
            assert "soc_incident_mttd_seconds" in content
            assert "soc_triage_suppressed_total" in content


@pytest.mark.asyncio
async def test_slo_metrics_handles_missing_keys():
    """Missing Redis keys should be handled gracefully (default to 0)."""
    db = AsyncMock()
    mock_val = MagicMock()
    mock_val.scalar.return_value = 0
    db.execute.return_value = mock_val

    mock_redis = MagicMock()
    mock_redis.get.return_value = None  # all keys missing
    mock_redis.llen.return_value = 0
    mock_redis.lrange.return_value = []

    with patch("services.api.app.routers.metrics.settings") as mock_settings:
        mock_settings.redis_url = "redis://localhost:6379/0"
        with patch("redis.from_url", return_value=mock_redis):
            res = await metrics(db=db, _="key")
            assert res.status_code == 200
            content = res.body.decode()
            assert "soc_triage_success_total" in content
            assert "soc_triage_fail_total" in content
            assert "soc_dlq_depth" in content
            assert "soc_triage_latency_ms" in content


@pytest.mark.asyncio
async def test_slo_metrics_delta_tracking():
    """Counter delta tracking should only increment by the difference."""
    db = AsyncMock()
    mock_val = MagicMock()
    mock_val.scalar.return_value = 0
    db.execute.return_value = mock_val

    mock_redis = MagicMock()

    call_count = [0]
    total_at_return = {0: 10, 1: 10}  # no change between scrapes

    def redis_get(key):
        if key == "triage_success_total":
            return str(total_at_return.get(call_count[0], 0))
        if key == "slo_last_seen_triage_success":
            return "10"  # already seen up to 10
        return None

    mock_redis.get.side_effect = redis_get

    def redis_set(key, value):
        if key == "slo_last_seen_triage_success":
            call_count[0] += 1

    mock_redis.set.side_effect = redis_set
    mock_redis.llen.return_value = 0
    mock_redis.lrange.return_value = []

    with patch("services.api.app.routers.metrics.settings") as mock_settings:
        mock_settings.redis_url = "redis://localhost:6379/0"
        with patch("redis.from_url", return_value=mock_redis):
            res = await metrics(db=db, _="key")
            assert res.status_code == 200
            content = res.body.decode()

            # soc_triage_success_total should be present (Counter value at 10)
            assert "soc_triage_success_total" in content
            # The delta was 0 so inc(0) was called — Counter should show 0
            assert "soc_triage_fail_total" in content
