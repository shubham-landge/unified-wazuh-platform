"""Tests for the ARQ durable queue job functions.

Validates that each job function delegates to the correct underlying worker,
that retry semantics are respected via arq's max_tries, and that the
WorkerSettings class exposes the expected configuration.
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.worker.app.arq_app import (
    WorkerSettings,
    enrich_job,
    reaper_cron,
    sigma_job,
    ti_enrich_job,
    triage_job,
)


# ── Fixtures ───────────────────────────────────────────────────────────────

@pytest.fixture
def fake_ctx():
    """Minimal arq WorkerContext stand-in."""
    return MagicMock()


# ── triage_job ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
@patch("services.worker.app.arq_app._get_redis")
@patch("services.worker.app.arq_app._get_engine")
async def test_triage_job_calls_process_message(
    mock_get_engine, mock_get_redis, fake_ctx,
):
    """triage_job builds a TriageWorker, sets up resources, and delegates."""
    alert_id = str(uuid.uuid4())

    mock_worker = AsyncMock()
    mock_worker.engine = MagicMock()
    mock_worker.process_message = AsyncMock()

    # Patch the *source* module of the lazy import inside the job function
    with patch(
        "services.worker.app.triage_worker.TriageWorker", return_value=mock_worker
    ) as MockTriageWorker:
        result = await triage_job(fake_ctx, alert_id, manual=True)

    MockTriageWorker.assert_called_once()
    mock_worker.process_message.assert_awaited_once_with(
        {"alert_id": alert_id, "manual": True}
    )
    assert result == {"alert_id": alert_id, "status": "triage_completed"}


# ── enrich_job ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
@patch("services.worker.app.arq_app._get_redis")
@patch("services.worker.app.arq_app._get_engine")
async def test_enrich_job_calls_enrich_alert(
    mock_get_engine, mock_get_redis, fake_ctx,
):
    """enrich_job loads the alert and delegates to enrich_alert."""
    alert_id = str(uuid.uuid4())
    mock_alert = MagicMock()
    mock_alert.id = alert_id
    mock_alert.tenant_id = uuid.uuid4()

    # Build a session that works with `await session.execute(...)` —
    # we use an AsyncMock for execute since the result is awaited.
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_alert

    mock_session = MagicMock()
    mock_session.execute = AsyncMock(return_value=mock_result)
    mock_session.__aenter__.return_value = mock_session
    mock_session.__aexit__.return_value = None

    mock_enrich_result = MagicMock()
    mock_enrich_result.ti_confidence = 0.0
    mock_enrich_result.vuln_matched = False

    # async_sessionmaker is imported at module level in arq_app, so patching
    # arq_app.async_sessionmaker works; enrich_alert is lazy-imported so
    # we patch its *source* module.
    with patch(
        "services.worker.app.arq_app.async_sessionmaker", return_value=lambda: mock_session
    ), patch(
        "shared.enrichment.pipeline.enrich_alert", AsyncMock(return_value=mock_enrich_result)
    ) as mock_enrich:
        result = await enrich_job(fake_ctx, alert_id)

    mock_enrich.assert_awaited_once()
    assert result == {"alert_id": alert_id, "status": "enrichment_completed"}


# ── ti_enrich_job ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
@patch("services.worker.app.arq_app._get_redis")
@patch("services.worker.app.arq_app._get_engine")
async def test_ti_enrich_job_calls_private_enrich(
    mock_get_engine, mock_get_redis, fake_ctx,
):
    """ti_enrich_job builds a ThreatIntelWorker and calls _enrich_alert."""
    alert_id = str(uuid.uuid4())
    mock_worker = AsyncMock()
    mock_worker._enrich_alert = AsyncMock()

    with patch(
        "services.worker.app.threat_intel_worker.ThreatIntelWorker", return_value=mock_worker
    ):
        result = await ti_enrich_job(fake_ctx, alert_id)

    mock_worker._enrich_alert.assert_awaited_once_with({"alert_id": alert_id})
    assert result == {"alert_id": alert_id, "status": "ti_enrich_completed"}


# ── sigma_job ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
@patch("services.worker.app.arq_app._get_redis")
@patch("services.worker.app.arq_app._get_engine")
async def test_sigma_job_calls_scan_once(
    mock_get_engine, mock_get_redis, fake_ctx,
):
    """sigma_job builds a SigmaWorker and calls scan_once."""
    mock_worker = AsyncMock()
    mock_worker.scan_once = AsyncMock(
        return_value={"success": True, "rules": 5, "matches": 2}
    )

    with patch(
        "services.worker.app.sigma_worker.SigmaWorker", return_value=mock_worker
    ):
        result = await sigma_job(fake_ctx)

    mock_worker.scan_once.assert_awaited_once()
    assert result["status"] == "sigma_completed"
    assert result["rules"] == 5
    assert result["matches"] == 2


# ── Retry semantics ────────────────────────────────────────────────────────

@pytest.mark.asyncio
@patch("services.worker.app.arq_app._get_redis")
@patch("services.worker.app.arq_app._get_engine")
async def test_retry_on_transient_failure(
    mock_get_engine, mock_get_redis, fake_ctx,
):
    """A job that fails transiently can be re-invoked after the error."""
    alert_id = str(uuid.uuid4())
    mock_worker = AsyncMock()
    mock_worker.engine = MagicMock()
    # Fail on first call
    mock_worker.process_message = AsyncMock(
        side_effect=[ConnectionError("Redis timeout"), None]
    )

    with patch(
        "services.worker.app.triage_worker.TriageWorker", return_value=mock_worker
    ):
        # First call raises (simulating a transient failure that arq would retry)
        with pytest.raises(ConnectionError):
            await triage_job(fake_ctx, alert_id)

        # Second call (simulating arq retry) succeeds
        result = await triage_job(fake_ctx, alert_id)

    assert result["status"] == "triage_completed"


# ── WorkerSettings configuration ───────────────────────────────────────────

def test_worker_settings_has_expected_structure():
    """WorkerSettings exposes the expected arq configuration contract."""
    assert WorkerSettings.functions is not None
    assert len(WorkerSettings.functions) == 4

    func_names = {f.__name__ for f in WorkerSettings.functions}
    assert func_names == {"triage_job", "enrich_job", "ti_enrich_job", "sigma_job"}

    assert WorkerSettings.max_tries == 3
    assert WorkerSettings.keep_result_seconds == 3600
    assert WorkerSettings.cron_jobs is not None
    assert len(WorkerSettings.cron_jobs) == 3

    # Cron jobs reference the expected coroutine functions
    cron_funcs = {c.coroutine.__name__ for c in WorkerSettings.cron_jobs}
    assert "reaper_cron" in cron_funcs
    assert "health_cron" in cron_funcs

    assert hasattr(WorkerSettings, "on_startup")
    assert hasattr(WorkerSettings, "on_shutdown")
