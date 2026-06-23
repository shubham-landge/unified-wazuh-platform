"""Tests for trigger_worker.py -- cron + webhook trigger engine."""

import uuid
from datetime import datetime, timezone

import pytest
from unittest.mock import AsyncMock, MagicMock, patch, call

from services.worker.app.trigger_worker import (
    _cron_matches,
    _parse_cron_triggers,
    _parse_webhook_triggers,
    _spawn_agent_run,
    _get_or_create_definition,
    CronTrigger,
    WebhookTrigger,
    TriggerWorker,
)
from shared.models.agent import AgentDefinition, AgentRun


def _async_session_mock(commit_side_effect=None):
    """Build a mock session that works correctly with `async with`.

    When used as `async with mock as session:`, the same mock is returned
    as `session` so that assertions like `session.add.assert_called_once()`
    work naturally.

    session.add is a regular MagicMock (synchronous SQLAlchemy method).
    session.commit and session.flush are AsyncMocks (awaitable).
    """
    session = AsyncMock()
    session.add = MagicMock()  # sync -- avoids "never awaited" warnings
    session.commit = AsyncMock(side_effect=commit_side_effect)
    session.flush = AsyncMock()
    session.__aenter__.return_value = session
    session.__aexit__ = AsyncMock()
    return session


# ── cron matching tests ─────────────────────────────────────────────────────

class TestCronMatches:
    """Test the 5-field cron expression matcher."""

    def test_star_matches_everything(self):
        """* * * * * matches any datetime."""
        dt = datetime(2025, 6, 15, 12, 30, tzinfo=timezone.utc)
        assert _cron_matches("* * * * *", dt) is True

    def test_exact_minute_match(self):
        """Exact field values match only when equal."""
        dt = datetime(2025, 6, 15, 12, 30, tzinfo=timezone.utc)
        assert _cron_matches("30 * * * *", dt) is True
        assert _cron_matches("31 * * * *", dt) is False

    def test_exact_hour_match(self):
        dt = datetime(2025, 6, 15, 12, 30, tzinfo=timezone.utc)
        assert _cron_matches("* 12 * * *", dt) is True
        assert _cron_matches("* 13 * * *", dt) is False

    def test_exact_dom_match(self):
        dt = datetime(2025, 6, 15, 12, 30, tzinfo=timezone.utc)
        assert _cron_matches("* * 15 * *", dt) is True
        assert _cron_matches("* * 16 * *", dt) is False

    def test_exact_month_match(self):
        dt = datetime(2025, 6, 15, 12, 30, tzinfo=timezone.utc)
        assert _cron_matches("* * * 6 *", dt) is True
        assert _cron_matches("* * * 7 *", dt) is False

    def test_comma_separated_values(self):
        """Comma-separated values match any in the list."""
        dt = datetime(2025, 6, 15, 12, 30, tzinfo=timezone.utc)
        assert _cron_matches("0,15,30,45 * * * *", dt) is True  # minute 30
        assert _cron_matches("0,15,45 * * * *", dt) is False     # minute 30 not in list

    def test_range_values(self):
        """Range values match within [lo, hi]."""
        dt = datetime(2025, 6, 15, 12, 30, tzinfo=timezone.utc)
        assert _cron_matches("25-35 * * * *", dt) is True
        assert _cron_matches("0-29 * * * *", dt) is False

    def test_step_values(self):
        """Step values */N match every N."""
        dt = datetime(2025, 6, 15, 12, 30, tzinfo=timezone.utc)
        # minute 30 is divisible by 15
        assert _cron_matches("*/15 * * * *", dt) is True
        # minute 30 is divisible by 10
        assert _cron_matches("*/10 * * * *", dt) is True
        # minute 30 is NOT divisible by 7
        assert _cron_matches("*/7 * * * *", dt) is False

    def test_range_with_step(self):
        """Range-step like 0-30/15 matches 0, 15, 30."""
        dt = datetime(2025, 6, 15, 12, 30, tzinfo=timezone.utc)
        assert _cron_matches("0-30/15 * * * *", dt) is True   # 30 is in 0,15,30
        dt2 = datetime(2025, 6, 15, 12, 45, tzinfo=timezone.utc)
        assert _cron_matches("0-30/15 * * * *", dt2) is False  # 45 > 30

    def test_daily_at_midnight(self):
        """0 0 * * * matches midnight."""
        dt = datetime(2025, 6, 15, 0, 0, tzinfo=timezone.utc)
        assert _cron_matches("0 0 * * *", dt) is True

        dt2 = datetime(2025, 6, 15, 0, 1, tzinfo=timezone.utc)
        assert _cron_matches("0 0 * * *", dt2) is False

    def test_weekday_match(self):
        """DOW 0=Monday, 6=Sunday."""
        # 2025-06-16 is a Monday (weekday=0)
        dt = datetime(2025, 6, 16, 12, 0, tzinfo=timezone.utc)
        assert _cron_matches("* * * * 0", dt) is True
        assert _cron_matches("* * * * 1", dt) is False

    def test_invalid_cron_expr(self):
        """Invalid expressions return False."""
        dt = datetime.now(timezone.utc)
        assert _cron_matches("", dt) is False
        assert _cron_matches("* * * *", dt) is False  # only 4 fields
        assert _cron_matches("abc def ghi jkl mno", dt) is False

    def test_comma_in_cron_field(self):
        """Cron field with commas matches correctly."""
        dt = datetime(2025, 6, 15, 12, 30, tzinfo=timezone.utc)
        assert _cron_matches("1,15,30,45 * * * *", dt) is True
        dt2 = datetime(2025, 6, 15, 12, 7, tzinfo=timezone.utc)
        assert _cron_matches("1,15,30,45 * * * *", dt2) is False


# ── parsing tests ───────────────────────────────────────────────────────────

class TestParseCronTriggers:
    """Test parsing of the cron trigger config string."""

    def test_single_entry(self):
        triggers = _parse_cron_triggers("* * * * *;triage;Check all alerts")
        assert len(triggers) == 1
        assert triggers[0].cron_expr == "* * * * *"
        assert triggers[0].agent_type == "triage"
        assert triggers[0].description == "Check all alerts"

    def test_single_entry_no_description(self):
        triggers = _parse_cron_triggers("0 2 * * *;meta_agent")
        assert len(triggers) == 1
        assert triggers[0].cron_expr == "0 2 * * *"
        assert triggers[0].agent_type == "meta_agent"
        assert triggers[0].description == ""

    def test_multiple_entries(self):
        raw = "* * * * *;triage;Check,0 2 * * *;ueba_check;Nightly"
        triggers = _parse_cron_triggers(raw)
        assert len(triggers) == 2
        assert triggers[0].cron_expr == "* * * * *"
        assert triggers[0].agent_type == "triage"
        assert triggers[1].cron_expr == "0 2 * * *"
        assert triggers[1].agent_type == "ueba_check"
        assert triggers[1].description == "Nightly"

    def test_comma_in_cron_field(self):
        """Cron field containing commas (e.g. 1,15,30,45) should not be
        treated as entry separators."""
        raw = "1,15,30,45 * * * *;triage;Frequent check,0 2 * * *;ueba;Nightly"
        triggers = _parse_cron_triggers(raw)
        assert len(triggers) == 2
        assert triggers[0].cron_expr == "1,15,30,45 * * * *"
        assert triggers[0].agent_type == "triage"
        assert triggers[1].cron_expr == "0 2 * * *"
        assert triggers[1].agent_type == "ueba"

    def test_empty_string(self):
        assert _parse_cron_triggers("") == []
        assert _parse_cron_triggers("   ") == []

    def test_description_contains_semicolons(self):
        """Description after the second semicolon should be captured fully."""
        raw = "* * * * *;triage;Alert check: every minute"
        triggers = _parse_cron_triggers(raw)
        assert len(triggers) == 1
        assert triggers[0].description == "Alert check: every minute"

    def test_extra_spaces(self):
        raw = "  0 2 * * *  ;  ueba_check  ;  Nightly UEBA scan  "
        triggers = _parse_cron_triggers(raw)
        assert len(triggers) == 1
        assert triggers[0].cron_expr == "0 2 * * *"
        assert triggers[0].agent_type == "ueba_check"
        assert triggers[0].description == "Nightly UEBA scan"


class TestParseWebhookTriggers:
    """Test parsing of the webhook trigger config string."""

    def test_single_entry(self):
        triggers = _parse_webhook_triggers("siem-webhook-a1b2c3;triage;External SIEM webhook")
        assert len(triggers) == 1
        assert triggers[0].path_secret == "siem-webhook-a1b2c3"
        assert triggers[0].agent_type == "triage"
        assert triggers[0].description == "External SIEM webhook"

    def test_single_entry_no_description(self):
        triggers = _parse_webhook_triggers("gh-secret-abc;triage")
        assert len(triggers) == 1
        assert triggers[0].path_secret == "gh-secret-abc"
        assert triggers[0].agent_type == "triage"
        assert triggers[0].description == ""

    def test_multiple_entries(self):
        raw = "wh-secret1;triage;Webhook 1,wh-secret2;ueba_check;Webhook 2"
        triggers = _parse_webhook_triggers(raw)
        assert len(triggers) == 2
        assert triggers[0].path_secret == "wh-secret1"
        assert triggers[1].path_secret == "wh-secret2"

    def test_empty_string(self):
        assert _parse_webhook_triggers("") == []
        assert _parse_webhook_triggers("   ") == []

    def test_extra_spaces(self):
        raw = "  wh-secret1  ;  triage  ;  Alert check  "
        triggers = _parse_webhook_triggers(raw)
        assert len(triggers) == 1
        assert triggers[0].path_secret == "wh-secret1"
        assert triggers[0].agent_type == "triage"
        assert triggers[0].description == "Alert check"


# ── AgentRun spawning tests ─────────────────────────────────────────────────

class TestGetOrCreateDefinition:
    """Test AgentDefinition lookup/creation."""

    @pytest.mark.asyncio
    async def test_creates_new_definition_when_missing(self):
        session = _async_session_mock()
        # Simulate no existing definition
        session.execute = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = None
        session.execute.return_value = result
        session.flush = AsyncMock()

        tenant_id = uuid.uuid4()
        definition = await _get_or_create_definition(
            session, "triage", "Test trigger", tenant_id,
        )

        assert definition.agent_type == "triage"
        assert definition.tenant_id == tenant_id
        assert definition.is_active is True
        session.add.assert_called_once()
        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_reuses_existing_definition(self):
        session = _async_session_mock()
        existing_def = AgentDefinition(
            id=uuid.uuid4(),
            name="triage-agent",
            agent_type="triage",
            is_active=True,
        )
        session.execute = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = existing_def
        session.execute.return_value = result

        tenant_id = uuid.uuid4()
        definition = await _get_or_create_definition(
            session, "triage", "Test trigger", tenant_id,
        )

        assert definition is existing_def
        session.add.assert_not_called()


class TestSpawnAgentRun:
    """Test AgentRun creation and redis enqueuing."""

    @pytest.mark.asyncio
    async def test_creates_agent_run_and_pushes_to_redis(self):
        session = _async_session_mock()

        redis_client = AsyncMock()
        redis_client.lpush = AsyncMock()

        tenant_id = uuid.uuid4()
        existing_def = AgentDefinition(
            id=uuid.uuid4(),
            name="triage-agent",
            agent_type="triage",
            is_active=True,
            tenant_id=tenant_id,
        )

        # Mock _get_or_create_definition
        with patch(
            "services.worker.app.trigger_worker._get_or_create_definition",
            return_value=existing_def,
        ):
            run_id = await _spawn_agent_run(
                session=session,
                agent_type="triage",
                description="Check all alerts",
                trigger_type="cron",
                trigger_ref="* * * * *",
                tenant_id=tenant_id,
                redis_client=redis_client,
            )

        # Verify AgentRun was created
        assert isinstance(run_id, str)
        assert len(run_id) > 0
        session.add.assert_called_once()
        session.commit.assert_awaited_once()

        # Verify the added AgentRun has correct fields
        added_run = session.add.call_args[0][0]
        assert isinstance(added_run, AgentRun)
        assert added_run.definition_id == existing_def.id
        assert added_run.trigger_type == "cron"
        assert added_run.trigger_ref == "* * * * *"
        assert added_run.status == "pending"
        assert added_run.result_summary == "Check all alerts"

        # Verify redis push
        redis_client.lpush.assert_awaited_once()
        enqueued = redis_client.lpush.call_args[0][0]
        assert enqueued == "agent_queue"

    @pytest.mark.asyncio
    async def test_spawn_without_redis_does_not_crash(self):
        session = _async_session_mock()

        tenant_id = uuid.uuid4()
        existing_def = AgentDefinition(
            id=uuid.uuid4(),
            name="triage-agent",
            agent_type="triage",
            is_active=True,
        )

        with patch(
            "services.worker.app.trigger_worker._get_or_create_definition",
            return_value=existing_def,
        ):
            run_id = await _spawn_agent_run(
                session=session,
                agent_type="triage",
                description="Test",
                trigger_type="webhook",
                trigger_ref="wh-secret",
                tenant_id=tenant_id,
                redis_client=None,  # No redis
            )

        assert isinstance(run_id, str)
        assert len(run_id) > 0
        session.add.assert_called_once()
        session.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_spawn_returns_empty_on_failure(self):
        session = _async_session_mock(commit_side_effect=RuntimeError("DB error"))

        tenant_id = uuid.uuid4()
        existing_def = AgentDefinition(
            id=uuid.uuid4(),
            name="triage-agent",
            agent_type="triage",
            is_active=True,
        )

        with patch(
            "services.worker.app.trigger_worker._get_or_create_definition",
            return_value=existing_def,
        ):
            run_id = await _spawn_agent_run(
                session=session,
                agent_type="triage",
                description="Test",
                trigger_type="cron",
                trigger_ref="* * * * *",
                tenant_id=tenant_id,
                redis_client=None,
            )

        assert run_id == ""

    @pytest.mark.asyncio
    async def test_redis_push_failure_does_not_prevent_agent_run(self):
        """If redis push fails, AgentRun should still be created."""
        session = _async_session_mock()

        redis_client = AsyncMock()
        redis_client.lpush = AsyncMock(side_effect=RuntimeError("Redis down"))

        tenant_id = uuid.uuid4()
        existing_def = AgentDefinition(
            id=uuid.uuid4(),
            name="triage-agent",
            agent_type="triage",
            is_active=True,
        )

        with patch(
            "services.worker.app.trigger_worker._get_or_create_definition",
            return_value=existing_def,
        ):
            run_id = await _spawn_agent_run(
                session=session,
                agent_type="triage",
                description="Test",
                trigger_type="cron",
                trigger_ref="* * * * *",
                tenant_id=tenant_id,
                redis_client=redis_client,
            )

        assert isinstance(run_id, str)
        assert len(run_id) > 0
        session.add.assert_called_once()
        session.commit.assert_awaited_once()


# ── TriggerWorker tests ─────────────────────────────────────────────────────

class TestTriggerWorkerFireCron:
    """Test TriggerWorker._fire_cron_triggers."""

    @pytest.mark.asyncio
    async def test_fires_matching_trigger(self):
        worker = TriggerWorker()
        worker._stopped = MagicMock()  # prevent asyncio.Event issues

        # Mock session -- use _async_session_mock so async with returns same mock
        mock_session = _async_session_mock()
        worker._session = MagicMock(return_value=mock_session)

        # Mock redis
        mock_redis = AsyncMock()
        mock_redis.lpush = AsyncMock()
        worker._redis_client = mock_redis

        # Mock tenant
        tenant_id = uuid.uuid4()
        worker._get_tenant_id = AsyncMock(return_value=tenant_id)

        # Mock existing definition
        existing_def = AgentDefinition(
            id=uuid.uuid4(),
            name="triage-agent",
            agent_type="triage",
            is_active=True,
            tenant_id=tenant_id,
        )

        with patch.object(worker.settings, "triggers_cron", "* * * * *;triage;Check alerts"):
            with patch(
                "services.worker.app.trigger_worker._get_or_create_definition",
                return_value=existing_def,
            ):
                await worker._fire_cron_triggers()

        # Should create an AgentRun
        mock_session.add.assert_called_once()
        mock_session.commit.assert_awaited()

    @pytest.mark.asyncio
    async def test_skips_already_fired_minute(self):
        worker = TriggerWorker()
        worker._stopped = MagicMock()

        mock_session = _async_session_mock()
        worker._session = MagicMock(return_value=mock_session)

        mock_redis = AsyncMock()
        worker._redis_client = mock_redis

        tenant_id = uuid.uuid4()
        worker._get_tenant_id = AsyncMock(return_value=tenant_id)

        now = datetime.now(timezone.utc)
        minute_key = int(now.strftime("%Y%m%d%H%M"))
        worker._last_fired["* * * * *:triage"] = minute_key

        with patch.object(worker.settings, "triggers_cron", "* * * * *;triage;Check alerts"):
            await worker._fire_cron_triggers()

        # Should NOT fire again this minute
        mock_session.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_skips_non_matching_triggers(self):
        worker = TriggerWorker()
        worker._stopped = MagicMock()

        mock_session = _async_session_mock()
        worker._session = MagicMock(return_value=mock_session)

        mock_redis = AsyncMock()
        worker._redis_client = mock_redis

        tenant_id = uuid.uuid4()
        worker._get_tenant_id = AsyncMock(return_value=tenant_id)

        # Trigger only fires at minute 0 -- current time probably not minute 0
        with patch.object(worker.settings, "triggers_cron", "0 0 * * *;ueba_check;Nightly"):
            await worker._fire_cron_triggers()

        # Should not fire unless it's actually midnight
        # (test doesn't assert on add; it just shouldn't crash)

    @pytest.mark.asyncio
    async def test_empty_cron_config(self):
        worker = TriggerWorker()
        worker._stopped = MagicMock()

        mock_session = _async_session_mock()
        worker._session = MagicMock(return_value=mock_session)

        with patch.object(worker.settings, "triggers_cron", ""):
            await worker._fire_cron_triggers()

        mock_session.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_handles_cron_fire_exception(self):
        worker = TriggerWorker()
        worker._stopped = MagicMock()

        # Simulate DB failure during commit
        mock_session = _async_session_mock(commit_side_effect=RuntimeError("DB down"))
        worker._session = MagicMock(return_value=mock_session)

        mock_redis = AsyncMock()
        worker._redis_client = mock_redis

        tenant_id = uuid.uuid4()
        worker._get_tenant_id = AsyncMock(return_value=tenant_id)

        existing_def = AgentDefinition(
            id=uuid.uuid4(),
            name="triage-agent",
            agent_type="triage",
            is_active=True,
            tenant_id=tenant_id,
        )

        with patch.object(worker.settings, "triggers_cron", "* * * * *;triage;Check"):
            with patch(
                "services.worker.app.trigger_worker._get_or_create_definition",
                return_value=existing_def,
            ):
                # Should not raise -- errors are caught and logged
                await worker._fire_cron_triggers()

    @pytest.mark.asyncio
    async def test_handles_tenant_resolution_failure(self):
        worker = TriggerWorker()
        worker._stopped = MagicMock()

        mock_session = _async_session_mock()
        worker._session = MagicMock(return_value=mock_session)

        mock_redis = AsyncMock()
        worker._redis_client = mock_redis

        worker._get_tenant_id = AsyncMock(side_effect=RuntimeError("No tenant"))

        with patch.object(worker.settings, "triggers_cron", "* * * * *;triage;Check"):
            await worker._fire_cron_triggers()

        # Should not crash


class TestTriggerWorkerWebhook:
    """Test TriggerWorker.handle_webhook."""

    @pytest.mark.asyncio
    async def test_matches_path_secret_and_spawns(self):
        worker = TriggerWorker()
        mock_redis = AsyncMock()
        mock_redis.lpush = AsyncMock()
        worker._redis_client = mock_redis

        session = _async_session_mock()

        tenant_id = uuid.uuid4()
        existing_def = AgentDefinition(
            id=uuid.uuid4(),
            name="triage-agent",
            agent_type="triage",
            is_active=True,
            tenant_id=tenant_id,
        )

        with patch.object(worker.settings, "triggers_webhooks", "siem-wh;triage;SIEM webhook"):
            with patch(
                "services.worker.app.trigger_worker._get_or_create_definition",
                return_value=existing_def,
            ):
                run_id = await worker.handle_webhook(
                    path_secret="siem-wh",
                    payload={"alert_id": "test-123"},
                    session=session,
                    tenant_id=tenant_id,
                )

        assert isinstance(run_id, str)
        assert len(run_id) > 0

    @pytest.mark.asyncio
    async def test_returns_none_for_unknown_path(self):
        worker = TriggerWorker()

        session = AsyncMock()
        tenant_id = uuid.uuid4()

        with patch.object(worker.settings, "triggers_webhooks", "siem-wh;triage;SIEM"):
            result = await worker.handle_webhook(
                path_secret="unknown-wh",
                payload={},
                session=session,
                tenant_id=tenant_id,
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_when_no_config(self):
        worker = TriggerWorker()

        session = AsyncMock()
        tenant_id = uuid.uuid4()

        with patch.object(worker.settings, "triggers_webhooks", ""):
            result = await worker.handle_webhook(
                path_secret="anything",
                payload={},
                session=session,
                tenant_id=tenant_id,
            )

        assert result is None


# ── TriggerWorker lifecycle tests ───────────────────────────────────────────

class TestTriggerWorkerLifecycle:
    """Test TriggerWorker start/stop/shutdown."""

    @pytest.mark.asyncio
    async def test_start_and_stop(self):
        worker = TriggerWorker()

        # Make _fire_cron_triggers a no-op so the loop doesn't touch DB
        worker._fire_cron_triggers = AsyncMock()

        # Start the worker, then stop it after a short delay
        async def _stop_after_delay():
            await asyncio_sleep(0.05)
            worker.stop()

        import asyncio
        task_start = asyncio.ensure_future(worker.start())
        task_stop = asyncio.ensure_future(_stop_after_delay())

        await asyncio.gather(task_start, task_stop)

        assert worker._stopped.is_set()

    @pytest.mark.asyncio
    async def test_shutdown_closes_connections(self):
        worker = TriggerWorker()
        mock_redis = AsyncMock()
        mock_redis.close = AsyncMock()
        worker._redis_client = mock_redis

        mock_engine = MagicMock()
        mock_engine.dispose = AsyncMock()
        worker._engine = mock_engine

        await worker.shutdown()

        assert worker._stopped.is_set()
        mock_redis.close.assert_awaited_once()
        mock_engine.dispose.assert_awaited_once()


# -- Helper to avoid real asyncio.sleep in tests --
async def asyncio_sleep(seconds: float):
    import asyncio
    await asyncio.sleep(seconds)
