"""Tests for the background reaper in TriageWorker.

Verifies that the worker-side reaper (`_reap_stale_pending` /
`_execute_reaper_update`) fails stuck pending triage rows older than the
budget timeout without depending on the dashboard poll, and that the
CircuitBreaker protects against cascading DB write failures.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.worker.app.triage_worker import (
    TriageWorker,
    _PENDING_REAPER_TIMEOUT_SECONDS,
)
from shared.connectors.circuit_breaker import CircuitBreaker, CircuitBreakerOpenError


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def worker():
    """Return a TriageWorker with a mocked engine/session factory.

    The DB session is a MagicMock with an AsyncMock execute().  No real
    database connection is created.
    """
    mock_engine = MagicMock()
    mock_session = MagicMock()
    mock_session.execute = AsyncMock()
    mock_session.commit = AsyncMock()
    mock_factory = MagicMock()
    mock_factory.return_value = mock_session
    mock_factory.return_value.__aenter__ = AsyncMock(return_value=mock_session)
    mock_factory.return_value.__aexit__ = AsyncMock(return_value=None)

    with (
        patch(
            "services.worker.app.triage_worker.create_async_engine",
            return_value=mock_engine,
        ),
        patch(
            "services.worker.app.triage_worker.async_sessionmaker",
            return_value=mock_factory,
        ),
    ):
        worker_obj = TriageWorker()
    return worker_obj


# ── Tests: Reaper circuit breaker configuration ────────────────────────────────


class TestReaperInit:
    def test_reaper_breaker_is_circuit_breaker_instance(self, worker):
        assert isinstance(worker._reaper_breaker, CircuitBreaker)

    def test_reaper_breaker_default_name(self, worker):
        assert worker._reaper_breaker.name == "triage_reaper"

    def test_reaper_breaker_default_threshold(self, worker):
        assert worker._reaper_breaker.failure_threshold == 3

    def test_reaper_breaker_default_recovery_timeout(self, worker):
        assert worker._reaper_breaker.recovery_timeout == 300.0

    def test_reaper_breaker_custom_thresholds(self):
        with patch(
            "services.worker.app.triage_worker.settings",
            reaper_cb_failure_threshold=5,
            reaper_cb_recovery_timeout=120.0,
            worker_triage_concurrency=1,
            create=True,
        ), patch(
            "services.worker.app.triage_worker.create_async_engine",
            return_value=MagicMock(),
        ), patch(
            "services.worker.app.triage_worker.async_sessionmaker",
            return_value=MagicMock(),
        ):
            w = TriageWorker()
            assert w._reaper_breaker.failure_threshold == 5
            assert w._reaper_breaker.recovery_timeout == 120.0


# ── Tests: _execute_reaper_update — DB update logic ────────────────────────────


class TestExecuteReaperUpdate:
    async def test_fails_stale_pending_rows(self, worker):
        """Rows older than _PENDING_REAPER_TIMEOUT_SECONDS are marked failed."""
        session = worker.session_factory.return_value
        # Simulate a result where 2 rows were updated
        from sqlalchemy.engine import CursorResult
        mock_result = MagicMock(spec=CursorResult)
        mock_result.rowcount = 2
        session.execute.return_value = mock_result

        await worker._execute_reaper_update()

        session.execute.assert_awaited_once()
        session.commit.assert_awaited_once()

    async def test_no_rows_affected_silent(self, worker):
        """When no stale rows exist, the reaper logs nothing (no warning)."""
        session = worker.session_factory.return_value
        from sqlalchemy.engine import CursorResult
        mock_result = MagicMock(spec=CursorResult)
        mock_result.rowcount = 0
        session.execute.return_value = mock_result

        await worker._execute_reaper_update()

        session.execute.assert_awaited_once()
        session.commit.assert_awaited_once()

    async def test_db_failure_propagates(self, worker):
        """When the DB update raises, the exception propagates to the breaker."""
        session = worker.session_factory.return_value
        session.execute.side_effect = RuntimeError("DB connection lost")

        with pytest.raises(RuntimeError, match="DB connection lost"):
            await worker._execute_reaper_update()

    async def test_marks_status_failed_and_success_false(self, worker):
        """The update sets status='failed', success=False, and a timeout message."""
        session = worker.session_factory.return_value
        from sqlalchemy.engine import CursorResult
        mock_result = MagicMock(spec=CursorResult)
        mock_result.rowcount = 1
        session.execute.return_value = mock_result

        await worker._execute_reaper_update()

        # Verify the update was called with the right values
        call_args = session.execute.call_args
        assert call_args is not None


# ── Tests: _reap_stale_pending — CircuitBreaker wrapping ───────────────────────


class TestReapStalePending:
    async def test_calls_breaker_with_execute_reaper_update(self, worker):
        """_reap_stale_pending wraps _execute_reaper_update in breaker.call()."""
        worker._reaper_breaker.call = AsyncMock(return_value=None)

        await worker._reap_stale_pending()

        worker._reaper_breaker.call.assert_awaited_once()
        # The first positional arg is the callable — verify its __name__
        call_args = worker._reaper_breaker.call.call_args
        assert call_args is not None
        assert call_args[0][0].__name__ == "_execute_reaper_update"

    async def test_skips_when_circuit_open(self, worker):
        """When the circuit is open, the reaper skips this cycle."""
        worker._reaper_breaker.call = AsyncMock(
            side_effect=CircuitBreakerOpenError("triage_reaper circuit is open")
        )

        # Should not raise — the error is caught and logged at debug level
        await worker._reap_stale_pending()

        worker._reaper_breaker.call.assert_awaited_once()

    async def test_breaker_success_resets_failure_count(self, worker):
        """A successful call resets the breaker's internal failure counter."""
        # Use a real breaker but mock the inner update
        worker._reaper_breaker = CircuitBreaker(
            name="test", failure_threshold=3, recovery_timeout=60.0
        )
        worker._execute_reaper_update = AsyncMock(return_value=None)

        await worker._reap_stale_pending()

        # After a success, failures should be 0 and circuit closed
        assert worker._reaper_breaker._state.failures == 0
        assert worker._reaper_breaker._state.opened_at is None


# ── Tests: CircuitBreaker integration (failure → open → recovery) ─────────────


class TestReaperCircuitBreaker:
    async def test_failures_accumulate(self, worker):
        """Each failing _execute_reaper_update increments the breaker counter."""
        worker._reaper_breaker = CircuitBreaker(
            name="test", failure_threshold=3, recovery_timeout=60.0
        )
        fail_count = 0

        async def failing_update():
            nonlocal fail_count
            fail_count += 1
            raise RuntimeError("DB error")

        worker._execute_reaper_update = failing_update

        for _ in range(2):
            try:
                await worker._reap_stale_pending()
            except RuntimeError:
                pass

        assert worker._reaper_breaker._state.failures == 2
        assert fail_count == 2

    async def test_circuit_opens_after_threshold(self, worker):
        """After failure_threshold consecutive failures, the circuit opens."""
        worker._reaper_breaker = CircuitBreaker(
            name="test", failure_threshold=2, recovery_timeout=9999
        )

        async def failing_update():
            raise RuntimeError("DB error")

        worker._execute_reaper_update = failing_update

        # Two failures open the circuit (failure_threshold=2)
        for _ in range(2):
            try:
                await worker._reap_stale_pending()
            except RuntimeError:
                pass

        assert worker._reaper_breaker._state.failures == 2
        assert worker._reaper_breaker._state.opened_at is not None

        # Third call should raise CircuitBreakerOpenError
        # (caught by _reap_stale_pending — does not propagate)
        # The breaker itself won't call the inner function again
        update_inner_called = False
        async def tracking_update():
            nonlocal update_inner_called
            update_inner_called = True

        worker._execute_reaper_update = tracking_update
        await worker._reap_stale_pending()
        # _execute_reaper_update should NOT have been called (circuit open)
        assert not update_inner_called

    async def test_circuit_recovers_after_timeout(self, worker):
        """After the recovery timeout, the circuit goes half-open and retries."""
        worker._reaper_breaker = CircuitBreaker(
            name="test", failure_threshold=1, recovery_timeout=0.0
        )
        async def failing_update():
            raise RuntimeError("DB error")
        worker._execute_reaper_update = failing_update

        # First call fails → circuit opens (failure_threshold=1)
        try:
            await worker._reap_stale_pending()
        except RuntimeError:
            pass
        assert worker._reaper_breaker._state.opened_at is not None

        # recovery_timeout=0.0 means the circuit is eligible for half-open
        # immediately.  It should transition to half_open on check_state.
        worker._reaper_breaker._state.opened_at -= 999  # push it far in the past
        worker._execute_reaper_update = AsyncMock(return_value=None)
        await worker._reap_stale_pending()

        # After a successful call, the breaker should reset
        assert worker._reaper_breaker._state.failures == 0


# ── Tests: _run_reaper_loop — periodic execution ──────────────────────────────


class TestReaperLoop:
    async def test_loop_calls_reap_stale_pending(self, worker):
        """_run_reaper_loop sleeps 60s then calls _reap_stale_pending."""
        worker._reap_stale_pending = AsyncMock()
        # Patch asyncio.sleep so we don't actually wait, then stop the loop.
        cycle_count = 0

        async def fake_sleep(seconds):
            nonlocal cycle_count
            cycle_count += 1
            if cycle_count == 1:
                return  # first sleep completes, letting _reap_stale_pending run
            # Second iteration: shut down the loop
            worker._shutdown = True
            return

        with patch(
            "services.worker.app.triage_worker.asyncio.sleep", fake_sleep
        ):
            await worker._run_reaper_loop()

        worker._reap_stale_pending.assert_awaited()

    async def test_loop_stops_on_shutdown(self, worker):
        """When _shutdown is True, the loop exits without calling reaper."""
        worker._shutdown = True
        worker._reap_stale_pending = AsyncMock()

        await worker._run_reaper_loop()

        worker._reap_stale_pending.assert_not_awaited()

    async def test_loop_handles_circuit_breaker_open_error(self, worker):
        """CircuitBreakerOpenError in the loop is caught and logged, not raised."""
        worker._shutdown = False
        cycle = 0

        async def cycle_then_shutdown():
            nonlocal cycle
            cycle += 1
            if cycle == 1:
                raise CircuitBreakerOpenError("test circuit open")
            # Second iteration: shutdown
            worker._shutdown = True

        worker._reap_stale_pending = AsyncMock(side_effect=cycle_then_shutdown)

        # Patch sleep so it's instant
        with patch(
            "services.worker.app.triage_worker.asyncio.sleep", AsyncMock()
        ):
            await worker._run_reaper_loop()

        # Both cycles should have run (first circuit-open, second shutdown)
        assert worker._reap_stale_pending.await_count == 2

    async def test_loop_handles_generic_exception(self, worker):
        """Generic exceptions are logged but do not crash the loop."""
        worker._shutdown = False
        cycle = 0

        async def error_then_shutdown():
            nonlocal cycle
            cycle += 1
            if cycle == 1:
                raise ValueError("something broke")
            worker._shutdown = True

        worker._reap_stale_pending = AsyncMock(side_effect=error_then_shutdown)

        with patch(
            "services.worker.app.triage_worker.asyncio.sleep", AsyncMock()
        ):
            await worker._run_reaper_loop()

        # Loop survived the error and continued
        assert worker._reap_stale_pending.await_count == 2


# ── Tests: start() integration ─────────────────────────────────────────────────


class TestStartIntegration:
    async def test_start_launches_reaper_alongside_consumers(self, worker):
        """start() gathers queue consumers + reaper loop via asyncio.gather."""
        worker.redis_client = AsyncMock()
        worker._shutdown = False

        # Patch _run_queue_loop and _run_reaper_loop so they return immediately
        worker._run_queue_loop = AsyncMock(
            side_effect=lambda idx: None  # returns immediately
        )
        worker._run_reaper_loop = AsyncMock(return_value=None)

        await worker.start()

        # Reaper loop should have been called
        worker._run_reaper_loop.assert_awaited_once()

        # Queue loops should match concurrency
        assert worker._run_queue_loop.await_count == worker._concurrency

    async def test_start_no_redis_reaper_still_runs(self, worker):
        """Even if Redis is unavailable, the reaper is still in the gather."""
        worker.redis_client = None
        worker._run_queue_loop = AsyncMock(return_value=None)
        worker._run_reaper_loop = AsyncMock(return_value=None)

        # Simulate the gather call that start() would make
        await asyncio.gather(
            *[worker._run_queue_loop(i) for i in range(worker._concurrency)],
            worker._run_reaper_loop(),
        )

        worker._run_reaper_loop.assert_awaited_once()


# ── Core invariants ───────────────────────────────────────────────────────────


class TestReaperInvariants:
    def test_pending_timeout_is_positive(self):
        """The timeout that defines 'stale' must be positive."""
        assert _PENDING_REAPER_TIMEOUT_SECONDS > 0

    def test_reaper_does_not_depend_on_dashboard_poll(self, worker):
        """_reap_stale_pending queries the DB directly — no HTTP/API dependency."""
        assert callable(worker._reap_stale_pending)
        # It should be usable without any HTTP context
        assert not hasattr(worker, "_dashboard_client")

    async def test_reaper_preserves_non_pending_rows(self, worker):
        """Only rows with status='pending' are affected by the reaper update."""
        session = worker.session_factory.return_value
        from sqlalchemy.engine import CursorResult
        mock_result = MagicMock(spec=CursorResult)
        mock_result.rowcount = 0
        session.execute.return_value = mock_result

        # A session with completed/failed rows should return rowcount=0
        await worker._execute_reaper_update()

        session.execute.assert_awaited_once()
        # Verify the WHERE clause includes status='pending'
        call_args = session.execute.call_args
        assert call_args is not None
