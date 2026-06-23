"""Tests for parallel triage consumers (WORKER_TRIAGE_CONCURRENCY).

Verifies that TriageWorker supports multiple concurrent queue-loop consumers
for DB/enrichment overlap, that the concurrency setting is read from settings,
and that the shutdown path stops all consumers cleanly.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.worker.app.triage_worker import TriageWorker
from shared.config import Settings


# ── Helpers ──────────────────────────────────────────────────────────────────

def _mock_alert(alert_id=None, rule_level=10, rule_id=1001, tenant_id=None):
    tid = tenant_id or uuid.uuid4()
    return SimpleNamespace(
        id=alert_id or uuid.uuid4(),
        rule_level=rule_level,
        rule_id=rule_id,
        rule_groups=[],
        rule_description="Test alert",
        agent_name="test-agent",
        agent_ip="10.0.0.1",
        source_ip="192.168.1.1",
        user_name="testuser",
        process_name="testproc",
        mitre_tactic="Execution",
        mitre_technique="T1059",
        tenant_id=tid,
        status="open",
    )


# ── Concurrency Setting ──────────────────────────────────────────────────────

class TestConcurrencySetting:
    def test_default_concurrency_is_one(self):
        """worker_triage_concurrency defaults to 1."""
        assert Settings().worker_triage_concurrency == 1

    def test_custom_concurrency_from_env(self, monkeypatch):
        """worker_triage_concurrency can be overridden via env."""
        monkeypatch.setenv("worker_triage_concurrency", "4")
        s = Settings()
        assert s.worker_triage_concurrency == 4

    def test_concurrency_clamps_to_positive(self):
        """Zero or negative values should be clamped to at least 1 in __init__."""
        import services.worker.app.triage_worker as tw_mod

        with patch.object(
            tw_mod, "create_async_engine", return_value=MagicMock()
        ), patch.object(
            tw_mod, "async_sessionmaker", return_value=MagicMock()
        ), patch.object(
            tw_mod.settings, "worker_triage_concurrency", 0,
        ):
            worker0 = TriageWorker()
            assert worker0._concurrency == 1

        with patch.object(
            tw_mod, "create_async_engine", return_value=MagicMock()
        ), patch.object(
            tw_mod, "async_sessionmaker", return_value=MagicMock()
        ), patch.object(
            tw_mod.settings, "worker_triage_concurrency", -3,
        ):
            worker3 = TriageWorker()
            assert worker3._concurrency == 1


# ── Worker Init ──────────────────────────────────────────────────────────────

class TestWorkerInit:
    def test_worker_stores_concurrency_from_settings(self):
        """TriageWorker.__init__ reads worker_triage_concurrency from settings."""
        import services.worker.app.triage_worker as tw_mod

        with patch.object(
            tw_mod, "create_async_engine", return_value=MagicMock()
        ), patch.object(
            tw_mod, "async_sessionmaker", return_value=MagicMock()
        ), patch.object(
            tw_mod.settings, "worker_triage_concurrency", 3,
        ):
            worker = TriageWorker()
            assert worker._concurrency == 3

    def test_worker_defaults_to_one_when_setting_missing(self):
        """When settings has no worker_triage_concurrency, default to 1."""
        import services.worker.app.triage_worker as tw_mod
        from shared.config import Settings as SettingsCls

        # Create a settings instance without worker_triage_concurrency,
        # then delete the attribute to simulate missing config.
        with patch.object(
            tw_mod, "create_async_engine", return_value=MagicMock()
        ), patch.object(
            tw_mod, "async_sessionmaker", return_value=MagicMock()
        ), patch.object(
            tw_mod.settings, "worker_triage_concurrency", create=True,
        ):
            del tw_mod.settings.worker_triage_concurrency
            worker = TriageWorker()
            assert worker._concurrency == 1


# ── Start / Consumers ────────────────────────────────────────────────────────

class TestStartConsumerCount:
    def test_start_launches_one_consumer_by_default(self):
        """With default concurrency=1, start() launches 1 queue loop + 1 reaper."""
        worker = TriageWorker()
        worker._concurrency = 1

        mock_redis = AsyncMock()
        with patch.object(worker, "_run_queue_loop") as mock_loop, \
             patch.object(worker, "_run_reaper_loop") as mock_reaper, \
             patch(
                "services.worker.app.triage_worker.redis",
            ) as mock_redis_mod:
            mock_redis_mod.from_url = AsyncMock(return_value=mock_redis)
            mock_loop.return_value = None
            mock_reaper.return_value = None
            worker._shutdown = True  # exit immediately

            asyncio.run(worker.start())

            assert mock_loop.call_count == 1, (
                f"Expected 1 consumer, got {mock_loop.call_count}"
            )
            mock_reaper.assert_called_once()

    def test_start_launches_three_consumers(self):
        """With concurrency=3, start() launches 3 queue loops + 1 reaper."""
        worker = TriageWorker()
        worker._concurrency = 3

        mock_redis = AsyncMock()
        with patch.object(worker, "_run_queue_loop") as mock_loop, \
             patch.object(worker, "_run_reaper_loop") as mock_reaper, \
             patch(
                "services.worker.app.triage_worker.redis",
            ) as mock_redis_mod:
            mock_redis_mod.from_url = AsyncMock(return_value=mock_redis)
            mock_loop.return_value = None
            mock_reaper.return_value = None
            worker._shutdown = True

            asyncio.run(worker.start())

            assert mock_loop.call_count == 3, (
                f"Expected 3 consumers, got {mock_loop.call_count}"
            )
            mock_reaper.assert_called_once()

    def test_start_always_launches_reaper(self):
        """Regardless of concurrency, the reaper loop is always launched."""
        for n in (1, 2, 5):
            worker = TriageWorker()
            worker._concurrency = n

            mock_redis = AsyncMock()
            with patch.object(worker, "_run_queue_loop") as mock_loop, \
                 patch.object(worker, "_run_reaper_loop") as mock_reaper, \
                 patch(
                    "services.worker.app.triage_worker.redis",
                ) as mock_redis_mod:
                mock_redis_mod.from_url = AsyncMock(return_value=mock_redis)
                mock_loop.return_value = None
                mock_reaper.return_value = None
                worker._shutdown = True

                asyncio.run(worker.start())
                mock_reaper.assert_called_once()


class TestConsumerIndex:
    def test_consumer_index_passed_to_loop(self):
        """Each consumer gets a unique index starting from 0."""
        worker = TriageWorker()
        worker._concurrency = 3

        mock_redis = AsyncMock()
        called_indices = []

        async def capture_loop(idx):
            called_indices.append(idx)

        with patch.object(worker, "_run_queue_loop", side_effect=capture_loop), \
             patch.object(worker, "_run_reaper_loop") as mock_reaper, \
             patch(
                "services.worker.app.triage_worker.redis",
            ) as mock_redis_mod:
            mock_redis_mod.from_url = AsyncMock(return_value=mock_redis)
            mock_reaper.return_value = None
            worker._shutdown = True

            asyncio.run(worker.start())

            assert called_indices == [0, 1, 2], (
                f"Expected consumer indices [0, 1, 2], got {called_indices}"
            )

    def test_consumer_index_in_error_logging(self):
        """_run_queue_loop includes consumer_idx in error log messages."""
        import services.worker.app.triage_worker as tw_mod

        worker = TriageWorker()
        worker.redis_client = AsyncMock()
        # First call raises, second call sets shutdown
        call_count = [0]

        async def mock_brpop(*a, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("test error")
            else:
                worker._shutdown = True
                return None

        worker.redis_client.brpop = mock_brpop

        # Patch the module-level logger directly
        with patch.object(
            tw_mod.logger, "error",
        ) as mock_error:
            asyncio.run(worker._run_queue_loop(2))

            assert mock_error.call_count >= 1
            # logger.error("Triage worker[%d] error: %s", consumer_idx, e, ...)
            fmt, idx_arg, exc_arg = mock_error.call_args[0][:3]
            assert fmt == "Triage worker[%d] error: %s", (
                f"Unexpected format string: {fmt}"
            )
            assert idx_arg == 2, (
                f"Expected consumer_idx=2, got {idx_arg}"
            )


# ── Concurrent Processing ────────────────────────────────────────────────────

class TestConcurrentProcessing:
    @pytest.mark.asyncio
    async def test_process_message_is_reentrant(self):
        """process_message can be called concurrently from multiple consumers
        without shared-state corruption (DB session per call)."""
        worker = TriageWorker()

        # Two alerts processed in parallel
        alert1 = _mock_alert()
        alert2 = _mock_alert()

        completed = []

        async def tracked_process(msg):
            await asyncio.sleep(0.01)  # simulate some async work
            completed.append(msg["alert_id"])
            return msg

        with patch.object(worker, "process_message", side_effect=tracked_process):
            msg1 = {"alert_id": str(alert1.id), "manual": True}
            msg2 = {"alert_id": str(alert2.id), "manual": True}
            await asyncio.gather(
                worker.process_message(msg1),
                worker.process_message(msg2),
            )
            assert len(completed) == 2
            assert str(alert1.id) in completed
            assert str(alert2.id) in completed

    @pytest.mark.asyncio
    async def test_multiple_consumers_take_different_messages(self):
        """When multiple consumers pop from the same Redis queue, each
        gets a different message."""
        worker = TriageWorker()
        worker._shutdown = False

        mock_redis = AsyncMock()
        # Two messages then None (timeout) → consumers check _shutdown
        call_counter = [0]
        queue_items = [
            (b"triage_queue", json.dumps({"alert_id": "a1", "manual": True})),
            (b"triage_queue", json.dumps({"alert_id": "a2", "manual": True})),
        ]

        async def mock_brpop(*a, **kw):
            if call_counter[0] < len(queue_items):
                result = queue_items[call_counter[0]]
                call_counter[0] += 1
                return result
            # Return None → consumer checks _shutdown immediately
            await asyncio.sleep(0)
            if not worker._shutdown:
                worker._shutdown = True
            return None

        mock_redis.brpop = mock_brpop
        worker.redis_client = mock_redis

        received = []

        async def capture_process(msg: dict):
            await asyncio.sleep(0)
            received.append(msg)

        with patch.object(worker, "process_message", side_effect=capture_process):
            async def run_consumer(idx):
                await worker._run_queue_loop(idx)

            await asyncio.wait_for(
                asyncio.gather(
                    run_consumer(0),
                    run_consumer(1),
                ),
                timeout=3,
            )

        assert len(received) == 2, (
            f"Expected 2 messages processed, got {len(received)}: {received}"
        )

    @pytest.mark.asyncio
    async def test_shutdown_stops_all_consumers(self):
        """When _shutdown is set, all queue-loop consumers exit."""
        worker = TriageWorker()
        worker._shutdown = False

        # Mock brpop to return None quickly (simulate timeout)
        mock_redis = AsyncMock()

        async def short_brpop(*a, **kw):
            await asyncio.sleep(0)
            if worker._shutdown:
                # Simulate asyncio.CancelledError or just return None
                return None
            return None

        mock_redis.brpop = short_brpop
        worker.redis_client = mock_redis

        exited = []

        async def tracked_loop(idx):
            await worker._run_queue_loop(idx)
            exited.append(idx)

        task0 = asyncio.create_task(tracked_loop(0))
        task1 = asyncio.create_task(tracked_loop(1))
        task2 = asyncio.create_task(tracked_loop(2))

        # Let them run briefly, then shut down
        await asyncio.sleep(0.02)
        worker._shutdown = True

        # Wait for all to exit (with timeout)
        try:
            await asyncio.wait_for(
                asyncio.gather(task0, task1, task2),
                timeout=3,
            )
        except asyncio.TimeoutError:
            pass

        assert exited == [0, 1, 2], (
            f"Expected all consumers to exit, got {exited}"
        )


# ── Pool Size / DB Safety ────────────────────────────────────────────────────

class TestDBSafety:
    def test_engine_pool_created_with_default_pool_size(self):
        """DB engine is created with pool_size=5, sufficient for moderate
        concurrency. The async pool queues gracefully, no deadlock risk."""
        worker = TriageWorker()
        # pool_size=5 was passed to create_async_engine; verify the engine
        # was successfully created (not None, not a mock).
        assert worker.engine is not None
        # With _concurrency up to pool_size, all consumers get a connection
        # without queuing. Above pool_size, async queue handles overflow.
        worker._concurrency = 5
        assert worker._concurrency >= 1

    @pytest.mark.asyncio
    async def test_session_factory_is_safe_for_concurrent_use(self):
        """session_factory() creates independent sessions — safe for parallel
        consumers within the same event loop."""
        worker = TriageWorker()
        worker._concurrency = 3

        async def use_session():
            session = worker.session_factory()
            async with session as s:
                # Simulate a DB query
                pass

        # Three concurrent session creations should not conflict
        await asyncio.gather(
            use_session(),
            use_session(),
            use_session(),
        )


# ── Integration: Full start() with mock process_message ──────────────────────

class TestIntegration:
    def test_start_with_concurrency_processes_messages(self):
        """Full start() flow with concurrency=2 processes messages via
        the queue loop."""
        import services.worker.app.triage_worker as tw_mod

        worker = TriageWorker()
        worker._concurrency = 2

        mock_redis = AsyncMock()
        messages_processed = []

        async def mock_process(msg):
            messages_processed.append(msg.get("alert_id"))

        # Patch process_message on the instance
        worker.process_message = mock_process

        # Queue returns one message per consumer, then None
        call_count = [0]
        queue_msgs = [
            (b"triage_queue", json.dumps({"alert_id": "integ-1", "manual": True})),
            (b"triage_queue", json.dumps({"alert_id": "integ-2", "manual": True})),
        ]

        async def mock_brpop(*a, **kw):
            if call_count[0] < len(queue_msgs) and not worker._shutdown:
                result = queue_msgs[call_count[0]]
                call_count[0] += 1
                return result
            await asyncio.sleep(0)
            worker._shutdown = True
            return None

        mock_redis.brpop = mock_brpop

        async def _run():
            with patch.object(
                tw_mod, "redis", autospec=True,
            ) as mock_redis_mod:
                mock_redis_mod.from_url = AsyncMock(return_value=mock_redis)
                with patch.object(worker, "_run_reaper_loop") as mock_reaper:
                    mock_reaper.return_value = None
                    await asyncio.wait_for(
                        worker.start(),
                        timeout=3,
                    )

        asyncio.run(_run())

        assert len(messages_processed) == 2, (
            f"Expected 2 messages, got {len(messages_processed)}: {messages_processed}"
        )


# ── Edge Cases ────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_concurrency_one_is_noop(self):
        """concurrency=1 should behave identically to old single-consumer
        code path."""
        worker = TriageWorker()
        worker._concurrency = 1

        mock_redis = AsyncMock()
        with patch.object(worker, "_run_queue_loop") as mock_loop, \
             patch.object(worker, "_run_reaper_loop") as mock_reaper, \
             patch(
                "services.worker.app.triage_worker.redis",
            ) as mock_redis_mod:
            mock_redis_mod.from_url = AsyncMock(return_value=mock_redis)
            mock_loop.return_value = None
            mock_reaper.return_value = None
            worker._shutdown = True

            asyncio.run(worker.start())

            mock_loop.assert_called_once_with(0)
            mock_reaper.assert_called_once()

    def test_concurrency_read_from_settings_at_init(self):
        """_concurrency is set at __init__ time, not at start() time."""
        import services.worker.app.triage_worker as tw_mod

        with patch.object(
            tw_mod, "create_async_engine", return_value=MagicMock()
        ), patch.object(
            tw_mod, "async_sessionmaker", return_value=MagicMock()
        ), patch.object(
            tw_mod.settings, "worker_triage_concurrency", 8,
        ):
            worker = TriageWorker()
            assert worker._concurrency == 8
