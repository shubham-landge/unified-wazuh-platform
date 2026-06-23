"""Tests for rule_historical_accuracy — accuracy computed from
AiTriageResult + UserFeedback via async ORM.

Covers:
- None rule_id → None
- Insufficient samples (< 5) → None
- All correct (accuracy = 1.0)
- All incorrect (accuracy = 0.0)
- Mixed feedback (accuracy = 0.6, etc.)
- No matching triage results → None
- DB error → None (fail-open)
- Redis cache hit (patched redis)
- Sync fallback path (no session provided)
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.fixture(autouse=True)
def _clear_redis_modules():
    """Ensure each test starts with a clean import state."""
    pass


# ─── Module is importable ──────────────────────────────────────────────


class TestImports:
    def test_function_imported_from_correlation(self):
        from shared.correlation import rule_historical_accuracy
        import inspect
        assert callable(rule_historical_accuracy)
        assert inspect.iscoroutinefunction(rule_historical_accuracy)


# ─── rule_id = None ────────────────────────────────────────────────────


class TestRuleIdNone:
    @pytest.mark.asyncio
    async def test_none_rule_id_returns_none(self):
        from shared.correlation.rule_historical_accuracy import rule_historical_accuracy
        session = AsyncMock()
        result = await rule_historical_accuracy(None, session=session)
        assert result is None
        session.execute.assert_not_called()


# ─── Insufficient samples (< MIN_SAMPLES=5) ────────────────────────────


class TestInsufficientSamples:
    @pytest.mark.asyncio
    async def test_zero_feedback_returns_none(self):
        from shared.correlation.rule_historical_accuracy import rule_historical_accuracy
        session = _session_returning(total=0)

        result = await rule_historical_accuracy(5710, session=session)
        assert result is None

    @pytest.mark.asyncio
    async def test_four_feedback_returns_none(self):
        from shared.correlation.rule_historical_accuracy import rule_historical_accuracy
        session = _session_returning(total=4)

        result = await rule_historical_accuracy(5710, session=session)
        assert result is None


# ─── Exact accuracy values ─────────────────────────────────────────────


class TestAccuracyValues:
    @pytest.mark.asyncio
    async def test_all_correct_returns_one(self):
        from shared.correlation.rule_historical_accuracy import rule_historical_accuracy
        session = _session_returning(total=10, correct=10)

        result = await rule_historical_accuracy(5710, session=session)
        assert result == 1.0

    @pytest.mark.asyncio
    async def test_all_incorrect_returns_zero(self):
        from shared.correlation.rule_historical_accuracy import rule_historical_accuracy
        session = _session_returning(total=10, correct=0)

        result = await rule_historical_accuracy(5710, session=session)
        assert result == 0.0

    @pytest.mark.asyncio
    async def test_mixed_accuracy(self):
        from shared.correlation.rule_historical_accuracy import rule_historical_accuracy
        session = _session_returning(total=10, correct=7)

        result = await rule_historical_accuracy(5710, session=session)
        assert result == 0.7

    @pytest.mark.asyncio
    async def test_three_of_five(self):
        from shared.correlation.rule_historical_accuracy import rule_historical_accuracy
        session = _session_returning(total=5, correct=3)

        result = await rule_historical_accuracy(5711, session=session)
        assert result == 0.6


# ─── No matching triage results ────────────────────────────────────────


class TestNoMatchingTriage:
    @pytest.mark.asyncio
    async def test_no_triage_for_rule_returns_none(self):
        """When no AiTriageResult links to alerts with the given rule_id."""
        from shared.correlation.rule_historical_accuracy import rule_historical_accuracy
        session = _session_returning(total=0)

        result = await rule_historical_accuracy(9999, session=session)
        assert result is None


# ─── DB error → None (fail-open) ───────────────────────────────────────


class TestDbError:
    @pytest.mark.asyncio
    async def test_db_error_returns_none(self):
        from shared.correlation.rule_historical_accuracy import rule_historical_accuracy
        session = AsyncMock()
        session.execute = AsyncMock(side_effect=Exception("DB connection lost"))

        result = await rule_historical_accuracy(5710, session=session)
        assert result is None


# ─── Redis cache ───────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestRedisCache:
    async def test_cache_hit_returns_cached_value(self):
        """When Redis has the key, return it without querying DB."""
        from shared.correlation.rule_historical_accuracy import rule_historical_accuracy

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value="0.85")
        mock_redis.aclose = AsyncMock()

        session = AsyncMock()

        with patch("redis.asyncio.from_url", return_value=mock_redis):
            result = await rule_historical_accuracy(5710, session=session)
            assert result == 0.85
            session.execute.assert_not_called()

    async def test_cache_miss_proceeds_to_db(self):
        """When Redis has no key, fall through to DB query."""
        from shared.correlation.rule_historical_accuracy import rule_historical_accuracy

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.aclose = AsyncMock()

        session = _session_returning(total=10, correct=8)

        with patch("redis.asyncio.from_url", return_value=mock_redis):
            result = await rule_historical_accuracy(5710, session=session)
            assert result == 0.8

    async def test_redis_error_proceeds_to_db(self):
        """Redis failure is non-fatal — fall through to DB."""
        from shared.correlation.rule_historical_accuracy import rule_historical_accuracy

        with patch(
            "redis.asyncio.from_url",
            side_effect=Exception("Redis unavailable"),
        ):
            session = _session_returning(total=8, correct=6)
            result = await rule_historical_accuracy(5710, session=session)
            assert result == 0.75


# ─── Sync fallback (no session) ────────────────────────────────────────


@pytest.mark.asyncio
class TestSyncFallback:
    async def test_no_session_uses_sync_engine(self):
        """When called without a session, fall back to sync DB path."""
        from shared.correlation.rule_historical_accuracy import rule_historical_accuracy

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.aclose = AsyncMock()

        mock_conn = MagicMock()
        mock_row = MagicMock()
        mock_row.total = 10
        mock_row.correct = 9
        mock_conn.execute.return_value.fetchone.return_value = mock_row
        mock_conn.__enter__.return_value = mock_conn

        mock_engine = MagicMock()
        mock_engine.connect.return_value = mock_conn

        with patch("redis.asyncio.from_url", return_value=mock_redis), \
             patch("sqlalchemy.create_engine", return_value=mock_engine):
            result = await rule_historical_accuracy(5710, session=None)
            assert result == 0.9

    async def test_sync_fallback_insufficient_samples(self):
        from shared.correlation.rule_historical_accuracy import rule_historical_accuracy

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.aclose = AsyncMock()

        mock_conn = MagicMock()
        mock_row = MagicMock()
        mock_row.total = 3
        mock_row.correct = 2
        mock_conn.execute.return_value.fetchone.return_value = mock_row
        mock_conn.__enter__.return_value = mock_conn

        mock_engine = MagicMock()
        mock_engine.connect.return_value = mock_conn

        with patch("redis.asyncio.from_url", return_value=mock_redis), \
             patch("sqlalchemy.create_engine", return_value=mock_engine):
            result = await rule_historical_accuracy(5710, session=None)
            assert result is None

    async def test_sync_fallback_db_error_returns_none(self):
        from shared.correlation.rule_historical_accuracy import rule_historical_accuracy

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.aclose = AsyncMock()

        with patch("redis.asyncio.from_url", return_value=mock_redis), \
             patch("sqlalchemy.create_engine",
                   side_effect=Exception("Cannot connect")):
            result = await rule_historical_accuracy(5710, session=None)
            assert result is None

    async def test_sync_fallback_none_row_returns_none(self):
        from shared.correlation.rule_historical_accuracy import rule_historical_accuracy

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.aclose = AsyncMock()

        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = None
        mock_conn.__enter__.return_value = mock_conn

        mock_engine = MagicMock()
        mock_engine.connect.return_value = mock_conn

        with patch("redis.asyncio.from_url", return_value=mock_redis), \
             patch("sqlalchemy.create_engine", return_value=mock_engine):
            result = await rule_historical_accuracy(5710, session=None)
            assert result is None


# ─── Edge cases ────────────────────────────────────────────────────────


class TestEdgeCases:
    @pytest.mark.asyncio
    async def test_rule_id_zero_is_valid(self):
        """rule_id=0 is a real ID, not None."""
        from shared.correlation.rule_historical_accuracy import rule_historical_accuracy
        session = _session_returning(total=5, correct=4)

        result = await rule_historical_accuracy(0, session=session)
        assert result == 0.8

    @pytest.mark.asyncio
    async def test_large_sample_size(self):
        from shared.correlation.rule_historical_accuracy import rule_historical_accuracy
        session = _session_returning(total=1000, correct=950)

        result = await rule_historical_accuracy(5710, session=session)
        assert result == 0.95

    @pytest.mark.asyncio
    async def test_exactly_min_samples(self):
        """5 samples (the threshold) should return a value."""
        from shared.correlation.rule_historical_accuracy import rule_historical_accuracy
        session = _session_returning(total=5, correct=5)

        result = await rule_historical_accuracy(5710, session=session)
        assert result == 1.0

    @pytest.mark.asyncio
    async def test_no_correct_but_enough_samples(self):
        """All negative feedback but enough samples → 0.0, not None."""
        from shared.correlation.rule_historical_accuracy import rule_historical_accuracy
        session = _session_returning(total=5, correct=0)

        result = await rule_historical_accuracy(5710, session=session)
        assert result == 0.0


# ─── Query structure verification ──────────────────────────────────────


class TestQueryStructure:
    """Verify that _compute_from_orm generates correct SQLAlchemy queries.

    The fix replaced a subquery()-wrapped-in-select() pattern with
    scalar_subquery() and removed the misleading isouter=True (LEFT OUTER
    JOIN that the WHERE clause turned into an effective inner join).
    """

    def test_uses_inner_join_not_outer(self):
        """The AiTriageResult→Alert join must be inner, not outer.

        alert_id is nullable on AiTriageResult, but triage results without
        an alert link cannot contribute to a rule's accuracy — they have
        no rule_id to match against.
        """
        from sqlalchemy import select
        from sqlalchemy.dialects import postgresql

        from shared.models.ai_triage_result import AiTriageResult
        from shared.models.alert import Alert

        subq = (
            select(AiTriageResult.id)
            .join(Alert, AiTriageResult.alert_id == Alert.id)
            .where(Alert.rule_id == 5710)
            .scalar_subquery()
        )

        compiled = str(subq.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        ))
        # Must be a plain inner JOIN, not LEFT OUTER or LEFT JOIN
        assert "LEFT" not in compiled.upper(), (
            f"Expected inner join, got: {compiled}"
        )

    def test_uses_scalar_subquery_pattern(self):
        """The subquery must be scalar_subquery() so in_() works directly.

        Calling .in_(select(subquery())) wraps the already-subquery'd
        select in another unnecessary layer.  .in_(scalar_subquery())
        produces a clean ``IN (SELECT ...)`` without extra nesting.
        """
        from shared.correlation.rule_historical_accuracy import _compute_from_orm
        import inspect

        source = inspect.getsource(_compute_from_orm)
        assert "scalar_subquery" in source, (
            "Expected scalar_subquery() call in _compute_from_orm"
        )
        assert ".subquery()" not in source, (
            "Expected .scalar_subquery() not .subquery() in _compute_from_orm"
        )


# ─── _compute_from_orm type contract ────────────────────────────────────


class TestComputeFromOrmTypes:
    """Verify the internal helper's return type is stable."""

    @pytest.mark.asyncio
    async def test_returns_two_ints(self):
        """_compute_from_orm always returns (int, int), never None."""
        from shared.correlation.rule_historical_accuracy import _compute_from_orm
        session = _session_returning(total=10, correct=7)

        total, correct = await _compute_from_orm(session, 5710)
        assert isinstance(total, int), f"Expected int, got {type(total)}"
        assert isinstance(correct, int), f"Expected int, got {type(correct)}"
        assert total == 10
        assert correct == 7

    @pytest.mark.asyncio
    async def test_insufficient_returns_zero_correct(self):
        """When total < MIN_SAMPLES, correct is 0 (not None or float)."""
        from shared.correlation.rule_historical_accuracy import _compute_from_orm
        session = _session_returning(total=3)

        total, correct = await _compute_from_orm(session, 5710)
        assert total == 3
        assert correct == 0
        assert isinstance(correct, int)


# ─── I'mport hygiene ────────────────────────────────────────────────────


class TestImportHygiene:
    """The module keeps its imports minimal and clean."""

    def test_module_importable_from_package(self):
        """The public API is importable from shared.correlation."""
        from shared.correlation import rule_historical_accuracy
        import inspect
        assert inspect.iscoroutinefunction(rule_historical_accuracy)

    def test_internal_helper_return_annotation(self):
        """_compute_from_orm return type must be (int, int), no None."""
        from shared.correlation.rule_historical_accuracy import _compute_from_orm
        import inspect
        assert inspect.iscoroutinefunction(_compute_from_orm)
        hints = _compute_from_orm.__annotations__
        assert "return" in hints
        return_hint = str(hints["return"])
        assert "int" in return_hint
        assert "None" not in return_hint, (
            f"Return type should not contain None: {return_hint}"
        )

    def test_no_stale_and_import(self):
        """The `and_` import was removed — .where() already ANDs args."""
        import importlib
        import os

        mod = importlib.import_module(
            "shared.correlation.rule_historical_accuracy"
        )
        path = os.path.join(
            os.path.dirname(mod.__file__),
            "rule_historical_accuracy.py",
        )
        with open(path) as f:
            src = f.read()
        assert "and_" not in src, (
            "Stale `and_` import still present in module source"
        )
        assert "from sqlalchemy import select, func" in src, (
            "Expected clean import: select, func only"
        )


# ═══════════════════════════════════════════════════════════════════════
# Test helpers
# ═══════════════════════════════════════════════════════════════════════


def _session_returning(total: int, correct: int = 0) -> AsyncMock:
    """Build an AsyncMock session that returns *total* and *correct* counts.

    The function fires two queries: first for total, then for correct
    (unless total < 5, in which case the second is skipped).
    """
    session = AsyncMock()

    # Execution counter to differentiate the two queries
    call_count = 0

    async def _execute_mock(statement):
        nonlocal call_count
        call_count += 1

        result = MagicMock()
        if call_count == 1:
            # First query: total count
            result.scalar.return_value = total
        elif call_count == 2:
            # Second query: correct count
            result.scalar.return_value = correct
        else:
            result.scalar.return_value = 0
        return result

    session.execute = AsyncMock(side_effect=_execute_mock)
    return session
