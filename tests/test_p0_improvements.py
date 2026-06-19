"""Tests for the P0 improvements from the agentic-SOC roadmap.

Covers:
- DLQ consumer bounded retries + parking
- Background triage reaper for stuck pending rows
- Containment action gating via ApprovalRequest
- Semantic triage cache lookup/store
- RAG augmentation wiring in triage_worker
"""

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.worker.app.dlq_worker import DLQWorker
from services.worker.app.triage_worker import TriageWorker
from shared import triage_cache, triage_rag
from shared.models.ai_triage_result import AiTriageResult


# ────────────────────────────────
# DLQ consumer
# ────────────────────────────────

@pytest.mark.asyncio
async def test_dlq_re_enqueues_then_parks():
    worker = DLQWorker()
    worker.max_retries = 2
    worker.redis_client = AsyncMock()

    alert_id = str(uuid.uuid4())
    job = {"alert_id": alert_id, "error": "boom"}

    worker.redis_client.hget = AsyncMock(return_value="0")
    worker.redis_client.hset = AsyncMock()
    worker.redis_client.lpush = AsyncMock()

    with patch("services.worker.app.dlq_worker.asyncio.sleep"):
        await worker._handle(json.dumps(job))

    # Should have re-enqueued to triage_queue and set retry count to 1.
    worker.redis_client.hset.assert_called_once_with("triage_dlq_retries", alert_id, 1)
    lpush_calls = worker.redis_client.lpush.call_args_list
    assert any(c.args[0] == "triage_queue" for c in lpush_calls)


@pytest.mark.asyncio
async def test_dlq_parks_after_max_retries():
    worker = DLQWorker()
    worker.max_retries = 2
    worker.redis_client = AsyncMock()

    alert_id = str(uuid.uuid4())
    job = {"alert_id": alert_id, "error": "boom"}

    # Already retried twice.
    worker.redis_client.hget = AsyncMock(return_value="2")
    worker.redis_client.hset = AsyncMock()
    worker.redis_client.lpush = AsyncMock()

    await worker._handle(json.dumps(job))

    # Should park, not re-enqueue.
    worker.redis_client.hset.assert_not_called()
    lpush_calls = worker.redis_client.lpush.call_args_list
    assert any(c.args[0] == "triage_dlq_parked" for c in lpush_calls)
    assert not any(c.args[0] == "triage_queue" for c in lpush_calls)


# ────────────────────────────────
# Reaper
# ────────────────────────────────

@pytest.mark.asyncio
async def test_reaper_fails_stale_pending_rows():
    worker = TriageWorker()
    worker._shutdown = True  # cause the reaper loop to exit after one iteration
    worker.redis_client = AsyncMock()

    stale = AiTriageResult(
        alert_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        status="pending",
        success=True,
        created_at=datetime.now(timezone.utc) - timedelta(seconds=900),
    )
    fresh = AiTriageResult(
        alert_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        status="pending",
        success=True,
        created_at=datetime.now(timezone.utc) - timedelta(seconds=60),
    )

    class _Session:
        def __init__(self, rows):
            self._rows = rows
            self.committed = False

        async def execute(self, stmt):
            # Simulate the update by marking matching rows.
            for row in self._rows:
                if row.status == "pending" and row.created_at < datetime.now(timezone.utc) - timedelta(seconds=600):
                    row.status = "failed"
                    row.success = False
                    row.error_message = "Reaper: triage timed out"
            class Result:
                rowcount = sum(1 for r in self._rows if r.status == "failed")
            return Result()

        async def commit(self):
            self.committed = True

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    worker.session_factory = lambda: _Session([stale, fresh])
    await worker._reap_stale_pending()

    assert stale.status == "failed"
    assert stale.success is False
    assert fresh.status == "pending"


# ────────────────────────────────
# Containment gating
# ────────────────────────────────

@pytest.mark.asyncio
async def test_containment_guard_creates_approval_request():
    from shared.orchestrator.handlers import containment_guard

    session = AsyncMock()
    session.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=None)))
    session.flush = AsyncMock()

    tenant_id = uuid.uuid4()
    result = await containment_guard(
        session,
        tenant_id,
        "disable_user",
        {"user_id": "user-123", "alert_id": "alert-456"},
        "Compromised account",
        risk_level="high",
    )

    assert result["approved"] is False
    assert "approval_id" in result
    # ApprovalRequest was added to the session.
    assert session.add.called
    assert session.flush.called


# ────────────────────────────────
# Semantic cache
# ────────────────────────────────

@pytest.mark.asyncio
async def test_triage_cache_lookup_returns_none_when_disabled():
    alert = MagicMock()
    alert.rule_id = "rule-1"
    alert.rule_level = 5
    alert.source_ip = "10.0.0.1"
    alert.agent_id = "agent-1"
    alert.user_name = "bob"
    alert.process_name = "cmd.exe"

    with patch("shared.triage_cache.settings.triage_cache_enabled", False):
        result = await triage_cache.lookup(None, alert)
    assert result is None


def test_triage_cache_key_is_stable():
    alert = MagicMock()
    alert.rule_id = "Rule-1"
    alert.source_ip = "10.0.0.1"
    alert.agent_id = uuid.UUID("12345678-1234-1234-1234-123456789abc")
    alert.user_name = "Bob"
    alert.process_name = "cmd.exe"

    key1 = triage_cache.cache_key(alert)
    key2 = triage_cache.cache_key(alert)
    assert key1 == key2
    assert key1.startswith("triage_cache:")


@pytest.mark.asyncio
async def test_triage_cache_store_respects_skip_level():
    alert = MagicMock()
    alert.rule_level = 15  # above default skip level of 12

    with patch("shared.triage_cache.settings.triage_cache_enabled", True):
        with patch("shared.triage_cache.settings.triage_cache_skip_level", 12):
            result = await triage_cache.store(AsyncMock(), alert, {"summary": "x"})
    assert result is False


# ────────────────────────────────
# RAG wiring
# ────────────────────────────────

@pytest.mark.asyncio
async def test_triage_rag_context_disabled_when_rag_off():
    alert = MagicMock()
    alert.rule_description = "Suspicious login"
    alert.mitre_technique = "T1078"
    alert.mitre_tactic = "Initial Access"
    alert.source_ip = "10.0.0.1"
    alert.user_name = "alice"

    session = AsyncMock()
    with patch("shared.triage_rag.settings.rag_enabled", False):
        context = await triage_rag.build_triage_context(session, alert, k=3)
    assert context == ""


@pytest.mark.asyncio
async def test_triage_rag_persist_disabled_when_skill_memory_off():
    alert = MagicMock()
    alert.id = uuid.uuid4()
    verdict = {"summary": "Benign", "category": "benign"}

    session = AsyncMock()
    with patch("shared.triage_rag.settings.rag_skill_memory_enabled", False):
        result = await triage_rag.persist_triage_verdict(session, alert, verdict)
    assert result is False
