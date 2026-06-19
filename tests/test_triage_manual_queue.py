"""Manual-Analyze path: API enqueues, worker updates the existing row + force_fast.

These tests exercise the worker's manual branch without a real DB/LLM by stubbing
the session, provider, and noise gate.
"""
import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.worker.app.triage_worker import TriageWorker


class _Result:
    def __init__(self, row):
        self._row = row

    def scalar_one_or_none(self):
        return self._row


class _Session:
    def __init__(self, alert, existing_row):
        self._alert = alert
        self._existing = existing_row
        self.added = []
        self.committed = False

    async def execute(self, *a, **k):
        return _Result(self._alert)

    async def get(self, model, pk):
        return self._existing

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        pass

    async def commit(self):
        self.committed = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def _alert():
    a = MagicMock()
    a.id = uuid.uuid4()
    a.tenant_id = uuid.uuid4()
    a.rule_description = "Test rule"
    a.rule_level = 5
    a.rule_groups = []
    return a


@pytest.mark.asyncio
async def test_manual_triage_forces_fast_and_updates_existing_row():
    alert = _alert()
    existing = MagicMock()  # the pending row the API created
    session = _Session(alert, existing)

    worker = TriageWorker()
    worker.session_factory = lambda: session
    worker.redis_client = AsyncMock()

    captured = {}

    async def fake_get_provider(**kwargs):
        captured["force_fast"] = kwargs.get("force_fast")
        prov = MagicMock()
        prov.name.return_value = "ollama/qwen2.5:3b-instruct"
        prov.analyze = AsyncMock(return_value={"success": True, "summary": "ok",
                                               "severity": "low", "confidence": 0.4})
        return prov

    triage_id = str(uuid.uuid4())
    with patch("services.worker.app.triage_worker.TieredRouter") as MockRouter:
        MockRouter.return_value.get_provider = fake_get_provider
        await worker.process_message({
            "alert_id": str(alert.id),
            "triage_id": triage_id,
            "manual": True,
            "force_fast": True,
        })

    # force_fast propagated to the router, and the existing row was updated (not a new insert).
    assert captured["force_fast"] is True
    assert existing.status == "completed"
    assert existing.severity == "low"
    assert session.committed is True


@pytest.mark.asyncio
async def test_manual_triage_skips_noise_gate():
    alert = _alert()
    session = _Session(alert, MagicMock())
    worker = TriageWorker()
    worker.session_factory = lambda: session
    worker.redis_client = AsyncMock()

    async def fake_get_provider(**kwargs):
        prov = MagicMock()
        prov.name.return_value = "ollama/qwen2.5:3b-instruct"
        prov.analyze = AsyncMock(return_value={"success": True})
        return prov

    with patch("services.worker.app.triage_worker.TieredRouter") as MockRouter, \
         patch("services.worker.app.triage_worker.noise_reduction.evaluate") as gate:
        MockRouter.return_value.get_provider = fake_get_provider
        await worker.process_message({
            "alert_id": str(alert.id),
            "triage_id": str(uuid.uuid4()),
            "manual": True,
            "force_fast": True,
        })
        gate.assert_not_called()  # noise gate bypassed for manual requests
