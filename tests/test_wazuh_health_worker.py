"""Tests for the Wazuh environment health worker's evaluation + snapshot build."""
from unittest.mock import AsyncMock, MagicMock

import pytest

from services.worker.app.wazuh_health_worker import WazuhHealthWorker


class _FakeSession:
    def __init__(self):
        self.added = []
        self.committed = False

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.committed = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def _worker(redis_client=None):
    w = WazuhHealthWorker(session_factory=lambda: _FakeSession(),
                          redis_client=redis_client or AsyncMock())
    return w


def test_evaluate_flags_mass_disconnect_and_red_indexer():
    w = _worker()
    agents = {"active": 10, "disconnected": 5, "never_connected": 0, "pending": 0, "total": 15}
    cluster = {"status": "ok"}
    stats = {"events_received": 100, "events_dropped": 0, "event_queue_usage": 0.1}
    status = {"all_running": True, "stopped": []}
    idx = {"status": "red", "unassigned_shards": 3}
    issues = w._evaluate(agents, cluster, stats, status, idx, lag=10)
    codes = {i["code"] for i in issues}
    assert "agents_disconnected" in codes  # 5/15 = 33% >= 20%
    assert "indexer_red" in codes
    assert any(i["severity"] == "critical" for i in issues)


def test_evaluate_healthy_environment_has_no_issues():
    w = _worker()
    agents = {"active": 20, "disconnected": 0, "never_connected": 0, "pending": 0, "total": 20}
    cluster = {"status": "ok"}
    stats = {"events_received": 500, "events_dropped": 0, "event_queue_usage": 0.05}
    status = {"all_running": True, "stopped": []}
    idx = {"status": "green", "unassigned_shards": 0}
    assert w._evaluate(agents, cluster, stats, status, idx, lag=5) == []


@pytest.mark.asyncio
async def test_publish_metrics_writes_redis_keys():
    redis_client = AsyncMock()
    w = _worker(redis_client=redis_client)
    snap = MagicMock()
    snap.indexer_status = "yellow"
    snap.agents_disconnected = 4
    snap.agents_active = 16
    snap.analysisd_eps = 123.0
    snap.ingestion_lag_seconds = 30.0
    snap.self_poller_lag_seconds = 12.0
    await w._publish_metrics(snap)
    written = {call.args[0] for call in redis_client.set.await_args_list}
    assert "wazuh_agents_disconnected" in written
    assert "wazuh_cluster_status_code" in written
