from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from services.worker.app.sigma_worker import SigmaWorker


class FakeResult:
    def __init__(self, row=None):
        self._row = row

    def scalar_one_or_none(self):
        return self._row


class FakeSession:
    def __init__(self):
        self.added = []
        self.committed = False

    async def execute(self, *args, **kwargs):
        return FakeResult(None)

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.committed = True


class FakeCtx:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, exc_type, exc, tb):
        return False


@pytest.mark.asyncio
async def test_compile_sigma_rule(tmp_path):
    worker = SigmaWorker(rules_dir=str(tmp_path), interval_seconds=1, session_factory=FakeCtx(FakeSession()))
    rule = {
        "title": "Suspicious PowerShell",
        "id": "1001",
        "level": "high",
        "detection": {
            "selection": {
                "EventID": 1,
                "CommandLine|contains": "powershell",
            },
            "condition": "selection",
        },
    }
    query = worker.compile_rule(rule)
    assert query["query"]["bool"]["filter"]


@pytest.mark.asyncio
async def test_scan_once_creates_alert(tmp_path, monkeypatch):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "rule.yml").write_text(
        """
title: Suspicious PowerShell
id: 1001
level: high
detection:
  selection:
    EventID: 1
    CommandLine|contains: powershell
  condition: selection
"""
    )
    session = FakeSession()
    worker = SigmaWorker(rules_dir=str(rules_dir), interval_seconds=1, session_factory=FakeCtx(session))
    hit = {
        "_id": "hit-1",
        "_source": {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": {"id": "001", "name": "server-1", "ip": "10.0.0.10"},
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "10.0.0.6"},
            "user": {"name": "alice"},
            "process": {"name": "powershell.exe"},
            "event_id": "1",
        },
    }
    worker._search_indexer = AsyncMock(return_value=[hit])
    result = await worker.scan_once()
    assert result["matches"] == 1
    assert session.committed is True
    assert session.added
    assert session.added[0].wazuh_alert_id.startswith("sigma:1001:")
