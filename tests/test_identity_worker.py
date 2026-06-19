import uuid
from types import SimpleNamespace

import pytest

from services.worker.app.identity_worker import IdentityWorker


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


class FakeConnector:
    def __init__(self, data):
        self._data = data

    async def get_signins(self):
        return self._data.get("signins", [])

    async def get_audit_logs(self):
        return self._data.get("audits", [])

    async def get_risky_signins(self):
        return self._data.get("risky_signins", [])

    async def get_risky_users(self):
        return self._data.get("risky_users", [])

    async def get_oauth_grants(self):
        return self._data.get("oauth", [])

    async def get_events(self):
        return self._data.get("events", [])


@pytest.mark.asyncio
async def test_identity_worker_emits_risky_signin_alert():
    session = FakeSession()
    _TENANT = uuid.UUID("00000000-0000-0000-0000-000000000001")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "services.worker.app.identity_worker.IdentityWorker._resolve_tenant_id",
            staticmethod(lambda: _TENANT),
        )
        worker = IdentityWorker(
            interval_seconds=1,
            session_factory=FakeCtx(session),
            entra=FakeConnector(
                {
                    "signins": [
                        {
                            "userPrincipalName": "alice@example.com",
                            "riskLevelAggregated": "high",
                            "ipAddress": "1.2.3.4",
                        }
                    ]
                }
            ),
        )
    result = await worker.scan_once()
    assert result["success"] is True
    assert result["created"] == 1
    assert session.committed is True
    assert session.added[0].user_name == "alice@example.com"
    assert session.added[0].event_type == "identity"


@pytest.mark.asyncio
async def test_identity_worker_detects_oauth_consent():
    session = FakeSession()
    _TENANT = uuid.UUID("00000000-0000-0000-0000-000000000001")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "services.worker.app.identity_worker.IdentityWorker._resolve_tenant_id",
            staticmethod(lambda: _TENANT),
        )
        worker = IdentityWorker(
            interval_seconds=1,
            session_factory=FakeCtx(session),
            o365=FakeConnector(
                {
                    "audits": [
                        {"activity": "OAuth Consent Granted", "user": "bob@example.com"}
                    ]
                }
            ),
        )
    result = await worker.scan_once()
    assert result["created"] == 1
    assert session.added[0].rule_description.lower().startswith("illicit oauth consent") or session.added[0].rule_description.lower().startswith("illicit")

