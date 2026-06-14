import uuid
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from services.worker.app.credential_leak_worker import CredentialLeakWorker
from shared.models.credential_leak import CredentialLeak


@pytest.mark.asyncio
async def test_upsert_leak_skips_duplicates():
    worker = CredentialLeakWorker()
    worker.engine = MagicMock()

    existing_leak = CredentialLeak(
        tenant_id=uuid.uuid4(),
        target="user@example.com",
        target_type="email",
        breach_name="TestBreach",
        breach_date="2023-01-01",
    )

    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_leak
    mock_session.execute = AsyncMock(return_value=mock_result)

    breach = {"Name": "TestBreach", "BreachDate": "2023-01-01", "DataClasses": ["Email"]}
    await worker._upsert_leak(mock_session, "user@example.com", "email", breach)

    mock_session.execute.assert_awaited_once()
    mock_session.add.assert_not_awaited()


@pytest.mark.asyncio
async def test_upsert_leak_adds_new():
    worker = CredentialLeakWorker()
    worker.engine = MagicMock()

    added = []

    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute = AsyncMock(return_value=mock_result)
    mock_session.add = lambda obj: added.append(obj)

    breach = {"Name": "NewBreach", "BreachDate": "2023-06-01", "DataClasses": ["Email", "Password"]}
    await worker._upsert_leak(mock_session, "user@example.com", "email", breach)

    assert len(added) == 1
    leak = added[0]
    assert isinstance(leak, CredentialLeak)
    assert leak.target == "user@example.com"
    assert leak.breach_name == "NewBreach"
    assert leak.compromised_data == ["Email", "Password"]


@pytest.mark.asyncio
async def test_query_hibp_returns_empty_without_api_key():
    worker = CredentialLeakWorker()
    worker.engine = MagicMock()

    with patch.object(CredentialLeakWorker, "__init__", lambda s: None):
        with patch("services.worker.app.credential_leak_worker.settings") as mock_settings:
            mock_settings.credential_leak_hibp_api_key = None
            result = await worker._query_hibp("breachedaccount/test@example.com")

    assert result == []


@pytest.mark.asyncio
async def test_query_hibp_returns_breaches():
    worker = CredentialLeakWorker()
    worker.engine = MagicMock()

    breach_data = [{"Name": "Breach1"}, {"Name": "Breach2"}]

    with patch("services.worker.app.credential_leak_worker.settings") as mock_settings:
        mock_settings.credential_leak_hibp_api_key = MagicMock()
        mock_settings.credential_leak_hibp_api_key.get_secret_value.return_value = "test-key"

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = breach_data
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("services.worker.app.credential_leak_worker.httpx.AsyncClient", return_value=mock_client):
            result = await worker._query_hibp("breachedaccount/test@example.com")

    assert result == breach_data
