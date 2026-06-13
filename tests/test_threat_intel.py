"""Tests for threat intel connectors — OTX, MISP, VirusTotal."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.fixture
def otx():
    from shared.connectors.ti_alienvault import AlienVaultOTXConnector
    return AlienVaultOTXConnector(api_key="test_otx_key")


@pytest.fixture
def misp():
    from shared.connectors.ti_misp import MISPConnector
    return MISPConnector(base_url="https://misp.local", api_key="test_misp_key")


@pytest.fixture
def vt():
    from shared.connectors.ti_virustotal import VirusTotalConnector
    return VirusTotalConnector(api_key="test_vt_key")


class TestAlienVaultOTX:
    async def test_lookup_found(self, otx):
        mock_data = {
            "pulse_info": {
                "count": 3,
                "pulses": [
                    {"malware_families": [{"display_name": "Emotet"}], "tags": ["botnet", "banking"]},
                    {"malware_families": [], "tags": ["c2"]},
                ],
            }
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value=mock_data)

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            result = await otx.lookup("ip", "1.2.3.4")

        assert result["found"] is True
        assert result["source"] == "otx"
        assert result["pulse_count"] == 3
        assert "Emotet" in result["malware_families"]

    async def test_lookup_not_found(self, otx):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            result = await otx.lookup("ip", "10.0.0.1")

        assert result["found"] is False

    async def test_no_api_key(self):
        from shared.connectors.ti_alienvault import AlienVaultOTXConnector
        result = await AlienVaultOTXConnector(api_key="").lookup("ip", "1.2.3.4")
        assert result["found"] is False
        assert "not configured" in result["error"]

    def test_unsupported_type(self, otx):
        import asyncio
        result = asyncio.get_event_loop().run_until_complete(otx.lookup("unknown_type", "val"))
        assert result["found"] is False


class TestMISP:
    async def test_search_found(self, misp):
        mock_data = {
            "response": {
                "Attribute": [
                    {
                        "value": "1.2.3.4",
                        "type": "ip-src",
                        "event_id": "123",
                        "Tag": [{"name": "tlp:red"}, {"name": "malware"}],
                        "Event": {"threat_level_id": "1"},
                    }
                ]
            }
        }
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value=mock_data)

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            result = await misp.search("ip", "1.2.3.4")

        assert result["found"] is True
        assert result["source"] == "misp"
        assert "tlp:red" in result["tags"]

    async def test_search_empty_result(self, misp):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={"response": {"Attribute": []}})

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            result = await misp.search("ip", "10.0.0.1")

        assert result["found"] is False


class TestVirusTotal:
    async def test_lookup_malicious(self, vt):
        mock_data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 45, "suspicious": 2, "undetected": 10, "harmless": 0},
                    "last_analysis_results": {
                        "engine1": {"category": "malicious", "result": "Trojan.Generic"},
                        "engine2": {"category": "malicious", "result": "Emotet"},
                    },
                    "reputation": -85,
                    "tags": ["trojan", "banker"],
                }
            }
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value=mock_data)

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            result = await vt.lookup("hash_sha256", "abc123" * 10)

        assert result["found"] is True
        assert result["malicious_engines"] == 45
        assert result["threat_score"] > 50

    async def test_lookup_clean(self, vt):
        mock_data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 5, "harmless": 65},
                    "last_analysis_results": {},
                    "reputation": 0,
                    "tags": [],
                }
            }
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value=mock_data)

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            result = await vt.lookup("hash_sha256", "abc123" * 10)

        assert result["found"] is False

    async def test_rate_limit_handled(self, vt):
        mock_resp = MagicMock()
        mock_resp.status_code = 429

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            result = await vt.lookup("ip", "1.2.3.4")

        assert result["found"] is False
        assert "Rate limit" in result["error"]
