from unittest.mock import AsyncMock, patch, MagicMock
import pytest
from services.api.app.routers.metrics import metrics

@pytest.mark.asyncio
async def test_modern_soc_metrics():
    db = AsyncMock()
    mock_val = MagicMock()
    mock_val.scalar.return_value = 1
    db.execute.return_value = mock_val
    
    mock_redis = MagicMock()
    mock_redis.get.side_effect = lambda k: "10"
    
    with patch("services.api.app.routers.metrics.settings") as mock_settings:
        mock_settings.redis_url = "redis://localhost:6379/0"
        with patch("redis.from_url", return_value=mock_redis):
            res = await metrics(db=db, _="key")
            assert res.status_code == 200
            content = res.body.decode()
            assert "soc_incident_mttd_seconds" in content
            assert "soc_incident_mttr_seconds" in content
            assert "soc_time_to_full_enrichment_seconds" in content
            assert "soc_breakout_incidents_total" in content
