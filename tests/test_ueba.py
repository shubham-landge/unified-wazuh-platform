import math
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestWelfordBaseline:
    def _make_baseline(self, n=0, mean=0.0, m2=0.0):
        from shared.models.ueba import UebaBaseline
        bl = UebaBaseline(
            subject_type="user", subject_id="alice", metric_name="alert_count"
        )
        bl.n = n
        bl.mean = mean
        bl.m2 = m2
        return bl

    def test_stddev_zero_samples(self):
        from shared.ueba.baseline import _stddev
        bl = self._make_baseline(n=0)
        assert _stddev(bl) == 0.0

    def test_stddev_one_sample(self):
        from shared.ueba.baseline import _stddev
        bl = self._make_baseline(n=1, mean=5.0, m2=0.0)
        assert _stddev(bl) == 0.0

    def test_stddev_known_values(self):
        from shared.ueba.baseline import _stddev
        bl = self._make_baseline(n=8, mean=5.0, m2=32.0)
        assert abs(_stddev(bl) - math.sqrt(32 / 7)) < 1e-6

    def test_z_score_zero_stddev(self):
        from shared.ueba.baseline import compute_z_score
        bl = self._make_baseline(n=1, mean=5.0, m2=0.0)
        assert compute_z_score(bl, 10.0) == 0.0

    def test_z_score_positive_anomaly(self):
        from shared.ueba.baseline import compute_z_score
        bl = self._make_baseline(n=10, mean=2.0, m2=9.0)
        z = compute_z_score(bl, 5.0)
        assert abs(z - 3.0) < 0.01

    async def test_update_baseline_creates_new(self):
        from shared.ueba.baseline import update_baseline
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none = MagicMock(return_value=None)
        mock_session.execute = AsyncMock(return_value=mock_result)

        bl = await update_baseline(mock_session, "user", "bob", "alert_count", 1.0)
        assert bl.n == 1
        assert bl.mean == 1.0
        mock_session.add.assert_called_once()

    async def test_update_baseline_updates_existing(self):
        from shared.ueba.baseline import update_baseline
        from shared.models.ueba import UebaBaseline

        existing = UebaBaseline(
            subject_type="user", subject_id="alice", metric_name="alert_count"
        )
        existing.n = 4
        existing.mean = 2.0
        existing.m2 = 3.0

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none = MagicMock(return_value=existing)
        mock_session.execute = AsyncMock(return_value=mock_result)

        bl = await update_baseline(mock_session, "user", "alice", "alert_count", 4.0)
        assert bl.n == 5
        assert bl.mean == pytest.approx(2.4)


class TestUEBADetector:
    def _make_alert(self, user="alice", agent="server01", rule_level=7):
        from shared.models.alert import Alert
        a = Alert(rule_description="Test alert", rule_level=rule_level)
        a.user_name = user
        a.agent_name = agent
        a.source_ip = "10.0.0.1"
        a.mitre_tactic = None
        return a

    async def test_process_alert_returns_list(self):
        from shared.ueba.detector import process_alert
        from shared.models.ueba import UebaBaseline

        baseline = UebaBaseline(
            subject_type="user", subject_id="alice", metric_name="alert_count"
        )
        baseline.n = 10
        baseline.mean = 1.0
        baseline.m2 = 5.0

        mock_result = MagicMock()
        mock_result.scalar_one_or_none = MagicMock(return_value=baseline)
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=mock_result)

        alert = self._make_alert()
        anomalies = await process_alert(mock_session, alert, tenant_id=None)
        assert isinstance(anomalies, list)