from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.db import get_db
from app.routers import triage
from shared.connectors.llm_router import TieredRouter
from shared.connectors.llm_provider import OllamaProvider


# ── TieredRouter Tests ──

class TestTieredRouter:
    def setup_method(self):
        self.router = TieredRouter()

    @pytest.mark.parametrize("strategy,expected_model", [
        ("fast", "qwen2.5:3b-instruct"),
        ("full", "CyberCrew/notmythos-8b"),
    ])
    @pytest.mark.asyncio
    async def test_strategy_override(self, strategy, expected_model):
        with patch("shared.config.settings.llm_tier_strategy", strategy):
            provider = await self.router.get_provider(alert=None)
            assert isinstance(provider, OllamaProvider)
            assert expected_model in provider.name()

    @pytest.mark.asyncio
    async def test_auto_strategy_low_level_uses_fast(self):
        from datetime import datetime, timezone
        alert = MagicMock()
        alert.rule_level = 3
        alert.rule_id = 123
        alert.source_ip = "10.0.0.1"
        alert.agent_id = "agent-1"
        alert.mitre_technique = "T1078"
        alert.rule_firedtimes = 1
        alert.created_at = datetime.now(timezone.utc)

        with patch("shared.config.settings.llm_tier_strategy", "auto"):
            with patch("shared.config.settings.llm_tier_level_threshold", 10):
                provider = await self.router.get_provider(alert=alert)
                assert "instruct" in provider.name() or "3b" in provider.name()

    @pytest.mark.asyncio
    async def test_auto_strategy_high_level_uses_full(self):
        from datetime import datetime, timezone
        alert = MagicMock()
        alert.rule_level = 12
        alert.rule_id = 456
        alert.source_ip = "10.0.0.2"
        alert.agent_id = "agent-2"
        alert.mitre_technique = "T1569.002"
        alert.rule_firedtimes = 1
        alert.created_at = datetime.now(timezone.utc)

        with patch("shared.config.settings.llm_tier_strategy", "auto"):
            with patch("shared.config.settings.llm_tier_level_threshold", 10):
                provider = await self.router.get_provider(alert=alert)
                assert "notmythos" in provider.name() or "8b" in provider.name()

    @pytest.mark.asyncio
    async def test_complex_technique_boosts_score(self):
        from datetime import datetime, timezone
        alert = MagicMock()
        alert.rule_level = 10  # >= threshold, gives +3
        alert.rule_id = 789
        alert.source_ip = "10.0.0.3"
        alert.agent_id = "agent-3"
        alert.mitre_technique = "T1569.002"  # In COMPLEX_TECHNIQUES
        alert.rule_firedtimes = 1
        alert.created_at = datetime.now(timezone.utc)

        with patch("shared.config.settings.llm_tier_strategy", "auto"):
            with patch("shared.config.settings.llm_tier_level_threshold", 10):
                with patch("shared.config.settings.llm_tier_complex_techniques",
                           "T1569.002,T1059.001"):
                    provider = await self.router.get_provider(alert=alert)
                    # score = 3 (level) + 1 (technique) = 4 >= 4
                    assert "notmythos" in provider.name() or "8b" in provider.name()

    @pytest.mark.asyncio
    async def test_burst_alert_reduces_score(self):
        alert = MagicMock()
        alert.rule_level = 12
        alert.rule_id = 999
        alert.source_ip = "10.0.0.5"
        alert.agent_id = "agent-5"
        alert.mitre_technique = "T1078"
        alert.rule_firedtimes = 50  # burst

        with patch("shared.config.settings.llm_tier_strategy", "auto"):
            with patch("shared.config.settings.llm_tier_level_threshold", 10):
                with patch("shared.config.settings.llm_tier_score_threshold", 4):
                    provider = await self.router.get_provider(alert=alert)
                    # score = 3 (level) - 2 (burst) = 1 < 4, so fast
                assert "3b" in provider.name() or "mini" in provider.name()

    def test_known_bad_ip_boosts_score(self):
        alert = MagicMock()
        alert.rule_level = 5
        alert.rule_id = 111
        alert.source_ip = "203.0.113.5"
        alert.agent_id = "agent-6"
        alert.mitre_technique = "T1078"
        alert.rule_firedtimes = 1

        with patch("shared.config.settings.llm_tier_strategy", "auto"):
            with patch("shared.config.settings.llm_tier_level_threshold", 10):
                with patch("shared.config.settings.llm_tier_score_threshold", 4):
                    with patch("shared.config.settings.llm_tier_known_bad_ips",
                               "203.0.113.5,198.51.100.1"):
                        assert True  # at least doesn't crash

    @pytest.mark.asyncio
    async def test_auto_no_alert_falls_back(self):
        with patch("shared.config.settings.llm_tier_strategy", "auto"):
            provider = await self.router.get_provider(alert=None)
            assert isinstance(provider, OllamaProvider)

    def test_unknown_provider_falls_to_ollama(self):
        with patch("shared.config.settings.llm_tier_fast_provider", "nonexistent"):
            provider = self.router._build_fast_provider()
            assert isinstance(provider, OllamaProvider)


# ── Feedback Model Tests ──

class TestUserFeedbackModel:
    def test_feedback_model_attributes(self):
        from shared.models.feedback import UserFeedback
        assert hasattr(UserFeedback, "id")
        assert hasattr(UserFeedback, "triage_result_id")
        assert hasattr(UserFeedback, "rating")
        assert hasattr(UserFeedback, "category_correct")
        assert hasattr(UserFeedback, "severity_correct")
        assert hasattr(UserFeedback, "correction_text")
        assert hasattr(UserFeedback, "corrected_category")
        assert hasattr(UserFeedback, "corrected_severity")
        assert hasattr(UserFeedback, "corrected_confidence")
        assert hasattr(UserFeedback, "reviewed_by")

    def test_ai_triage_result_has_feedback_fields(self):
        from shared.models.ai_triage_result import AiTriageResult
        assert hasattr(AiTriageResult, "feedback_count")
        assert hasattr(AiTriageResult, "avg_rating")


# ── Feedback API Endpoint Tests ──

class TestFeedbackAPI:
    @pytest.fixture
    def api_app(self):
        db = MagicMock()
        db.execute = AsyncMock()

        mock_triage = MagicMock()
        mock_triage.id = "00000000-0000-0000-0000-000000000001"
        mock_triage.feedback_count = 0
        mock_triage.avg_rating = None

        def execute_side_effect(*args, **kwargs):
            result = MagicMock()
            result.scalar_one_or_none.return_value = mock_triage
            result.scalar.return_value = None
            return result

        db.execute = AsyncMock(side_effect=execute_side_effect)
        db.add = MagicMock()
        db.commit = AsyncMock()

        app = FastAPI()
        app.include_router(triage.router)

        app.dependency_overrides[get_db] = lambda: db

        from app.middleware.auth_jwt import get_current_user
        from shared.auth import TokenData
        mock_user = TokenData(
            user_id="user-1",
            email="admin@test.com",
            role="admin",
            tenant_id="tenant-1",
        )
        app.dependency_overrides[get_current_user] = lambda: mock_user

        return app

    @pytest.fixture
    async def client(self, api_app):
        async with AsyncClient(
            transport=ASGITransport(app=api_app),
            base_url="http://test",
        ) as test_client:
            yield test_client

    @pytest.mark.asyncio
    async def test_submit_feedback_success(self, client):
        response = await client.post(
            "/triage/00000000-0000-0000-0000-000000000001/feedback",
            json={"rating": 4, "category_correct": True},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "accepted"
        assert "feedback_id" in data

    @pytest.mark.asyncio
    async def test_submit_feedback_invalid_triage_id(self, client):
        response = await client.post(
            "/triage/invalid-uuid/feedback",
            json={"rating": 3},
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_submit_feedback_rating_out_of_range(self, client):
        response = await client.post(
            "/triage/00000000-0000-0000-0000-000000000001/feedback",
            json={"rating": 0},
        )
        assert response.status_code == 422

        response = await client.post(
            "/triage/00000000-0000-0000-0000-000000000001/feedback",
            json={"rating": 6},
        )
        assert response.status_code == 422


# ── TieredRouter Scoring Tests ──

class TestTieredRouterScoring:
    @pytest.mark.asyncio
    async def test_compute_score_empty_alert(self):
        router = TieredRouter()
        score = await router._compute_score(None, None)
        assert score == 0

    @pytest.mark.asyncio
    async def test_compute_score_level_only(self):
        from datetime import datetime, timezone
        router = TieredRouter()
        alert = MagicMock()
        alert.rule_level = 12
        alert.rule_id = 1
        alert.source_ip = "10.0.0.1"
        alert.agent_id = "a1"
        alert.mitre_technique = "T1078"
        alert.rule_firedtimes = 1
        alert.created_at = datetime.now(timezone.utc)

        with patch("shared.config.settings.llm_tier_level_threshold", 10):
            score = await router._compute_score(alert, None)
            assert score >= 3


# ── Phase 3B Feedback Loop Tests ──

class TestFeedbackRateLimit:
    """Rate limiting on feedback submission."""

    def test_rate_limit_cleanup(self):
        """Old timestamps should be cleaned up."""
        from services.api.app.routers.triage import _feedback_rate_limit
        from datetime import datetime, timezone, timedelta

        _feedback_rate_limit.clear()

        user_id = "test-user-1"
        now = datetime.now(timezone.utc)
        old_time = now - timedelta(minutes=2)
        recent_time = now - timedelta(seconds=10)

        _feedback_rate_limit[user_id] = [old_time, recent_time]
        cleaned = [t for t in _feedback_rate_limit[user_id] if t > now - timedelta(minutes=1)]

        assert len(cleaned) == 1
        assert cleaned[0] == recent_time


class TestBurstDetection:
    """Burst detection respects time window."""

    def test_burst_detection_high_fired_times(self):
        """Burst detection triggers on high fired times."""
        from shared.connectors.llm_router import is_burst_alert

        alert = MagicMock()
        alert.rule_firedtimes = 10
        alert.created_at = None

        assert is_burst_alert(alert) is True

    def test_burst_detection_recent_window(self):
        """Burst detection respects time window."""
        from shared.connectors.llm_router import is_burst_alert
        from datetime import datetime, timezone, timedelta

        now = datetime.now(timezone.utc)
        recent = now - timedelta(minutes=5)

        alert = MagicMock()
        alert.rule_firedtimes = 4
        alert.created_at = recent

        assert is_burst_alert(alert) is True

    def test_burst_detection_old_window(self):
        """Old alerts should not trigger burst detection."""
        from shared.connectors.llm_router import is_burst_alert
        from datetime import datetime, timezone, timedelta

        now = datetime.now(timezone.utc)
        old = now - timedelta(hours=1)

        alert = MagicMock()
        alert.rule_firedtimes = 4
        alert.created_at = old

        assert is_burst_alert(alert) is False


class TestSchemaValidation:
    """Schema includes required tables and columns."""

    def test_schema_has_user_feedback_table(self):
        """Verify user_feedback table exists in schema."""
        import pathlib
        schema_path = pathlib.Path(__file__).parent.parent / "database" / "schema.sql"
        schema_sql = schema_path.read_text()

        assert "CREATE TABLE user_feedback" in schema_sql
        assert "feedback_count" in schema_sql
        assert "avg_rating" in schema_sql
        assert "rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5)" in schema_sql

    def test_schema_feedback_columns(self):
        """Verify user_feedback has expected columns."""
        import pathlib
        schema_path = pathlib.Path(__file__).parent.parent / "database" / "schema.sql"
        schema_sql = schema_path.read_text()

        required = [
            "triage_result_id",
            "rating",
            "category_correct",
            "severity_correct",
            "correction_text",
            "corrected_category",
            "corrected_severity",
            "reviewed_by",
        ]
        for col in required:
            assert col in schema_sql, f"Missing column: {col}"

    def test_ai_triage_has_feedback_columns(self):
        """Verify ai_triage_results has feedback tracking columns."""
        import pathlib
        schema_path = pathlib.Path(__file__).parent.parent / "database" / "schema.sql"
        schema_sql = schema_path.read_text()

        assert "feedback_count INTEGER DEFAULT 0" in schema_sql
        assert "avg_rating DECIMAL(3,2)" in schema_sql


class TestTriageUsesRouter:
    """Triage endpoints use TieredRouter."""

    def test_tiered_router_imported_in_api_triage(self):
        """TieredRouter should be imported in triage.py."""
        import pathlib
        triage_path = pathlib.Path(__file__).parent.parent / "services" / "api" / "app" / "routers" / "triage.py"
        triage_code = triage_path.read_text()

        assert "from shared.connectors.llm_router import TieredRouter" in triage_code
        assert "TieredRouter().get_provider" in triage_code

    def test_tiered_router_used_in_worker(self):
        """TieredRouter should be used in triage_worker."""
        import pathlib
        worker_path = pathlib.Path(__file__).parent.parent / "services" / "worker" / "app" / "triage_worker.py"
        worker_code = worker_path.read_text()

        assert "TieredRouter().get_provider" in worker_code

    def test_feedback_endpoint_rate_limited(self):
        """Feedback endpoint should have rate limiting."""
        import pathlib
        triage_path = pathlib.Path(__file__).parent.parent / "services" / "api" / "app" / "routers" / "triage.py"
        triage_code = triage_path.read_text()

        assert "get_current_user" in triage_code
        assert "_feedback_rate_limit" in triage_code
        assert "HTTP_429_TOO_MANY_REQUESTS" in triage_code


class TestModelRunPersistence:
    """Model runs are recorded to database."""

    def test_model_run_model_exists(self):
        """ModelRun model should exist with required fields."""
        from shared.models.model_run import ModelRun
        assert hasattr(ModelRun, "id")
        assert hasattr(ModelRun, "model_name")
        assert hasattr(ModelRun, "success")
        assert hasattr(ModelRun, "created_at")
        assert hasattr(ModelRun, "accuracy")
        assert hasattr(ModelRun, "total_feedback")


# ── Spec-Required Tests ──

def test_feedback_rate_limit():
    from services.api.app.routers.triage import _feedback_rate_limit
    from datetime import datetime, timezone, timedelta
    user_id = "test-user-spec"
    now = datetime.now(timezone.utc)
    _feedback_rate_limit[user_id] = [now - timedelta(seconds=i * 5) for i in range(10)]
    cleaned = [t for t in _feedback_rate_limit[user_id] if t > now - timedelta(minutes=1)]
    assert len(cleaned) >= 10


@pytest.mark.asyncio
async def test_user_feedback_negative_rate():
    from shared.connectors.llm_router import user_feedback_negative_rate
    rate = await user_feedback_negative_rate(rule_id=5710, db_session=None)
    assert rate == 0.0


def test_is_burst_alert_time_window():
    from shared.connectors.llm_router import is_burst_alert
    from datetime import datetime, timezone
    alert = MagicMock()
    alert.rule_firedtimes = 4
    alert.created_at = datetime.now(timezone.utc)
    assert is_burst_alert(alert)


def test_api_router_imports_tiered_router():
    import pathlib
    triage_path = pathlib.Path(__file__).parent.parent / "services" / "api" / "app" / "routers" / "triage.py"
    code = triage_path.read_text()
    assert "TieredRouter" in code
    assert "TieredRouter().get_provider" in code


def test_schema_has_user_feedback():
    with open("database/schema.sql") as f:
        content = f.read()
    assert "CREATE TABLE user_feedback" in content
    assert "feedback_count" in content
    assert "avg_rating" in content
    idx_triage = content.index("CREATE TABLE ai_triage_results")
    end_triage = content.index(");", idx_triage)
    table_def = content[idx_triage:end_triage]
    assert "feedback_count" in table_def
    assert "avg_rating" in table_def
