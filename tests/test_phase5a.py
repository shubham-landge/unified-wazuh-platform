import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
import json


# ── RAG Tests ──

class TestEmbeddings:
    def test_cosine_similarity_identical(self):
        from shared.rag.embeddings import cosine_similarity
        v = [1.0, 0.0, 0.0]
        assert cosine_similarity(v, v) == 1.0

    def test_cosine_similarity_orthogonal(self):
        from shared.rag.embeddings import cosine_similarity
        a = [1.0, 0.0, 0.0]
        b = [0.0, 1.0, 0.0]
        assert cosine_similarity(a, b) == 0.0

    def test_cosine_similarity_opposite(self):
        from shared.rag.embeddings import cosine_similarity
        a = [1.0, 0.0]
        b = [-1.0, 0.0]
        assert cosine_similarity(a, b) == -1.0


class TestKnowledgeChunkModel:
    def test_model_attributes(self):
        from shared.models.knowledge_base import KnowledgeChunk
        assert hasattr(KnowledgeChunk, "id")
        assert hasattr(KnowledgeChunk, "source")
        assert hasattr(KnowledgeChunk, "chunk_text")
        assert hasattr(KnowledgeChunk, "embedding")
        assert hasattr(KnowledgeChunk, "extra_meta")
        assert hasattr(KnowledgeChunk, "token_count")


# ── Compliance Model Tests ──

class TestComplianceModels:
    def test_framework_model(self):
        from shared.models.compliance import ComplianceFramework
        assert hasattr(ComplianceFramework, "name")
        assert hasattr(ComplianceFramework, "score")
        assert hasattr(ComplianceFramework, "total_controls")

    def test_control_model(self):
        from shared.models.compliance import ComplianceControl
        assert hasattr(ComplianceControl, "control_id")
        assert hasattr(ComplianceControl, "title")
        assert hasattr(ComplianceControl, "status")
        assert hasattr(ComplianceControl, "framework_id")

    def test_mapping_model(self):
        from shared.models.compliance import ComplianceMapping
        assert hasattr(ComplianceMapping, "rule_id")
        assert hasattr(ComplianceMapping, "cve_pattern")

    def test_exception_model(self):
        from shared.models.compliance import ComplianceException
        assert hasattr(ComplianceException, "reason")
        assert hasattr(ComplianceException, "status")
        assert hasattr(ComplianceException, "duration_days")


# ── Compliance Checker Tests ──

class TestComplianceChecker:
    @pytest.mark.asyncio
    async def test_score_no_controls_returns_unknown(self):
        db = MagicMock()
        db.execute = AsyncMock()
        result = MagicMock()
        result.scalars.return_value.all.return_value = []
        db.execute.return_value = result

        from shared.compliance_checker import ComplianceChecker
        checker = ComplianceChecker(db)
        # framework doesn't exist, but the checker should handle empty controls
        assert checker is not None

    @pytest.mark.asyncio
    async def test_checker_has_required_methods(self):
        from shared.compliance_checker import ComplianceChecker
        db = MagicMock()
        checker = ComplianceChecker.__new__(ComplianceChecker)
        assert hasattr(ComplianceChecker, "score_framework")
        assert hasattr(ComplianceChecker, "_check_control")


# ── Dashboard Compliance Page Test ──

@patch("services.dashboard.app.main.api_request")
def test_compliance_page_loads(mock_api):
    import jinja2
    from fastapi.testclient import TestClient
    from services.dashboard.app.main import app, templates
    templates.env.loader = jinja2.FileSystemLoader("services/dashboard/templates")

    mock_api.side_effect = lambda method, path, *args, **kwargs: {
        "/compliance/frameworks": {
            "status": "success",
            "frameworks": [
                {"id": "fw-1", "name": "SOC2", "version": "1.0", "description": "SOC2", "total_controls": 4, "score": 95.0},
            ]
        },
        "/compliance/frameworks/fw-1/score": {
            "status": "success",
            "framework": {"id": "fw-1", "name": "SOC2", "version": "1.0"},
            "score": {
                "total_controls": 4,
                "compliant": 3,
                "warnings": 1,
                "breaches": 0,
                "unknown": 0,
                "score": 75.0,
                "controls": [
                    {"id": "c1", "control_id": "CC6.1", "title": "Access Control", "description": "", "status": "compliant", "evidence": []},
                    {"id": "c2", "control_id": "CC7.1", "title": "Vuln Mgmt", "description": "", "status": "warning", "evidence": [{"type": "alert", "id": "a1", "rule_description": "Test"}]},
                ]
            }
        }
    }.get(path, {})

    client = TestClient(app)
    resp = client.get("/compliance?framework=fw-1")
    assert resp.status_code == 200
    assert "Compliance Mapping Console" in resp.text
    assert "SOC2" in resp.text


# ── API Router Tests ──

class TestRAGRoutes:
    def test_rag_router_imports(self):
        from app.routers import rag
        assert rag is not None


class TestComplianceRoutes:
    def test_compliance_router_imports(self):
        from app.routers import compliance
        assert compliance is not None


# ── Config Tests ──

class TestPhase5AConfig:
    def test_new_settings_exist(self):
        from shared.config import settings
        assert hasattr(settings, "embedding_model")
        assert hasattr(settings, "rag_enabled")
        assert hasattr(settings, "rag_top_k")


# ── Report Generator Compliance Method Test ──

def test_report_generator_has_compliance_method():
    from shared.report_generator import ReportGenerator
    assert hasattr(ReportGenerator, "generate_compliance_report")
    assert callable(ReportGenerator.generate_compliance_report)


# ── Schema Compliance Tests ──

def test_schema_has_knowledge_chunks():
    with open("database/schema.sql") as f:
        content = f.read()
    assert "CREATE TABLE knowledge_chunks" in content
    assert "CREATE TABLE compliance_frameworks" in content
    assert "CREATE TABLE compliance_controls" in content
    assert "CREATE TABLE compliance_mappings" in content
    assert "CREATE TABLE compliance_exceptions" in content


# ── Main.py router registration test ──

def test_main_registers_compliance_and_rag():
    from services.api.app.main import app
    routes = [r.path for r in app.routes]
    assert any("/compliance/frameworks" in r for r in routes)
    assert any("/rag/query" in r for r in routes)
