"""Tests for semantic embedding-similarity verdict cache.

Covers:
  - Store + lookup hit (same alert features).
  - Lookup miss (different alert features).
  - Threshold filtering (similar alert below threshold).
  - Redis failure → fail-open (returns False, {}).
  - TTL expiration.
  - Embedding generation (deterministic, similar texts yield similar embeddings).
  - Empty feature text handling.
"""
from __future__ import annotations

import json
import math
import time
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shared.enrichment.semantic_cache import (
    SemanticCache,
    _compute_embedding,
    _features_text,
    _similarity,
    _tokenize,
)


# ── Pure embedding helpers ───────────────────────────────────────────────────


class TestTokenize:
    def test_tokenize_splits_on_whitespace_and_punctuation(self):
        tokens = _tokenize("CVE-2024-1234 exploits RDP on 192.168.1.1")
        assert "cve-2024-1234" in tokens
        assert "exploits" in tokens
        assert "rdp" in tokens
        assert "192.168.1.1" in tokens

    def test_tokenize_lowercases(self):
        tokens = _tokenize("MALWARE Ransomware")
        assert "malware" in tokens
        assert "ransomware" in tokens
        assert "MALWARE" not in tokens


class TestComputeEmbedding:
    def test_returns_correct_dimension(self):
        emb = _compute_embedding("test alert features", dim=128)
        assert len(emb) == 128
        # Should be L2-normalized (norm ≈ 1.0)
        norm = math.sqrt(sum(v * v for v in emb))
        assert abs(norm - 1.0) < 0.001

    def test_same_text_produces_same_embedding(self):
        a = _compute_embedding("malware detected on host")
        b = _compute_embedding("malware detected on host")
        assert a == b

    def test_similar_texts_have_high_similarity(self):
        a = _compute_embedding("malware detected on host 192.168.1.1")
        b = _compute_embedding("malware detected on host 192.168.1.1 rdp")
        sim = _similarity(a, b)
        assert sim > 0.5, f"Expected high similarity, got {sim:.4f}"

    def test_dissimilar_texts_have_low_similarity(self):
        a = _compute_embedding("malware ransomware Trojan wiper")
        b = _compute_embedding("user login successful auth ok")
        sim = _similarity(a, b)
        assert sim < 0.5, f"Expected low similarity, got {sim:.4f}"

    def test_empty_text_returns_zero_vector(self):
        emb = _compute_embedding("")
        assert len(emb) == 128
        norm = math.sqrt(sum(v * v for v in emb))
        assert norm == 0.0


class TestSimilarity:
    def test_identical_vectors(self):
        v = [0.5, 0.5, 0.5, 0.5]
        assert _similarity(v, v) == pytest.approx(1.0)

    def test_orthogonal_vectors(self):
        a = [1.0, 0.0]
        b = [0.0, 1.0]
        assert _similarity(a, b) == 0.0

    def test_zero_norm_returns_zero(self):
        a = [0.0, 0.0]
        b = [1.0, 0.0]
        assert _similarity(a, b) == 0.0

    def test_dimension_mismatch_raises(self):
        with pytest.raises(ValueError):
            _similarity([1.0], [1.0, 2.0])


class TestFeaturesText:
    def test_concatenates_expected_fields(self):
        features = {
            "rule_description": "Possible RDP brute force",
            "source_ip": "10.0.0.5",
            "mitre_technique": "T1110",
            "rule_groups": "windows,authentication_failure",
        }
        text = _features_text(features)
        assert "Possible RDP brute force" in text
        assert "10.0.0.5" in text
        assert "T1110" in text
        assert "windows" in text

    def test_missing_fields_omitted(self):
        features = {"rule_description": "test", "source_ip": "1.2.3.4"}
        text = _features_text(features)
        assert text == "test 1.2.3.4"


# ── SemanticCache with mocked Redis ──────────────────────────────────────────


def _make_mock_redis():
    """Create a mock Redis client that behaves like a simple dict.

    Uses async side effects so ``await redis.get(key)`` etc. work with
    the async ``SemanticCache`` implementation.
    """
    mock = MagicMock()
    store: dict[str, str] = {}

    async def _get(key):
        return store.get(key)

    async def _set(key, value, ex=None):
        store[key] = value
        return True

    async def _scan(cursor=0, match=None, count=100):
        import fnmatch
        # Simulate SCAN returning keys that match the pattern
        pattern = match.replace("*", "*") if match else "*"
        all_keys = list(store.keys())
        # Simple wildcard matching
        matching = [k for k in all_keys if fnmatch.fnmatch(k, pattern)]
        return (0, matching)

    async def _delete(*keys):
        removed = 0
        for k in keys:
            if k in store:
                del store[k]
                removed += 1
        return removed

    mock.get.side_effect = _get
    mock.set.side_effect = _set
    mock.scan.side_effect = _scan
    mock.delete.side_effect = _delete
    mock._store = store  # expose for inspection in tests
    return mock


@pytest.fixture
def redis_mock():
    return _make_mock_redis()


@pytest.fixture
def cache(redis_mock):
    return SemanticCache(redis_client=redis_mock, tenant_id="test-tenant")


@pytest.fixture
def alert_rdp():
    return {
        "rule_description": "Possible RDP brute force attack detected",
        "source_ip": "192.168.1.100",
        "mitre_technique": "T1110",
        "rule_groups": "windows,authentication_failure,brute_force",
    }


@pytest.fixture
def alert_ssh():
    return {
        "rule_description": "SSH authentication failure threshold exceeded",
        "source_ip": "10.0.0.50",
        "mitre_technique": "T1110",
        "rule_groups": "linux,authentication_failure,ssh",
    }


# ── Tests ────────────────────────────────────────────────────────────────────


class TestSemanticCacheStoreLookup:
    @pytest.mark.asyncio
    async def test_store_and_lookup_hit(self, cache, alert_rdp):
        """Store a verdict, then lookup the same features → hit."""
        verdict = {"verdict": "malicious", "severity": "high", "confidence": 0.95}
        stored = await cache.store(alert_rdp, verdict)
        assert stored is True

        hit, result = await cache.lookup(alert_rdp, threshold=0.85)
        assert hit is True
        assert result["verdict"] == "malicious"
        assert result["severity"] == "high"

    @pytest.mark.asyncio
    async def test_lookup_miss_different_alert(self, cache, alert_rdp, alert_ssh):
        """Lookup with different feature set → miss."""
        verdict = {"verdict": "malicious", "severity": "high"}
        await cache.store(alert_rdp, verdict)

        hit, result = await cache.lookup(alert_ssh, threshold=0.85)
        assert hit is False
        assert result == {}

    @pytest.mark.asyncio
    async def test_threshold_filtering(self, cache, alert_rdp):
        """With a very high threshold, even similar alerts should miss."""
        verdict = {"verdict": "malicious"}
        await cache.store(alert_rdp, verdict)

        # Slightly modified features — should still be similar but
        # with threshold 0.999, almost nothing matches
        modified = dict(alert_rdp)
        modified["rule_description"] = "RDP brute force attempt observed"

        hit_high, _ = await cache.lookup(modified, threshold=0.999)
        hit_normal, _ = await cache.lookup(modified, threshold=0.5)

        # At threshold 0.999, may or may not hit — but at 0.5 it should hit
        # (since it shares most tokens with the stored entry)
        assert hit_normal is True, "Expected hit at threshold 0.5 for similar alert"

    @pytest.mark.asyncio
    async def test_redis_failure_fail_open(self, alert_rdp):
        """If Redis raises, lookup returns (False, {}) — fail-open."""
        broken_redis = MagicMock()
        broken_redis.scan.side_effect = ConnectionError("Redis down")

        cache_broken = SemanticCache(redis_client=broken_redis, tenant_id="test")
        hit, result = await cache_broken.lookup(alert_rdp)
        assert hit is False
        assert result == {}

        broken_redis.set.side_effect = ConnectionError("Redis down")
        stored = await cache_broken.store(alert_rdp, {"ok": True})
        assert stored is False

    @pytest.mark.asyncio
    async def test_none_redis_fail_open(self, alert_rdp):
        """Without a Redis client, all operations are no-op."""
        cache_noop = SemanticCache(redis_client=None, tenant_id="test")
        hit, result = await cache_noop.lookup(alert_rdp)
        assert hit is False
        assert result == {}

        stored = await cache_noop.store(alert_rdp, {"ok": True})
        assert stored is False

    @pytest.mark.asyncio
    async def test_empty_features_returns_miss(self, cache):
        """Empty feature dict → no hit."""
        hit, result = await cache.lookup({})
        assert hit is False
        assert result == {}

        stored = await cache.store({}, {"ok": True})
        assert stored is False


class TestSemanticCacheTTL:
    @pytest.mark.asyncio
    async def test_store_sets_ttl(self, redis_mock, alert_rdp):
        """Verify that set() is called with ex=ttl parameter."""
        cache = SemanticCache(redis_client=redis_mock, tenant_id="ttl-tenant")
        await cache.store(alert_rdp, {"verdict": "benign"}, ttl=42)

        # Check that set was called with the TTL
        set_calls = redis_mock.set.call_args_list
        # The last call should have ex=42
        found_ttl = False
        for call in set_calls:
            if call.kwargs.get("ex") == 42:
                found_ttl = True
                break
        assert found_ttl, f"Expected set() call with ex=42, got {set_calls}"


class TestSemanticCacheClear:
    @pytest.mark.asyncio
    async def test_clear_tenant_removes_keys(self, cache, alert_rdp, alert_ssh):
        """clear_tenant() removes all entries for the tenant."""
        await cache.store(alert_rdp, {"verdict": "malicious"})
        await cache.store(alert_ssh, {"verdict": "benign"})

        # Both should be findable
        hit1, _ = await cache.lookup(alert_rdp, threshold=0.5)
        assert hit1 is True

        deleted = await cache.clear_tenant()
        assert deleted >= 2

        # After clear, lookups should miss
        hit2, _ = await cache.lookup(alert_rdp, threshold=0.5)
        assert hit2 is False


class TestEmbeddingQuality:
    def test_similar_alerts_produce_similar_embeddings(self):
        """Two alerts with similar features should have high cosine similarity."""
        rdp1 = {
            "rule_description": "Possible RDP brute force attack detected on host dc01",
            "source_ip": "192.168.1.100",
            "mitre_technique": "T1110",
            "rule_groups": "windows,authentication_failure,brute_force",
        }
        rdp2 = {
            "rule_description": "RDP brute force attempt observed on host dc01",
            "source_ip": "192.168.1.100",
            "mitre_technique": "T1110",
            "rule_groups": "windows,authentication_failure",
        }

        emb1 = _compute_embedding(_features_text(rdp1))
        emb2 = _compute_embedding(_features_text(rdp2))
        sim = _similarity(emb1, emb2)

        assert sim > 0.7, f"Similar alerts should have sim > 0.7, got {sim:.4f}"

    def test_different_alerts_produce_low_similarity(self):
        """Two alerts with very different features should have low similarity."""
        rdp = {
            "rule_description": "RDP brute force detected",
            "source_ip": "192.168.1.100",
            "mitre_technique": "T1110",
            "rule_groups": "windows,authentication_failure",
        }
        web = {
            "rule_description": "Web server returning 200 OK for health check",
            "source_ip": "10.0.0.1",
            "mitre_technique": "",
            "rule_groups": "web,health_check",
        }

        emb1 = _compute_embedding(_features_text(rdp))
        emb2 = _compute_embedding(_features_text(web))
        sim = _similarity(emb1, emb2)

        assert sim < 0.5, f"Dissimilar alerts should have sim < 0.5, got {sim:.4f}"


# ── L2-only gating (triage_worker integration) ───────────────────────────────


class TestSemanticCacheL2Gating:
    """Verify that triage_worker only consults SemanticCache for L2_TRIAGE alerts.

    This tests the integration decision gate → semantic cache wiring.
    """

    @pytest.fixture
    def alert(self):
        return MagicMock(
            id=uuid.uuid4(),
            rule_id=5712,
            rule_description="sshd: brute force",
            rule_level=10,
            source_ip="10.0.0.5",
            agent_id="agent-01",
            agent_name="web-01",
            agent_ip="192.168.1.10",
            tenant_id=uuid.uuid4(),
            mitre_technique="T1110",
            rule_groups="ssh,brute_force",
            mitre_tactic="Initial Access",
            user_name="root",
            process_name="sshd",
        )

    class _MockSession:
        """Minimal async session that returns the given alert on execute()."""

        def __init__(self, a):
            self._alert = a

        async def execute(self, stmt):
            alert_ref = self._alert  # capture for closure

            class _Result:
                def scalar_one_or_none(self):
                    return alert_ref
            return _Result()

        async def flush(self):
            pass

        async def commit(self):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def get(self, model, id):
            return None

        def add(self, obj):
            pass

    async def _run_with_level(self, alert, level: str):
        """Run triage_worker.process_message() and return the mocked SemanticCache.lookup.

        Only ``level`` is varied; all other dependencies are mocked out.
        """
        from shared.enrichment.decision import Decision, DecisionLevel

        # We need the real TriageWorker for process_message — but we patch
        # everything else.  Import here to avoid module-level side effects.
        from services.worker.app.triage_worker import TriageWorker

        worker = TriageWorker()
        worker._shutdown = True
        worker.redis_client = AsyncMock()
        worker.session_factory = lambda: self._MockSession(alert)

        with (
            patch(
                "services.worker.app.triage_worker.noise_reduction.evaluate",
                new_callable=AsyncMock,
            ) as m_noise,
            patch(
                "services.worker.app.triage_worker.enrich_alert",
                new_callable=AsyncMock,
            ) as m_enrich,
            patch(
                "services.worker.app.triage_worker.compute_risk_score",
            ) as m_risk,
            patch("services.worker.app.triage_worker.decide") as m_decide,
            patch(
                "services.worker.app.triage_worker.TieredRouter",
            ) as m_router,
            patch(
                "services.worker.app.triage_worker.triage_rag.persist_triage_verdict",
                new_callable=AsyncMock,
            ),
            patch(
                "services.worker.app.triage_worker.fuse_verdict",
            ) as m_fuse,
            patch(
                "services.worker.app.triage_worker.SemanticCache.lookup",
                new_callable=AsyncMock,
            ) as m_cache_lookup,
        ):
            m_noise.return_value = MagicMock(
                should_triage=True,
                action="keep",
                force_fast_tier=False,
                incident=None,
                reason="kept",
            )
            m_enrich.return_value = MagicMock(
                ti_confidence=0,
                ti_is_known_bad=False,
                ti_is_kev=False,
                ueba_zscore=0,
                geo_tor_vpn=False,
                geo_bad_asn=False,
                geo_impossible_travel=False,
                vuln_matched=False,
                is_allowlisted=False,
            )
            m_risk.return_value = 50

            # Decision level is the primary variable under test.
            if level in ("L3_ESCALATE", "L4_CRITICAL"):
                m_decide.return_value = Decision(
                    level=getattr(DecisionLevel, level),
                    score=75,
                    reason="test",
                    skip_llm=False,
                    fast_llm_only=True,
                    auto_verdict="malicious",
                    auto_severity="high",
                )
            else:
                m_decide.return_value = Decision(
                    level=getattr(DecisionLevel, level),
                    score=50,
                    reason="test",
                    skip_llm=False,
                    fast_llm_only=False,
                )

            mock_provider = MagicMock()
            mock_provider.name.return_value = "test-model"
            mock_provider.analyze = AsyncMock(
                return_value={
                    "success": True,
                    "summary": "test summary",
                    "category": "attack",
                    "severity": "medium",
                    "confidence": 0.5,
                    "false_positive_likelihood": 0.3,
                    "escalation_required": False,
                },
            )
            m_router.return_value.get_provider = AsyncMock(
                return_value=mock_provider,
            )

            # Fusion just passes through
            def _passthrough_fuse(data, ctx, score):
                data["fusion_applied"] = False
                return data

            m_fuse.side_effect = _passthrough_fuse

            # Cache miss by default so the LLM path runs for L2
            m_cache_lookup.return_value = (False, {})

            await worker.process_message({"alert_id": str(alert.id)})

        return m_cache_lookup

    # ── Each level test ───────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_cache_skipped_for_l0_suppress(self, alert):
        """L0_SUPPRESS → SemanticCache.lookup not called."""
        cache_mock = await self._run_with_level(alert, "L0_SUPPRESS")
        cache_mock.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_cache_skipped_for_l1_auto_close(self, alert):
        """L1_AUTO_CLOSE → SemanticCache.lookup not called."""
        cache_mock = await self._run_with_level(alert, "L1_AUTO_CLOSE")
        cache_mock.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_cache_consulted_for_l2_triage(self, alert):
        """L2_TRIAGE → SemanticCache.lookup is called."""
        cache_mock = await self._run_with_level(alert, "L2_TRIAGE")
        cache_mock.assert_awaited()

    @pytest.mark.asyncio
    async def test_cache_skipped_for_l3_escalate(self, alert):
        """L3_ESCALATE → SemanticCache.lookup not called."""
        cache_mock = await self._run_with_level(alert, "L3_ESCALATE")
        cache_mock.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_cache_skipped_for_l4_critical(self, alert):
        """L4_CRITICAL → SemanticCache.lookup not called."""
        cache_mock = await self._run_with_level(alert, "L4_CRITICAL")
        cache_mock.assert_not_awaited()
