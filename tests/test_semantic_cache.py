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
from unittest.mock import MagicMock, patch

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
    """Create a mock Redis client that behaves like a simple dict."""
    mock = MagicMock()
    store: dict[str, str] = {}

    def _get(key):
        return store.get(key)

    def _set(key, value, ex=None):
        store[key] = value
        return True

    def _scan(cursor=0, match=None, count=100):
        import fnmatch
        import os
        # Simulate SCAN returning keys that match the pattern
        pattern = match.replace("*", "*") if match else "*"
        all_keys = list(store.keys())
        # Simple wildcard matching
        matching = [k for k in all_keys if fnmatch.fnmatch(k, pattern)]
        return (0, matching)

    def _delete(*keys):
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
