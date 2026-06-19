"""Embedding-similarity cache for triage verdicts.

Avoids redundant LLM calls by checking if a semantically similar alert was
already triaged. Uses hash-based random projection for lightweight embeddings
(no heavy ML dependencies). Falls back to sentence-transformers if available.

Architecture:
  - Each entry stored as Redis key: sem_cache:{tenant_id}:{text_hash}
  - Value: JSON {embedding, result, stored_at}
  - Lookup: scan tenant keys, compute cosine similarity, return best match > threshold
  - Fail-open: if Redis unavailable, returns (False, {})

Alert features for embedding: rule_description + source_ip + mitre_technique + rule_groups.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import time
from typing import Callable, Optional

from shared.config import settings

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────
_EMBEDDING_DIM = 128
_SEED_PREFIX = "semcache:v1:"


# ── Embedding helpers ────────────────────────────────────────────────────────


def _tokenize(text: str) -> list[str]:
    """Simple whitespace + punctuation tokenizer (no external deps)."""
    import re

    return re.findall(r"[a-zA-Z0-9_.\-/:]+", text.lower())


def _compute_embedding(text: str, dim: int = _EMBEDDING_DIM) -> list[float]:
    """Compute a deterministic embedding via hash-based random projection.

    For each token in the text, a random ±1 vector of length `dim` is generated
    deterministically from the token and a per-dimension seed. All token vectors
    are summed, then L2-normalized.

    This approximates random indexing — similar texts (sharing many tokens)
    will have similar embeddings (high cosine similarity). No ML dependencies.

    Args:
        text: The concatenated feature text to embed.
        dim: Embedding dimension (default 128).

    Returns:
        list[float] of length `dim`, L2-normalized.
    """
    tokens = _tokenize(text)
    if not tokens:
        # Return zero vector for empty input
        return [0.0] * dim

    # Random projection: for each token, generate a ±1 vector deterministically
    vec = [0.0] * dim

    for token in set(tokens):  # de-duplicate tokens for efficiency
        token_bytes = token.encode("utf-8", errors="replace")
        for d in range(dim):
            seed = f"{_SEED_PREFIX}{d}:{token}".encode("utf-8")
            h = hashlib.sha256(seed + token_bytes).digest()
            # Use first byte to determine ±1
            bit = h[0] & 1
            vec[d] += 1.0 if bit else -1.0

    # L2 normalization
    norm = math.sqrt(sum(v * v for v in vec))
    if norm > 0:
        vec = [v / norm for v in vec]

    return vec


def _similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two embedding vectors.

    Returns 0.0 if either vector has zero norm.
    """
    if len(a) != len(b):
        raise ValueError(
            f"Embedding dimension mismatch: {len(a)} vs {len(b)}"
        )

    dot = sum(ai * bi for ai, bi in zip(a, b))
    norm_a = math.sqrt(sum(ai * ai for ai in a))
    norm_b = math.sqrt(sum(bi * bi for bi in b))

    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0

    return dot / (norm_a * norm_b)


def _features_text(alert_features: dict) -> str:
    """Concatenate alert features into a single text for embedding.

    Fields used: rule_description, source_ip, mitre_technique, rule_groups.
    """
    parts = []
    for key in ("rule_description", "source_ip", "mitre_technique", "rule_groups"):
        val = alert_features.get(key, "")
        if val:
            parts.append(str(val))
    return " ".join(parts)


def _hash_text(text: str) -> str:
    """Return a short hex digest of the feature text for Redis key purposes."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


# ── Optional sentence-transformers integration ───────────────────────────────

_sentence_transformers_available = False
try:
    from sentence_transformers import SentenceTransformer  # type: ignore

    _sentence_transformers_available = True
except ImportError:
    pass


# ── SemanticCache ────────────────────────────────────────────────────────────


class SemanticCache:
    """Embedding-similarity verdict cache backed by Redis.

    Usage:
        cache = SemanticCache(redis_client, tenant_id="default")
        hit, result = await cache.lookup(alert_features)
        if not hit:
            # ... run LLM triage ...
            await cache.store(alert_features, verdict_result)
    """

    def __init__(
        self,
        redis_client=None,
        tenant_id: str = "default",
        embedding_fn: Optional[Callable[[str], list[float]]] = None,
        embedding_dim: int = _EMBEDDING_DIM,
    ):
        """Initialize the semantic cache.

        Args:
            redis_client: Redis client (or None for fail-open no-op mode).
            tenant_id: Tenant identifier for key scoping.
            embedding_fn: Custom embedding function (text → list[float]).
                          If None, uses hash-based random projection unless
                          sentence-transformers is installed.
            embedding_dim: Embedding vector dimension (default 128).
        """
        self._r = redis_client
        self._tenant_id = tenant_id
        self._dim = embedding_dim

        # Resolve embedding function
        if embedding_fn is not None:
            self._embed = embedding_fn
        elif _sentence_transformers_available:
            # Use a lightweight SentenceTransformer model
            model_name = str(
                getattr(settings, "semantic_cache_st_model", "all-MiniLM-L6-v2")
            )
            self._st_model = SentenceTransformer(model_name)

            def _st_embed(text: str) -> list[float]:
                return self._st_model.encode(text).tolist()  # type: ignore[union-attr]

            self._embed = _st_embed
        else:
            self._embed = _compute_embedding
            self._st_model = None

    def _key(self, text_hash: str) -> str:
        """Build the Redis key for a cached entry."""
        return f"sem_cache:{self._tenant_id}:{text_hash}"

    def _key_pattern(self) -> str:
        """Redis SCAN pattern for all entries of this tenant."""
        return f"sem_cache:{self._tenant_id}:*"

    # ── Public API ─────────────────────────────────────────────────────────

    async def lookup(
        self,
        alert_features: dict,
        threshold: float = 0.92,
        max_scan: int = 1000,
    ) -> tuple[bool, dict]:
        """Check if a semantically similar alert was already triaged.

        Args:
            alert_features: Dict with rule_description, source_ip,
                            mitre_technique, rule_groups.
            threshold: Cosine similarity threshold (0.0–1.0). Default 0.92.
            max_scan: Maximum number of cached entries to scan.

        Returns:
            (hit: bool, cached_result: dict). If no hit or Redis unavailable,
            returns (False, {}).
        """
        if self._r is None:
            return False, {}

        text = _features_text(alert_features)
        if not text.strip():
            return False, {}

        try:
            query_embedding = self._embed(text)
            if not query_embedding or all(v == 0.0 for v in query_embedding):
                return False, {}
        except Exception as exc:
            logger.debug("semantic_cache embedding error: %s", exc)
            return False, {}

        # Scan tenant keys for existing entries
        try:
            best_similarity = -1.0
            best_result: dict = {}

            cursor = 0
            scanned = 0
            while True:
                cursor, keys = await self._r.scan(
                    cursor, match=self._key_pattern(), count=100
                )
                scanned += len(keys)

                for key in keys:
                    try:
                        raw = await self._r.get(key)
                        if not raw:
                            continue
                        entry = json.loads(raw)
                        stored_embedding = entry.get("embedding")
                        if not stored_embedding or len(stored_embedding) != self._dim:
                            continue

                        sim = _similarity(query_embedding, stored_embedding)
                        if sim > best_similarity and sim >= threshold:
                            best_similarity = sim
                            best_result = entry.get("result", {})
                    except (json.JSONDecodeError, ValueError, TypeError) as exc:
                        logger.debug("semantic_cache parse error for key %s: %s", key, exc)
                        continue

                if cursor == 0 or scanned >= max_scan:
                    break

            if best_similarity >= threshold:
                logger.debug(
                    "semantic_cache hit: sim=%.4f threshold=%.2f",
                    best_similarity,
                    threshold,
                )
                return True, best_result

            return False, {}

        except Exception as exc:
            logger.debug("semantic_cache lookup error: %s", exc)
            return False, {}

    async def store(
        self,
        alert_features: dict,
        result: dict,
        ttl: int = 86400,
    ) -> bool:
        """Store a triage verdict with its embedding in the cache.

        Args:
            alert_features: Dict with alert feature fields.
            result: The triage result dict to cache.
            ttl: Time-to-live in seconds (default 86400 = 24 hours).

        Returns:
            True if stored successfully, False if Redis unavailable or error.
        """
        if self._r is None:
            return False

        text = _features_text(alert_features)
        if not text.strip():
            return False

        text_hash = _hash_text(text)
        key = self._key(text_hash)

        try:
            embedding = self._embed(text)
        except Exception as exc:
            logger.debug("semantic_cache embedding error on store: %s", exc)
            return False

        payload = {
            "embedding": embedding,
            "result": result,
            "stored_at": time.time(),
            "text_hash": text_hash,
        }

        try:
            await self._r.set(key, json.dumps(payload), ex=ttl)
            logger.debug("semantic_cache stored key=%s ttl=%d", key, ttl)
            return True
        except Exception as exc:
            logger.debug("semantic_cache store error: %s", exc)
            return False

    async def clear_tenant(self) -> int:
        """Remove all cached entries for this tenant.

        Returns:
            Number of keys deleted.
        """
        if self._r is None:
            return 0

        try:
            deleted = 0
            cursor = 0
            while True:
                cursor, keys = await self._r.scan(
                    cursor, match=self._key_pattern(), count=100
                )
                if keys:
                    await self._r.delete(*keys)
                    deleted += len(keys)
                if cursor == 0:
                    break
            return deleted
        except Exception as exc:
            logger.debug("semantic_cache clear error: %s", exc)
            return 0
