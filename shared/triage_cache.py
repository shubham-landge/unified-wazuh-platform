"""Semantic result cache for AI triage.

Near-duplicate alerts reuse recent verdicts without paying the LLM inference
penalty.  The cache is keyed by normalized entities + rule_id and stored in
Redis with the verdict embedding and TTL.
"""

import json
import logging
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

import redis.asyncio as redis

from shared.config import settings
from shared.models.alert import Alert
from shared.rag.embeddings import cosine_similarity, embed_text

logger = logging.getLogger(__name__)

_TRIAGE_CACHE_INDEX = "triage_cache_index"


def _normalize_entities(alert: Alert) -> dict[str, str]:
    """Return normalized fields that make a triage result reusable."""
    return {
        "rule_id": str(alert.rule_id or "").strip().lower(),
        "source_ip": str(alert.source_ip or "").strip().lower(),
        "agent_id": str(alert.agent_id or ""),
        "user_name": str(alert.user_name or "").strip().lower(),
        "process_name": str(alert.process_name or "").strip().lower(),
    }


def cache_key(alert: Alert) -> str:
    """Deterministic key for the cache bucket for this alert."""
    entities = _normalize_entities(alert)
    payload = json.dumps(entities, sort_keys=True)
    return f"triage_cache:{sha256(payload.encode()).hexdigest()[:32]}"


def _verdict_text(verdict: dict[str, Any]) -> str:
    """Flatten a triage verdict into an embeddable string."""
    parts = [
        verdict.get("summary", ""),
        verdict.get("category", ""),
        verdict.get("severity", ""),
        str(verdict.get("false_positive_likelihood", "")),
    ]
    return " | ".join(p for p in parts if p)


async def lookup(
    redis_client: redis.Redis | None,
    alert: Alert,
    threshold: float | None = None,
) -> dict[str, Any] | None:
    """Return a cached triage verdict if a sufficiently similar one exists."""
    if not redis_client or not settings.triage_cache_enabled:
        return None
    if alert.rule_level and alert.rule_level >= settings.triage_cache_skip_level:
        return None

    threshold = threshold or settings.triage_cache_similarity_threshold
    key = cache_key(alert)

    # Pull all verdicts currently in the bucket.
    raw_entries = await redis_client.lrange(key, 0, -1)
    if not raw_entries:
        return None

    alert_text = json.dumps(_normalize_entities(alert), sort_keys=True)
    alert_emb = await embed_text(alert_text)
    if not alert_emb:
        return None

    now = datetime.now(timezone.utc).timestamp()
    ttl = settings.triage_cache_ttl_seconds

    best: dict[str, Any] | None = None
    best_score = 0.0

    for raw in raw_entries:
        try:
            entry = json.loads(raw)
            if entry.get("expires_at", 0) < now:
                continue
            cached_emb = entry.get("embedding")
            if not cached_emb:
                continue
            score = cosine_similarity(alert_emb, cached_emb)
            if score > best_score:
                best_score = score
                best = entry.get("verdict")
        except Exception:
            continue

    if best and best_score >= threshold:
        logger.info(
            "Triage cache hit for alert %s (score=%.3f, key=%s)",
            alert.id,
            best_score,
            key,
        )
        best["_cached"] = True
        best["_cache_score"] = round(best_score, 3)
        return best

    return None


async def store(
    redis_client: redis.Redis | None,
    alert: Alert,
    verdict: dict[str, Any],
) -> bool:
    """Store a triage verdict in the semantic cache."""
    if not redis_client or not settings.triage_cache_enabled:
        return False
    if alert.rule_level and alert.rule_level >= settings.triage_cache_skip_level:
        return False

    key = cache_key(alert)
    text = _verdict_text(verdict)
    embedding = await embed_text(text)
    if not embedding:
        return False

    entry = {
        "verdict": verdict,
        "embedding": embedding,
        "expires_at": (datetime.now(timezone.utc).timestamp() + settings.triage_cache_ttl_seconds),
        "alert_id": str(alert.id),
        "rule_id": alert.rule_id,
    }

    try:
        await redis_client.lpush(key, json.dumps(entry))
        await redis_client.expire(key, settings.triage_cache_ttl_seconds)
        # Keep bucket bounded (recent 20 verdicts).
        await redis_client.ltrim(key, 0, 19)
        return True
    except Exception as exc:
        logger.warning("Failed to store triage cache entry: %s", exc)
        return False
